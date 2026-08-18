"""Canonical version-aware interpretation owner for Agent Plugins."""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import Enum
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Any

import yaml

from ..hook_contract import HookContractError, HookSourceDocument, parse_hook_source
from ..utils.path_security import PathTraversalError, ensure_path_within, validate_path_segments
from .assets import AssetInventory, AssetInventoryError, normalized_path_key
from .constants import (
    AGENT_PLUGINS_SCHEMA_PREFIX,
    AGENT_PLUGINS_VERSION,
    COM_MICROSOFT_APM_NAMESPACE,
    COM_MICROSOFT_APM_SCHEMA_VERSION,
    PLUGIN_SCHEMA_ID,
)
from .errors import (
    AgentPluginError,
    AgentPluginLegacyBoundaryError,
    AgentPluginManifestAuthorityError,
    AgentPluginManifestError,
    NotAgentPluginError,
    UnsupportedAgentPluginVersionError,
)
from .io import MAX_JSON_BYTES, decode_json_document, read_json_document
from .ir import (
    AgentPlugin,
    AgentPluginAsset,
    AgentPluginComponents,
    AgentPluginDetection,
    AgentPluginDiagnostic,
    AgentPluginExecutable,
    AgentPluginIdentity,
    AgentPluginMcpServer,
    AgentPluginSkill,
    ApmConfiguration,
    ApmExtensionComponents,
    ApmExtensionData,
    ApmExtensionFileComponent,
    ApmExtensionHookComponent,
    ApmExtensionLspComponent,
    ApmExtensionLspServer,
    DiagnosticSeverity,
    FrozenJsonArray,
    FrozenJsonObject,
    FrozenJsonValue,
    McpServerType,
    SourceProvenance,
)
from .validation import (
    validate_lsp_extension_document,
    validate_mcp_config_file,
    validate_plugin_manifest_document,
)

_PORTABLE_IDENTITY_FIELDS = frozenset(
    {
        "name",
        "version",
        "description",
        "author",
        "homepage",
        "repository",
        "license",
        "keywords",
    }
)
_APM_CONFIGURATION_FIELDS = frozenset(
    {
        "allowExecutables",
        "build",
        "dependencies",
        "devDependencies",
        "includes",
        "manifestVersion",
        "policy",
        "registries",
        "schemaVersion",
        "scripts",
        "target",
        "targets",
        "type",
    }
)
_REJECTED_MANIFEST_SCHEMA_ID = "<rejected-root-plugin-json>"
_APM_DIRECTORY_COMPONENTS = ("agents", "commands", "instructions", "extensions")
_APM_ALLOWED_ROOT_ENTRIES = frozenset({*_APM_DIRECTORY_COMPONENTS, "hooks", "lsp.json"})
_IGNORED_PORTABLE_COMPONENT_PATHS = (
    "agents",
    "commands",
    "hooks",
    "instructions",
    "extensions",
    "lsp.json",
)
_PATH_REFERENCE_RE = re.compile(
    r"(?<![A-Za-z0-9_$.])"
    r"(?P<reference>"
    r"\$\{PLUGIN_ROOT\}[/\\][^\s\"']+|"
    r"(?:\.\.[/\\])+[^\s\"']+|"
    r"\.[/\\][^\s\"']+"
    r")"
)


@dataclass(frozen=True, slots=True)
class _AdmissibleRootManifest:
    path: Path
    document: Mapping[str, Any]


class _CandidateDisposition(Enum):
    ABSENT = "absent"
    SAFE = "safe"
    REJECTED = "rejected"


@dataclass(frozen=True, slots=True)
class _CandidateResolution:
    path: Path
    disposition: _CandidateDisposition
    rejection: str | None = None


def detect_agent_plugin(package_root: Path) -> AgentPluginDetection | None:
    """Classify and interpret a native Agent Plugin from its exact root manifest."""
    manifest_path = package_root / "plugin.json"
    try:
        evidence = _read_admissible_root_manifest(package_root)
    except AgentPluginManifestError as exc:
        return _rejected_manifest_detection(
            manifest_path,
            str(exc),
        )
    if evidence is None:
        return None
    document = dict(evidence.document)
    if "$schema" not in document:
        return None
    schema_id = document["$schema"]
    if not isinstance(schema_id, str):
        return _rejected_manifest_detection(
            manifest_path,
            "Invalid root plugin.json: $schema must be a string",
        )
    if not schema_id.startswith(AGENT_PLUGINS_SCHEMA_PREFIX):
        return None
    try:
        loader = _VERSION_LOADERS.get(schema_id)
        if loader is None:
            raise UnsupportedAgentPluginVersionError(
                f"Unsupported Agent Plugins manifest schema: {schema_id}"
            )
        plugin = loader(package_root, manifest_path, document)
    except AgentPluginError as exc:
        return AgentPluginDetection(
            manifest_path=manifest_path,
            schema_id=schema_id,
            error=exc,
        )
    return AgentPluginDetection(
        manifest_path=manifest_path,
        schema_id=schema_id,
        plugin=plugin,
    )


def _rejected_manifest_detection(
    manifest_path: Path,
    message: str,
) -> AgentPluginDetection:
    return AgentPluginDetection(
        manifest_path=manifest_path,
        schema_id=_REJECTED_MANIFEST_SCHEMA_ID,
        error=AgentPluginManifestError(message),
    )


def load_agent_plugin(package_root: Path) -> AgentPlugin:
    """Load one native Agent Plugin or raise a typed fail-closed error."""
    detection = detect_agent_plugin(package_root)
    if detection is None:
        raise NotAgentPluginError(
            f"{package_root} does not contain a root plugin.json selecting Agent Plugins"
        )
    if detection.error is not None:
        raise detection.error
    if detection.plugin is None:
        raise AgentPluginManifestError("Agent Plugin detection produced no contract IR")
    return detection.plugin


def reject_agent_plugin_legacy_normalization(package_root: Path) -> None:
    """Prevent native Agent Plugin input from entering Claude normalization."""
    admit_legacy_plugin_manifest(package_root)


def admit_legacy_plugin_manifest(package_root: Path) -> dict[str, Any] | None:
    """Return one admissible schema-less legacy manifest or reject fallback."""
    try:
        evidence = _read_admissible_root_manifest(package_root)
    except AgentPluginManifestError as exc:
        raise AgentPluginLegacyBoundaryError(
            f"Present root plugin.json cannot enter Claude plugin normalization: {exc}"
        ) from exc
    if evidence is None:
        return None
    schema_id = evidence.document.get("$schema")
    if isinstance(schema_id, str) and schema_id.startswith(AGENT_PLUGINS_SCHEMA_PREFIX):
        raise AgentPluginLegacyBoundaryError(
            "Agent Plugin input must be interpreted by load_agent_plugin(), "
            "not Claude plugin normalization"
        )
    return dict(evidence.document)


def _read_admissible_root_manifest(package_root: Path) -> _AdmissibleRootManifest | None:
    manifest_path = package_root / "plugin.json"
    try:
        manifest_present = any(entry.name == "plugin.json" for entry in package_root.iterdir())
    except OSError as exc:
        raise AgentPluginManifestError(
            f"Root plugin.json presence could not be determined: {exc}"
        ) from exc
    if not manifest_present:
        return None
    if normalized_path_key("plugin.json") in _case_ambiguous_names(package_root):
        raise AgentPluginManifestError("Root plugin.json is case-ambiguous")
    try:
        document = read_json_document(manifest_path, reject_duplicate_schema=True)
    except (OSError, ValueError) as exc:
        raise AgentPluginManifestError(f"Invalid root plugin.json: {exc}") from exc
    if not isinstance(document, dict):
        raise AgentPluginManifestError("Invalid root plugin.json: manifest must be a JSON object")
    schema_id = document.get("$schema")
    if "$schema" in document and not isinstance(schema_id, str):
        raise AgentPluginManifestError("Invalid root plugin.json: $schema must be a string")
    return _AdmissibleRootManifest(
        path=manifest_path,
        document=MappingProxyType(document),
    )


def _load_v1(
    package_root: Path,
    manifest_path: Path,
    document: dict[str, Any],
) -> AgentPlugin:
    root = package_root.resolve()
    validation = validate_plugin_manifest_document(document)
    if not validation.is_valid or validation.normalized is None:
        raise AgentPluginManifestError("; ".join(validation.errors))
    manifest = validation.normalized
    diagnostics = [
        _diagnostic(
            code="manifest.field.ignored",
            severity=DiagnosticSeverity.WARNING,
            message=warning,
            root=root,
            path=manifest_path,
            component="manifest",
        )
        for warning in sorted(validation.warnings)
    ]

    asset_inventory = AssetInventory(root)
    try:
        root_entries = asset_inventory.list_component_candidates(root)
    except (AssetInventoryError, OSError) as exc:
        diagnostics.append(
            _diagnostic(
                code="assets.package.invalid",
                severity=DiagnosticSeverity.ERROR,
                message=f"Agent Plugin component discovery was disabled: {exc}",
                root=root,
                path=root,
                component="components",
            )
        )
        root_entries = ()
        inventory_available = False
    else:
        inventory_available = True

    identity = _identity_from_manifest(manifest)
    apm_configuration = None
    if inventory_available:
        apm_configuration, authority_diagnostics = _load_apm_configuration(
            root,
            root_entries,
            identity=identity,
            manifest=manifest,
        )
        diagnostics.extend(authority_diagnostics)

    skills, skill_diagnostics = _discover_skills(root, root_entries, asset_inventory)
    diagnostics.extend(skill_diagnostics)
    mcp_servers, mcp_diagnostics = _discover_mcp_servers(root, root_entries, asset_inventory)
    diagnostics.extend(mcp_diagnostics)
    apm_extension = _apm_extension_from_manifest(manifest, manifest_path)
    apm_components, extension_diagnostics = _discover_apm_extension_components(
        root,
        root_entries,
        apm_extension,
        asset_inventory,
    )
    diagnostics.extend(extension_diagnostics)
    diagnostics.extend(_ignored_portable_component_diagnostics(root, root_entries))

    return AgentPlugin(
        specification_version=AGENT_PLUGINS_VERSION,
        root=root,
        manifest=SourceProvenance(path=manifest_path, json_pointer=""),
        identity=identity,
        components=AgentPluginComponents(skills=skills, mcp_servers=mcp_servers),
        apm_extension=apm_extension,
        apm_configuration=apm_configuration,
        diagnostics=tuple(
            sorted(
                diagnostics,
                key=lambda item: (item.path, item.component or "", item.code, item.message),
            )
        ),
        apm_components=apm_components,
    )


def _identity_from_manifest(manifest: dict[str, Any]) -> AgentPluginIdentity:
    author = manifest.get("author")
    author_items = (
        tuple(sorted((str(key), str(value)) for key, value in author.items()))
        if isinstance(author, dict)
        else ()
    )
    keywords = manifest.get("keywords")
    return AgentPluginIdentity(
        name=manifest["name"],
        version=manifest.get("version"),
        description=manifest.get("description"),
        author=author_items,
        homepage=manifest.get("homepage"),
        repository=manifest.get("repository"),
        license=manifest.get("license"),
        keywords=tuple(keywords) if isinstance(keywords, list) else (),
    )


def _apm_extension_from_manifest(
    manifest: dict[str, Any],
    manifest_path: Path,
) -> ApmExtensionData | None:
    extensions = manifest.get("extensions")
    if not isinstance(extensions, dict):
        return None
    payload = extensions.get(COM_MICROSOFT_APM_NAMESPACE)
    if not isinstance(payload, dict):
        return None
    schema_version = payload.get("schemaVersion")
    if not isinstance(schema_version, str):
        return None
    return ApmExtensionData(
        schema_version=schema_version,
        values=_freeze_object(payload),
        provenance=SourceProvenance(
            path=manifest_path,
            json_pointer="/extensions/com.microsoft.apm",
        ),
    )


def _load_apm_configuration(
    root: Path,
    root_entries: tuple[Path, ...],
    *,
    identity: AgentPluginIdentity,
    manifest: dict[str, Any],
) -> tuple[ApmConfiguration | None, list[AgentPluginDiagnostic]]:
    apm_yml_path = root / "apm.yml"
    if not _has_exact_entry(root_entries, "apm.yml"):
        return None, []
    if not apm_yml_path.is_file() or apm_yml_path.is_symlink():
        raise AgentPluginManifestAuthorityError("Agent Plugin apm.yml must be a regular file")

    from ..utils.yaml_io import load_yaml

    try:
        document = load_yaml(apm_yml_path)
    except (OSError, yaml.YAMLError) as exc:
        raise AgentPluginManifestAuthorityError(f"Invalid Agent Plugin apm.yml: {exc}") from exc
    if not isinstance(document, dict):
        raise AgentPluginManifestAuthorityError("Agent Plugin apm.yml must contain a YAML object")
    if not all(isinstance(key, str) for key in document):
        raise AgentPluginManifestAuthorityError("Agent Plugin apm.yml keys must be strings")

    conflicts = _identity_conflicts(document, identity=identity, manifest=manifest)
    if conflicts:
        raise AgentPluginManifestAuthorityError(
            "Agent Plugin portable identity is owned by plugin.json; conflicting apm.yml fields: "
            + ", ".join(conflicts)
        )

    unsupported = sorted(set(document) - _PORTABLE_IDENTITY_FIELDS - _APM_CONFIGURATION_FIELDS)
    if unsupported:
        raise AgentPluginManifestAuthorityError(
            "Agent Plugin apm.yml may contain only APM dependency, policy, and build "
            "configuration; unsupported fields: " + ", ".join(str(field) for field in unsupported)
        )

    config = {
        str(key): value for key, value in document.items() if key in _APM_CONFIGURATION_FIELDS
    }
    duplicated = sorted(str(key) for key in document if key in _PORTABLE_IDENTITY_FIELDS)
    diagnostics = []
    if duplicated:
        diagnostics.append(
            _diagnostic(
                code="manifest.apm_identity.ignored",
                severity=DiagnosticSeverity.WARNING,
                message=(
                    "Portable identity from apm.yml was ignored; plugin.json is authoritative: "
                    + ", ".join(duplicated)
                ),
                root=root,
                path=apm_yml_path,
                component="apm",
            )
        )
    if not config:
        return None, diagnostics
    return (
        ApmConfiguration(values=_freeze_object(config), provenance=apm_yml_path),
        diagnostics,
    )


def _identity_conflicts(
    apm_document: dict[str, Any],
    *,
    identity: AgentPluginIdentity,
    manifest: dict[str, Any],
) -> list[str]:
    conflicts: list[str] = []
    for field in sorted(_PORTABLE_IDENTITY_FIELDS):
        if field not in apm_document or field not in manifest:
            continue
        apm_value = apm_document[field]
        plugin_value = manifest[field]
        if field == "author" and isinstance(apm_value, str):
            apm_value = {"name": apm_value}
        if field == "keywords" and isinstance(apm_value, tuple):
            apm_value = list(apm_value)
        if apm_value != plugin_value:
            conflicts.append(field)
    if apm_document.get("name") not in (None, identity.name):
        conflicts.append("name")
    return sorted(set(conflicts))


def _discover_skills(
    root: Path,
    root_entries: tuple[Path, ...],
    asset_inventory: AssetInventory,
) -> tuple[tuple[AgentPluginSkill, ...], list[AgentPluginDiagnostic]]:
    skills_path = root / "skills"
    if not _has_exact_entry(root_entries, "skills"):
        return (), []
    if normalized_path_key("skills") in _case_ambiguous_entries(root_entries):
        return (), [
            _diagnostic(
                code="skills.location.ambiguous",
                severity=DiagnosticSeverity.ERROR,
                message="Agent Plugins root skills directory is case-ambiguous",
                root=root,
                path=skills_path,
                component="skills",
            )
        ]
    if skills_path.is_symlink() or not skills_path.is_dir():
        return (), [
            _diagnostic(
                code="skills.location.invalid",
                severity=DiagnosticSeverity.ERROR,
                message="Agent Plugins skills must be a regular root directory",
                root=root,
                path=skills_path,
                component="skills",
            )
        ]

    from ..primitives.parser import parse_skill_file

    skills: list[AgentPluginSkill] = []
    diagnostics: list[AgentPluginDiagnostic] = []
    try:
        skill_entries = asset_inventory.list_component_candidates(skills_path)
    except (AssetInventoryError, OSError) as exc:
        return (), [
            _diagnostic(
                code="skills.assets.invalid",
                severity=DiagnosticSeverity.ERROR,
                message=f"Agent Plugins skills were disabled: {exc}",
                root=root,
                path=skills_path,
                component="skills",
            )
        ]
    ambiguous_names = _case_ambiguous_entries(skill_entries)
    for child in skill_entries:
        if normalized_path_key(child.name) in ambiguous_names:
            diagnostics.append(
                _diagnostic(
                    code="skill.path.ambiguous",
                    severity=DiagnosticSeverity.ERROR,
                    message=f"Skill directory {child.name} is case-ambiguous and was skipped",
                    root=root,
                    path=child,
                    component=f"skill:{child.name}",
                )
            )
            continue
        if child.is_symlink() or not child.is_dir():
            diagnostics.append(
                _diagnostic(
                    code="skill.location.invalid",
                    severity=DiagnosticSeverity.ERROR,
                    message=f"Skill entry {child.name} is not a regular directory and was skipped",
                    root=root,
                    path=child,
                    component=f"skill:{child.name}",
                )
            )
            continue
        try:
            assets = asset_inventory.collect_component(child)
        except (AssetInventoryError, OSError) as exc:
            diagnostics.append(
                _diagnostic(
                    code="skill.assets.invalid",
                    severity=DiagnosticSeverity.ERROR,
                    message=f"Skill {child.name} was skipped: {exc}",
                    root=root,
                    path=child,
                    component=f"skill:{child.name}",
                )
            )
            continue
        skill_manifest = child / "SKILL.md"
        manifest_relative = f"skills/{child.name}/SKILL.md"
        manifest_asset = next((asset for asset in assets if asset.path == manifest_relative), None)
        if manifest_asset is None:
            diagnostics.append(
                _diagnostic(
                    code="skill.manifest.missing",
                    severity=DiagnosticSeverity.ERROR,
                    message=f"Skill directory {child.name} has no exact regular SKILL.md and was skipped",
                    root=root,
                    path=child,
                    component=f"skill:{child.name}",
                )
            )
            continue
        try:
            parsed = parse_skill_file(skill_manifest)
            errors = parsed.validate()
            with asset_inventory.open_verified_asset(manifest_asset):
                pass
        except (AssetInventoryError, ValueError) as exc:
            errors = [str(exc)]
            parsed = None
        if errors or parsed is None:
            diagnostics.append(
                _diagnostic(
                    code="skill.invalid",
                    severity=DiagnosticSeverity.ERROR,
                    message=f"Skill {child.name} was skipped: {'; '.join(errors)}",
                    root=root,
                    path=skill_manifest,
                    component=f"skill:{child.name}",
                )
            )
            continue
        skills.append(
            AgentPluginSkill(
                directory_name=child.name,
                name=parsed.name,
                description=parsed.description,
                root=child,
                manifest=SourceProvenance(path=skill_manifest, json_pointer=""),
                assets=assets,
            )
        )
    return tuple(skills), diagnostics


def _discover_mcp_servers(
    root: Path,
    root_entries: tuple[Path, ...],
    asset_inventory: AssetInventory,
) -> tuple[tuple[AgentPluginMcpServer, ...], list[AgentPluginDiagnostic]]:
    mcp_path = root / "mcp.json"
    if not _has_exact_entry(root_entries, "mcp.json"):
        return (), []
    if normalized_path_key("mcp.json") in _case_ambiguous_entries(root_entries):
        return (), [
            _diagnostic(
                code="mcp.location.ambiguous",
                severity=DiagnosticSeverity.ERROR,
                message="Agent Plugins root mcp.json is case-ambiguous",
                root=root,
                path=mcp_path,
                component="mcp",
            )
        ]
    if mcp_path.is_symlink() or not mcp_path.is_file():
        return (), [
            _diagnostic(
                code="mcp.location.invalid",
                severity=DiagnosticSeverity.ERROR,
                message="Agent Plugins MCP configuration must be root mcp.json as a regular file",
                root=root,
                path=mcp_path,
                component="mcp",
            )
        ]

    try:
        validation = validate_mcp_config_file(
            mcp_path,
            expected_plugin_schema_id=PLUGIN_SCHEMA_ID,
            isolate_invalid_servers=True,
            plugin_root=root,
        )
    except (OSError, ValueError) as exc:
        return (), [
            _diagnostic(
                code="mcp.document.invalid",
                severity=DiagnosticSeverity.ERROR,
                message=f"Agent Plugins mcp.json was disabled: {exc}",
                root=root,
                path=mcp_path,
                component="mcp",
            )
        ]
    if validation.errors or validation.normalized is None:
        return (), [
            _diagnostic(
                code="mcp.document.invalid",
                severity=DiagnosticSeverity.ERROR,
                message=f"Agent Plugins mcp.json was disabled: {error}",
                root=root,
                path=mcp_path,
                component="mcp",
            )
            for error in sorted(validation.errors)
        ]

    diagnostics = [
        _diagnostic(
            code="mcp.server.invalid",
            severity=DiagnosticSeverity.ERROR,
            message=warning,
            root=root,
            path=mcp_path,
            component="mcp",
        )
        for warning in sorted(validation.warnings)
    ]
    raw_servers = validation.normalized["mcpServers"]
    servers: list[AgentPluginMcpServer] = []
    for name in sorted(raw_servers):
        server, executable_diagnostics = _mcp_server_from_normalized(
            name,
            raw_servers[name],
            mcp_path,
            root,
            asset_inventory,
        )
        diagnostics.extend(executable_diagnostics)
        if server is not None:
            servers.append(server)
    return tuple(servers), diagnostics


def _mcp_server_from_normalized(
    name: str,
    config: dict[str, Any],
    mcp_path: Path,
    root: Path,
    asset_inventory: AssetInventory,
) -> tuple[AgentPluginMcpServer | None, list[AgentPluginDiagnostic]]:
    server_type = McpServerType(config["type"])
    provenance = SourceProvenance(
        path=mcp_path,
        json_pointer=f"/mcpServers/{_escape_json_pointer(name)}",
    )
    executables, diagnostics = _declaration_executables(
        root=root,
        asset_inventory=asset_inventory,
        declarations=(
            (
                config.get("command"),
                f"{provenance.json_pointer}/command",
                True,
            ),
            *(
                (
                    argument,
                    f"{provenance.json_pointer}/args/{index}",
                    False,
                )
                for index, argument in enumerate(config.get("args", ()))
            ),
        ),
        source_path=mcp_path,
        component=f"mcp:{name}",
        diagnostic_code="mcp.server.executable.invalid",
    )
    if any(diagnostic.severity is DiagnosticSeverity.ERROR for diagnostic in diagnostics):
        return None, diagnostics
    return (
        AgentPluginMcpServer(
            name=name,
            server_type=server_type,
            command=config.get("command"),
            args=tuple(config.get("args", ())),
            env=tuple(sorted(config.get("env", {}).items())),
            cwd=config.get("cwd"),
            url=config.get("url"),
            headers=tuple(sorted(config.get("headers", {}).items())),
            provenance=provenance,
            executables=executables,
        ),
        diagnostics,
    )


def _discover_apm_extension_components(
    root: Path,
    root_entries: tuple[Path, ...],
    extension: ApmExtensionData | None,
    asset_inventory: AssetInventory,
) -> tuple[ApmExtensionComponents | None, list[AgentPluginDiagnostic]]:
    namespace_root = root / COM_MICROSOFT_APM_NAMESPACE
    if extension is None or extension.schema_version != COM_MICROSOFT_APM_SCHEMA_VERSION:
        if _has_exact_entry(root_entries, COM_MICROSOFT_APM_NAMESPACE):
            return None, [
                _diagnostic(
                    code="apm.extension.undeclared",
                    severity=DiagnosticSeverity.WARNING,
                    message=(
                        "com.microsoft.apm data was ignored because plugin.json does not "
                        "declare extensions.com.microsoft.apm.schemaVersion '1'"
                    ),
                    root=root,
                    path=namespace_root,
                    component="apm-extension",
                )
            ]
        return None, []

    empty = ApmExtensionComponents(
        agents=None,
        commands=None,
        instructions=None,
        extensions=None,
        hooks=None,
        lsp=None,
    )
    if not _has_exact_entry(root_entries, COM_MICROSOFT_APM_NAMESPACE):
        return empty, []
    if normalized_path_key(COM_MICROSOFT_APM_NAMESPACE) in _case_ambiguous_entries(root_entries):
        return empty, [
            _diagnostic(
                code="apm.extension.location.ambiguous",
                severity=DiagnosticSeverity.ERROR,
                message="com.microsoft.apm is case-ambiguous and was ignored",
                root=root,
                path=namespace_root,
                component="apm-extension",
            )
        ]
    if namespace_root.is_symlink() or not namespace_root.is_dir():
        return empty, [
            _diagnostic(
                code="apm.extension.location.invalid",
                severity=DiagnosticSeverity.ERROR,
                message="com.microsoft.apm must be an exact regular directory",
                root=root,
                path=namespace_root,
                component="apm-extension",
            )
        ]

    diagnostics: list[AgentPluginDiagnostic] = []
    try:
        namespace_entries = asset_inventory.list_component_candidates(namespace_root)
    except (AssetInventoryError, OSError) as exc:
        return empty, [
            _diagnostic(
                code="apm.extension.location.invalid",
                severity=DiagnosticSeverity.ERROR,
                message=f"com.microsoft.apm could not be inspected: {exc}",
                root=root,
                path=namespace_root,
                component="apm-extension",
            )
        ]
    ambiguous_names = _case_ambiguous_entries(namespace_entries)
    for entry in namespace_entries:
        if entry.name not in _APM_ALLOWED_ROOT_ENTRIES:
            diagnostics.append(
                _diagnostic(
                    code="apm.extension.path.ignored",
                    severity=DiagnosticSeverity.WARNING,
                    message=f"Undeclared APM extension path {entry.name} was ignored",
                    root=root,
                    path=entry,
                    component="apm-extension",
                )
            )

    directory_components: dict[str, ApmExtensionFileComponent | None] = {}
    for name in _APM_DIRECTORY_COMPONENTS:
        directory_components[name] = _discover_apm_file_component(
            root,
            namespace_root,
            namespace_entries,
            name,
            ambiguous_names,
            asset_inventory,
            diagnostics,
        )
    hooks = _discover_apm_hook_component(
        root,
        namespace_root,
        namespace_entries,
        ambiguous_names,
        asset_inventory,
        diagnostics,
    )
    lsp = _discover_apm_lsp_component(
        root,
        namespace_root,
        namespace_entries,
        ambiguous_names,
        asset_inventory,
        diagnostics,
    )
    return (
        ApmExtensionComponents(
            agents=directory_components["agents"],
            commands=directory_components["commands"],
            instructions=directory_components["instructions"],
            extensions=directory_components["extensions"],
            hooks=hooks,
            lsp=lsp,
        ),
        diagnostics,
    )


def _discover_apm_file_component(
    root: Path,
    namespace_root: Path,
    namespace_entries: tuple[Path, ...],
    name: str,
    ambiguous_names: set[str],
    asset_inventory: AssetInventory,
    diagnostics: list[AgentPluginDiagnostic],
) -> ApmExtensionFileComponent | None:
    component_root = namespace_root / name
    if not _has_exact_entry(namespace_entries, name):
        return None
    if normalized_path_key(name) in ambiguous_names:
        diagnostics.append(
            _diagnostic(
                code="apm.extension.path.ambiguous",
                severity=DiagnosticSeverity.ERROR,
                message=f"APM extension component {name} is case-ambiguous and was ignored",
                root=root,
                path=component_root,
                component=f"apm:{name}",
            )
        )
        return None
    if component_root.is_symlink() or not component_root.is_dir():
        diagnostics.append(
            _diagnostic(
                code="apm.extension.component.invalid",
                severity=DiagnosticSeverity.ERROR,
                message=f"APM extension component {name} must be a regular directory",
                root=root,
                path=component_root,
                component=f"apm:{name}",
            )
        )
        return None
    try:
        assets = asset_inventory.collect_component(component_root)
    except (AssetInventoryError, OSError) as exc:
        diagnostics.append(
            _diagnostic(
                code="apm.extension.assets.invalid",
                severity=DiagnosticSeverity.ERROR,
                message=f"APM extension component {name} was ignored: {exc}",
                root=root,
                path=component_root,
                component=f"apm:{name}",
            )
        )
        return None
    return ApmExtensionFileComponent(
        name=name,
        root=component_root,
        provenance=SourceProvenance(path=component_root, json_pointer=""),
        assets=assets,
    )


def _discover_apm_lsp_component(
    root: Path,
    namespace_root: Path,
    namespace_entries: tuple[Path, ...],
    ambiguous_names: set[str],
    asset_inventory: AssetInventory,
    diagnostics: list[AgentPluginDiagnostic],
) -> ApmExtensionLspComponent | None:
    lsp_path = namespace_root / "lsp.json"
    if not _has_exact_entry(namespace_entries, "lsp.json"):
        return None
    if normalized_path_key("lsp.json") in ambiguous_names:
        diagnostics.append(
            _diagnostic(
                code="apm.lsp.path.ambiguous",
                severity=DiagnosticSeverity.ERROR,
                message="com.microsoft.apm/lsp.json is case-ambiguous and was disabled",
                root=root,
                path=lsp_path,
                component="apm:lsp",
            )
        )
        return None
    try:
        document_asset, payload = asset_inventory.read_file(
            lsp_path,
            max_bytes=MAX_JSON_BYTES,
        )
        document = decode_json_document(payload, path=lsp_path)
        validation = validate_lsp_extension_document(
            document,
            isolate_invalid_servers=True,
            plugin_root=root,
        )
    except (AssetInventoryError, OSError, ValueError) as exc:
        diagnostics.append(
            _diagnostic(
                code="apm.lsp.document.invalid",
                severity=DiagnosticSeverity.ERROR,
                message=f"com.microsoft.apm/lsp.json was disabled: {exc}",
                root=root,
                path=lsp_path,
                component="apm:lsp",
            )
        )
        return None
    if validation.errors or validation.normalized is None:
        for error in sorted(validation.errors):
            diagnostics.append(
                _diagnostic(
                    code="apm.lsp.document.invalid",
                    severity=DiagnosticSeverity.ERROR,
                    message=f"com.microsoft.apm/lsp.json was disabled: {error}",
                    root=root,
                    path=lsp_path,
                    component="apm:lsp",
                )
            )
        return None
    diagnostics.extend(
        _diagnostic(
            code="apm.lsp.server.invalid",
            severity=DiagnosticSeverity.ERROR,
            message=warning,
            root=root,
            path=lsp_path,
            component="apm:lsp",
        )
        for warning in sorted(validation.warnings)
    )
    servers: list[ApmExtensionLspServer] = []
    assets = [document_asset]
    raw_servers = validation.normalized["lspServers"]
    for name in sorted(raw_servers):
        config = raw_servers[name]
        provenance = SourceProvenance(
            path=lsp_path,
            json_pointer=f"/lspServers/{_escape_json_pointer(name)}",
        )
        executables, executable_diagnostics = _declaration_executables(
            root=root,
            asset_inventory=asset_inventory,
            declarations=(
                (config.get("command"), f"{provenance.json_pointer}/command", True),
                *(
                    (argument, f"{provenance.json_pointer}/args/{index}", False)
                    for index, argument in enumerate(config.get("args", ()))
                ),
            ),
            source_path=lsp_path,
            component=f"apm:lsp:{name}",
            diagnostic_code="apm.lsp.server.executable.invalid",
        )
        diagnostics.extend(executable_diagnostics)
        if any(
            diagnostic.severity is DiagnosticSeverity.ERROR for diagnostic in executable_diagnostics
        ):
            continue
        for executable in executables:
            if executable.asset is not None:
                assets.append(executable.asset)
        servers.append(_lsp_server_from_normalized(name, config, provenance, executables))
    return ApmExtensionLspComponent(
        provenance=SourceProvenance(path=lsp_path, json_pointer=""),
        servers=tuple(servers),
        assets=_deduplicate_assets(assets),
    )


def _lsp_server_from_normalized(
    name: str,
    config: dict[str, Any],
    provenance: SourceProvenance,
    executables: tuple[AgentPluginExecutable, ...],
) -> ApmExtensionLspServer:
    initialization_options = config.get("initializationOptions")
    settings = config.get("settings")
    return ApmExtensionLspServer(
        name=name,
        command=config["command"],
        args=tuple(config.get("args", ())),
        env=tuple(sorted(config.get("env", {}).items())),
        extension_to_language=tuple(sorted(config.get("extensionToLanguage", {}).items())),
        transport=config.get("transport"),
        initialization_options=(
            _freeze_json(initialization_options) if initialization_options is not None else None
        ),
        settings=_freeze_json(settings) if settings is not None else None,
        workspace_folder=config.get("workspaceFolder"),
        startup_timeout=config.get("startupTimeout"),
        shutdown_timeout=config.get("shutdownTimeout"),
        restart_on_crash=config.get("restartOnCrash"),
        max_restarts=config.get("maxRestarts"),
        provenance=provenance,
        executables=executables,
    )


def _discover_apm_hook_component(
    root: Path,
    namespace_root: Path,
    namespace_entries: tuple[Path, ...],
    ambiguous_names: set[str],
    asset_inventory: AssetInventory,
    diagnostics: list[AgentPluginDiagnostic],
) -> ApmExtensionHookComponent | None:
    hooks_root = namespace_root / "hooks"
    if not _has_exact_entry(namespace_entries, "hooks"):
        return None
    if (
        normalized_path_key("hooks") in ambiguous_names
        or hooks_root.is_symlink()
        or not hooks_root.is_dir()
    ):
        diagnostics.append(
            _diagnostic(
                code="apm.hooks.location.invalid",
                severity=DiagnosticSeverity.ERROR,
                message="com.microsoft.apm/hooks must be one exact regular directory",
                root=root,
                path=hooks_root,
                component="apm:hooks",
            )
        )
        return None
    hooks_path = hooks_root / "hooks.json"
    try:
        hook_entries = asset_inventory.list_component_candidates(hooks_root)
    except (AssetInventoryError, OSError) as exc:
        diagnostics.append(
            _diagnostic(
                code="apm.hooks.location.invalid",
                severity=DiagnosticSeverity.ERROR,
                message=f"com.microsoft.apm/hooks could not be inspected: {exc}",
                root=root,
                path=hooks_root,
                component="apm:hooks",
            )
        )
        return None
    hook_ambiguous_names = _case_ambiguous_entries(hook_entries)
    if not _has_exact_entry(hook_entries, "hooks.json"):
        diagnostics.append(
            _diagnostic(
                code="apm.hooks.document.missing",
                severity=DiagnosticSeverity.ERROR,
                message="com.microsoft.apm/hooks has no exact hooks/hooks.json",
                root=root,
                path=hooks_root,
                component="apm:hooks",
            )
        )
        return None
    if normalized_path_key("hooks.json") in hook_ambiguous_names:
        diagnostics.append(
            _diagnostic(
                code="apm.hooks.path.ambiguous",
                severity=DiagnosticSeverity.ERROR,
                message="com.microsoft.apm/hooks/hooks.json is case-ambiguous and was disabled",
                root=root,
                path=hooks_path,
                component="apm:hooks",
            )
        )
        return None
    try:
        document_asset, payload = asset_inventory.read_file(
            hooks_path,
            max_bytes=MAX_JSON_BYTES,
        )
        document = decode_json_document(payload, path=hooks_path)
    except (AssetInventoryError, OSError, ValueError) as exc:
        diagnostics.append(
            _diagnostic(
                code="apm.hooks.document.invalid",
                severity=DiagnosticSeverity.ERROR,
                message=f"com.microsoft.apm/hooks/hooks.json was disabled: {exc}",
                root=root,
                path=hooks_path,
                component="apm:hooks",
            )
        )
        return None
    try:
        hook_source = parse_hook_source(document)
    except HookContractError as exc:
        diagnostics.append(
            _diagnostic(
                code="apm.hooks.document.invalid",
                severity=DiagnosticSeverity.ERROR,
                message=f"com.microsoft.apm/hooks/hooks.json was disabled: {exc}",
                root=root,
                path=hooks_path,
                component="apm:hooks",
            )
        )
        return None
    executables, executable_diagnostics = _hook_executables(
        root,
        hooks_path,
        hook_source,
        asset_inventory,
    )
    diagnostics.extend(executable_diagnostics)
    if any(
        diagnostic.severity is DiagnosticSeverity.ERROR for diagnostic in executable_diagnostics
    ):
        return None
    _warn_unreferenced_hook_entries(
        root,
        hooks_root,
        hook_entries,
        executables,
        diagnostics,
    )
    assets = [
        document_asset,
        *(executable.asset for executable in executables if executable.asset is not None),
    ]
    return ApmExtensionHookComponent(
        document=_freeze_object(document),
        provenance=SourceProvenance(path=hooks_path, json_pointer=""),
        executables=executables,
        assets=_deduplicate_assets(assets),
    )


def _hook_executables(
    root: Path,
    hooks_path: Path,
    hook_source: HookSourceDocument,
    asset_inventory: AssetInventory,
) -> tuple[tuple[AgentPluginExecutable, ...], list[AgentPluginDiagnostic]]:
    executables: list[AgentPluginExecutable] = []
    diagnostics: list[AgentPluginDiagnostic] = []
    for declaration in hook_source.commands:
        references = _command_path_references(declaration.command)
        if not references:
            executables.append(
                AgentPluginExecutable(
                    declaration=declaration.command,
                    plugin_relative_path=None,
                    asset=None,
                    provenance=SourceProvenance(
                        path=hooks_path,
                        json_pointer=declaration.json_pointer,
                    ),
                )
            )
            continue
        declarations = tuple(
            (reference, declaration.json_pointer, False) for reference in references
        )
        resolved, errors = _declaration_executables(
            root=root,
            asset_inventory=asset_inventory,
            declarations=declarations,
            source_path=hooks_path,
            component=f"apm:hooks:{declaration.event}",
            diagnostic_code="apm.hooks.executable.invalid",
            relative_base=hooks_path.parent,
        )
        executables.extend(resolved)
        diagnostics.extend(errors)
    return tuple(executables), diagnostics


def _warn_unreferenced_hook_entries(
    root: Path,
    hooks_root: Path,
    hook_entries: tuple[Path, ...],
    executables: tuple[AgentPluginExecutable, ...],
    diagnostics: list[AgentPluginDiagnostic],
) -> None:
    """Warn only for hook-directory entries absent from typed declarations."""
    referenced_entries: set[str] = set()
    for executable in executables:
        relative = executable.plugin_relative_path
        if relative is None:
            continue
        try:
            hook_relative = (root / Path(*relative.split("/"))).relative_to(hooks_root)
        except ValueError:
            continue
        if hook_relative.parts:
            referenced_entries.add(hook_relative.parts[0])
    for entry in hook_entries:
        if entry.name == "hooks.json" or entry.name in referenced_entries:
            continue
        diagnostics.append(
            _diagnostic(
                code="apm.hooks.path.ignored",
                severity=DiagnosticSeverity.WARNING,
                message=f"Undeclared APM hook path {entry.name} was ignored",
                root=root,
                path=entry,
                component="apm:hooks",
            )
        )


def _command_path_references(command: str) -> tuple[str, ...]:
    return tuple(
        dict.fromkeys(
            match.group("reference").replace("\\", "/")
            for match in _PATH_REFERENCE_RE.finditer(command)
        )
    )


def _declaration_executables(
    *,
    root: Path,
    asset_inventory: AssetInventory,
    declarations: tuple[tuple[object, str, bool], ...],
    source_path: Path,
    component: str,
    diagnostic_code: str,
    relative_base: Path | None = None,
) -> tuple[tuple[AgentPluginExecutable, ...], list[AgentPluginDiagnostic]]:
    executables: list[AgentPluginExecutable] = []
    diagnostics: list[AgentPluginDiagnostic] = []
    for declaration, json_pointer, include_external in declarations:
        if not isinstance(declaration, str):
            continue
        relative = _plugin_relative_declaration_path(declaration)
        if relative is None:
            if include_external:
                executables.append(
                    AgentPluginExecutable(
                        declaration=declaration,
                        plugin_relative_path=None,
                        asset=None,
                        provenance=SourceProvenance(
                            path=source_path,
                            json_pointer=json_pointer,
                        ),
                    )
                )
            continue
        try:
            validate_path_segments(
                relative,
                context="Agent Plugin executable reference",
                reject_empty=True,
                allow_current_dir=True,
            )
        except PathTraversalError as exc:
            diagnostics.append(
                _diagnostic(
                    code=diagnostic_code,
                    severity=DiagnosticSeverity.ERROR,
                    message=f"Executable reference {declaration!r} was rejected: {exc}",
                    root=root,
                    path=source_path,
                    component=component,
                )
            )
            continue
        relative_path = Path(*PurePosixPath(relative).parts)
        if declaration.replace("\\", "/").startswith("./") and relative_base is not None:
            primary = _resolve_executable_candidate(relative_base / relative_path, root)
            resolution = (
                _resolve_executable_candidate(root / relative_path, root)
                if primary.disposition is _CandidateDisposition.ABSENT
                else primary
            )
        else:
            resolution = _resolve_executable_candidate(root / relative_path, root)
        if resolution.disposition is _CandidateDisposition.REJECTED:
            diagnostics.append(
                _diagnostic(
                    code=diagnostic_code,
                    severity=DiagnosticSeverity.ERROR,
                    message=(
                        f"Executable reference {declaration!r} was rejected: {resolution.rejection}"
                    ),
                    root=root,
                    path=source_path,
                    component=component,
                )
            )
            continue
        candidate = resolution.path
        relative = candidate.relative_to(root).as_posix()
        if resolution.disposition is _CandidateDisposition.ABSENT:
            executables.append(
                AgentPluginExecutable(
                    declaration=declaration,
                    plugin_relative_path=relative,
                    asset=None,
                    provenance=SourceProvenance(
                        path=source_path,
                        json_pointer=json_pointer,
                    ),
                )
            )
            diagnostics.append(
                _diagnostic(
                    code=diagnostic_code.replace(".invalid", ".missing"),
                    severity=DiagnosticSeverity.WARNING,
                    message=f"Executable reference {declaration!r} has no package asset",
                    root=root,
                    path=source_path,
                    component=component,
                )
            )
            continue
        try:
            asset = asset_inventory.collect_file(candidate)
        except (AssetInventoryError, OSError) as exc:
            diagnostics.append(
                _diagnostic(
                    code=diagnostic_code,
                    severity=DiagnosticSeverity.ERROR,
                    message=f"Executable reference {declaration!r} was rejected: {exc}",
                    root=root,
                    path=source_path,
                    component=component,
                )
            )
            continue
        executables.append(
            AgentPluginExecutable(
                declaration=declaration,
                plugin_relative_path=relative,
                asset=asset,
                provenance=SourceProvenance(
                    path=source_path,
                    json_pointer=json_pointer,
                ),
            )
        )
    return tuple(executables), diagnostics


def _resolve_executable_candidate(path: Path, root: Path) -> _CandidateResolution:
    """Classify one literal candidate without conflating absence and rejection."""
    try:
        ensure_path_within(path, root)
    except (OSError, PathTraversalError, RuntimeError) as exc:
        return _CandidateResolution(
            path=path,
            disposition=_CandidateDisposition.REJECTED,
            rejection=str(exc),
        )
    try:
        path.lstat()
    except FileNotFoundError:
        return _CandidateResolution(path=path, disposition=_CandidateDisposition.ABSENT)
    except OSError as exc:
        return _CandidateResolution(
            path=path,
            disposition=_CandidateDisposition.REJECTED,
            rejection=f"asset metadata is unreadable: {exc}",
        )
    return _CandidateResolution(path=path, disposition=_CandidateDisposition.SAFE)


def _plugin_relative_declaration_path(declaration: str) -> str | None:
    portable_declaration = declaration.replace("\\", "/")
    if portable_declaration.startswith("./"):
        relative = portable_declaration[2:]
    elif portable_declaration.startswith("${PLUGIN_ROOT}/"):
        relative = portable_declaration.removeprefix("${PLUGIN_ROOT}/")
    elif portable_declaration.startswith("../"):
        relative = portable_declaration
    else:
        return None
    portable = PurePosixPath(relative)
    if portable.is_absolute() or any(part in ("", ".", "..") for part in portable.parts):
        return relative
    return portable.as_posix()


def _deduplicate_assets(assets: list[AgentPluginAsset]) -> tuple[AgentPluginAsset, ...]:
    return tuple(
        {asset.path: asset for asset in assets}[path] for path in sorted({a.path for a in assets})
    )


def _ignored_portable_component_diagnostics(
    root: Path,
    root_entries: tuple[Path, ...],
) -> list[AgentPluginDiagnostic]:
    diagnostics: list[AgentPluginDiagnostic] = []
    for name in _IGNORED_PORTABLE_COMPONENT_PATHS:
        if not _has_exact_entry(root_entries, name):
            continue
        diagnostics.append(
            _diagnostic(
                code="portable.component.ignored",
                severity=DiagnosticSeverity.WARNING,
                message=(
                    f"Root {name} is not an Agent Plugins v1 portable component and was ignored; "
                    f"declare APM-specific content under {COM_MICROSOFT_APM_NAMESPACE}/"
                ),
                root=root,
                path=root / name,
                component="portable",
            )
        )
    return diagnostics


def _case_ambiguous_names(directory: Path) -> set[str]:
    try:
        return _case_ambiguous_entries(tuple(directory.iterdir()))
    except OSError:
        return set()


def _case_ambiguous_entries(entries: tuple[Path, ...]) -> set[str]:
    grouped: dict[str, list[str]] = {}
    for entry in entries:
        grouped.setdefault(normalized_path_key(entry.name), []).append(entry.name)
    return {key for key, names in grouped.items() if len(set(names)) > 1}


def _freeze_json(value: object) -> FrozenJsonValue:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, list):
        return FrozenJsonArray(tuple(_freeze_json(item) for item in value))
    if isinstance(value, dict):
        return _freeze_object(value)
    raise AgentPluginManifestAuthorityError(
        f"APM configuration contains unsupported value type: {type(value).__name__}"
    )


def _freeze_object(value: dict[str, Any]) -> FrozenJsonObject:
    if not all(isinstance(key, str) for key in value):
        raise AgentPluginManifestAuthorityError("APM configuration object keys must be strings")
    return FrozenJsonObject(tuple(sorted((key, _freeze_json(item)) for key, item in value.items())))


def _diagnostic(
    *,
    code: str,
    severity: DiagnosticSeverity,
    message: str,
    root: Path,
    path: Path,
    component: str | None,
) -> AgentPluginDiagnostic:
    try:
        relative_path = path.resolve().relative_to(root).as_posix()
    except (OSError, ValueError):
        relative_path = path.name
    return AgentPluginDiagnostic(
        code=code,
        severity=severity,
        message=message,
        path=relative_path,
        component=component,
    )


def _escape_json_pointer(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def _has_exact_entry(entries: tuple[Path, ...], name: str) -> bool:
    return any(entry.name == name for entry in entries)


_VERSION_LOADERS: dict[str, Callable[[Path, Path, dict[str, Any]], AgentPlugin]] = {
    PLUGIN_SCHEMA_ID: _load_v1
}
