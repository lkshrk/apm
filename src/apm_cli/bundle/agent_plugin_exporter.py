"""Agent Plugin bundle exporter."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
from pathlib import Path

from ..agent_plugins import (
    MCP_SCHEMA_ID,
    PLUGIN_SCHEMA_ID,
    AgentPlugin,
    AgentPluginAsset,
    AgentPluginExecutable,
    DiagnosticSeverity,
    args_contain_literal_secret,
    contains_literal_secret_fields,
    load_agent_plugin,
    url_contains_literal_secret,
)
from ..agent_plugins.constants import (
    COM_MICROSOFT_APM_NAMESPACE,
    COM_MICROSOFT_APM_SCHEMA_VERSION,
)
from ..deps.lockfile import LockFile, get_lockfile_path, migrate_lockfile_if_needed
from ..deps.plugin_parser import synthesize_plugin_json_from_apm_yml
from ..models.apm_package import APMPackage
from ..utils.archive import (
    projected_archive_path,
    validate_archive_format,
)
from ..utils.console import _rich_warning
from ..utils.path_security import ensure_path_within, safe_rmtree
from .export_common import (
    _cache_would_contribute_hooks_or_mcp,
    _cache_would_contribute_primitives,
    _collect_apm_components,
    _collect_deployed_components,
    _collect_explicit_local_components,
    _collect_hooks_from_apm,
    _collect_hooks_from_root,
    _collect_root_plugin_components,
    _deep_merge,
    _dep_install_path,
    _get_dev_dependency_urls,
    _merge_file_map,
    _sanitize_bundle_name,
    _scan_bundle_sources,
    _warn_no_local_primitives,
    _warn_skipped_root_components,
    _write_bundle_sources,
)
from .formats import BundleFormat, agent_plugin_warning
from .lockfile_enrichment import enrich_lockfile_for_pack
from .packer import PackResult
from .reproducible_archive import write_reproducible_archive

_NAMESPACE = COM_MICROSOFT_APM_NAMESPACE
_NAMESPACE_PREFIX = f"{_NAMESPACE}/"
_APM_FILE_COMPONENT_NAMES = ("agents", "commands", "instructions", "extensions")


def _namespace_output_rel(output_rel: str) -> str:
    """Map plugin-native paths into the Agent Plugin namespace."""
    if output_rel.startswith("skills/") or output_rel.startswith(_NAMESPACE_PREFIX):
        return output_rel
    if output_rel == "hooks.json":
        return f"{_NAMESPACE_PREFIX}hooks/hooks.json"
    if output_rel == ".mcp.json":
        return "mcp.json"
    if output_rel == "mcp.json":
        return "mcp.json"
    if output_rel == ".lsp.json":
        return f"{_NAMESPACE_PREFIX}lsp.json"
    return f"{_NAMESPACE_PREFIX}{output_rel}"


def _copy_optional_root_file(project_root: Path, bundle_dir: Path, name: str) -> str | None:
    source = project_root / name
    if not source.is_file() or source.is_symlink():
        return None
    dest = bundle_dir / name
    ensure_path_within(dest, bundle_dir)
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, dest, follow_symlinks=False)
    return name


def _agent_lsp_document(package: APMPackage, lockfile: LockFile) -> dict | None:
    """Project resolved production LSP configs into the APM extension."""
    dev_names = {dependency.name for dependency in package.get_dev_lsp_dependencies()}
    prod_names = {dependency.name for dependency in package.get_lsp_dependencies()}
    resolved_names = set(lockfile.lsp_servers)
    servers: dict[str, object] = {}
    for name, config in lockfile.lsp_configs.items():
        if name not in resolved_names or (name in dev_names and name not in prod_names):
            continue
        if isinstance(config, dict):
            projected = dict(config)
            projected.pop("name", None)
        else:
            projected = config
        servers[str(name)] = projected
    if not servers:
        return None
    return {"lspServers": servers}


def _agent_mcp_document(package: APMPackage, lockfile: LockFile) -> dict:
    """Project resolved production MCP configs into the Agent Plugins schema."""
    dev_names = {dependency.name for dependency in package.get_dev_mcp_dependencies()}
    prod_names = {dependency.name for dependency in package.get_mcp_dependencies()}
    servers: dict[str, dict] = {}
    resolved_names = set(lockfile.mcp_servers)
    for name, raw_config in lockfile.mcp_configs.items():
        if name not in resolved_names:
            continue
        if name in dev_names and name not in prod_names:
            continue
        if not isinstance(raw_config, dict):
            raise ValueError(f"Cannot pack MCP server {name!r}: resolved config is not an object")

        transport = str(raw_config.get("transport") or raw_config.get("type") or "").lower()
        if transport == "http":
            transport = "streamable-http"
        if transport == "stdio":
            allowed = ("command", "args", "env", "cwd")
        elif transport in {"streamable-http", "sse"}:
            allowed = ("url", "headers")
        else:
            raise ValueError(
                f"Cannot pack MCP server {name!r}: transport {transport or '<missing>'!r} "
                "is not representable by Agent Plugins v1. Use a portable stdio, "
                "streamable-http, or sse config, or run 'apm pack --claude-plugin'."
            )

        projected = {"type": transport}
        projected.update(
            {key: raw_config[key] for key in allowed if raw_config.get(key) is not None}
        )
        if (
            contains_literal_secret_fields(projected.get("env"))
            or contains_literal_secret_fields(projected.get("headers"))
            or url_contains_literal_secret(projected.get("url"))
            or args_contain_literal_secret(projected.get("args"))
        ):
            raise ValueError(
                f"Cannot pack MCP server {name!r}: secret-shaped environment, header, URL, "
                "or argument values must use ${VAR} references. Replace the literal secret or run "
                "'apm pack --claude-plugin'."
            )
        servers[str(name)] = projected

    return {"$schema": MCP_SCHEMA_ID, "mcpServers": servers}


def _expected_skill_assets(output_files: set[str]) -> dict[str, set[str]]:
    """Return exact portable skill assets grouped by immediate directory."""
    expected: dict[str, set[str]] = {}
    for output_file in output_files:
        parts = Path(output_file).parts
        if len(parts) >= 3 and parts[0] == "skills":
            expected.setdefault(parts[1], set()).add(output_file)
    return expected


def _asset_paths(assets: tuple[AgentPluginAsset, ...]) -> set[str]:
    """Return canonical paths from an immutable loader-owned inventory."""
    return {asset.path for asset in assets}


def _validate_executable_facts(
    executables: tuple[AgentPluginExecutable, ...],
    *,
    declaration_path: Path,
    expected_output_files: set[str],
    component: str,
) -> None:
    """Require referenced executable facts to remain tied to generated assets."""
    for executable in executables:
        if executable.provenance.path != declaration_path:
            raise ValueError(
                f"Generated Agent Plugin {component} executable provenance changed during "
                f"canonical reload: {executable.provenance.path}"
            )
        if executable.plugin_relative_path is None:
            if executable.asset is not None:
                raise ValueError(
                    f"Generated Agent Plugin {component} external executable unexpectedly "
                    "resolved to a package asset"
                )
            continue
        if (
            executable.asset is None
            or executable.asset.path != executable.plugin_relative_path
            or executable.asset.path not in expected_output_files
        ):
            raise ValueError(
                f"Generated Agent Plugin {component} executable asset changed during "
                f"canonical reload: {executable.plugin_relative_path}"
            )


def _validate_apm_component_round_trip(
    plugin: AgentPlugin,
    *,
    expected_output_files: set[str],
    expected_lsp_names: set[str],
    expected_hooks_document: dict | None,
) -> None:
    """Compare generated extension facts with canonical loader-owned component IR."""
    extension = plugin.apm_extension
    if (
        extension is None
        or extension.schema_version != COM_MICROSOFT_APM_SCHEMA_VERSION
        or extension.provenance.path != plugin.manifest.path
        or extension.provenance.json_pointer != f"/extensions/{COM_MICROSOFT_APM_NAMESPACE}"
    ):
        raise ValueError("Generated Agent Plugin lost its exact com.microsoft.apm declaration")

    components = plugin.apm_components
    if components is None:
        raise ValueError("Generated Agent Plugin lost its declared com.microsoft.apm components")

    for name in _APM_FILE_COMPONENT_NAMES:
        prefix = f"{_NAMESPACE_PREFIX}{name}/"
        expected_assets = {
            output_file for output_file in expected_output_files if output_file.startswith(prefix)
        }
        component = getattr(components, name)
        loaded_assets = set() if component is None else _asset_paths(component.assets)
        if loaded_assets != expected_assets:
            raise ValueError(
                f"Generated Agent Plugin {name} assets changed during canonical reload: "
                f"expected {sorted(expected_assets)}, got {sorted(loaded_assets)}"
            )
        if component is not None and component.root != plugin.root / _NAMESPACE / name:
            raise ValueError(
                f"Generated Agent Plugin {name} path changed during canonical reload: "
                f"{component.root}"
            )

    expected_lsp_path = plugin.root / _NAMESPACE / "lsp.json"
    lsp = components.lsp
    if not expected_lsp_names:
        if lsp is not None:
            raise ValueError("Generated Agent Plugin unexpectedly activated an LSP component")
    elif lsp is None:
        raise ValueError("Generated Agent Plugin lost its com.microsoft.apm/lsp.json component")
    else:
        loaded_lsp_names = {server.name for server in lsp.servers}
        if loaded_lsp_names != expected_lsp_names or lsp.provenance.path != expected_lsp_path:
            raise ValueError(
                "Generated Agent Plugin LSP servers changed during canonical reload: "
                f"expected {sorted(expected_lsp_names)}, got {sorted(loaded_lsp_names)}"
            )
        if f"{_NAMESPACE_PREFIX}lsp.json" not in _asset_paths(lsp.assets):
            raise ValueError("Generated Agent Plugin LSP inventory lost its declaration asset")
        for server in lsp.servers:
            _validate_executable_facts(
                server.executables,
                declaration_path=expected_lsp_path,
                expected_output_files=expected_output_files,
                component=f"LSP server {server.name!r}",
            )

    expected_hooks_path = plugin.root / _NAMESPACE / "hooks" / "hooks.json"
    hooks = components.hooks
    if expected_hooks_document is None:
        if hooks is not None:
            raise ValueError("Generated Agent Plugin unexpectedly activated a hooks component")
    elif hooks is None:
        raise ValueError(
            "Generated Agent Plugin lost its com.microsoft.apm/hooks/hooks.json component"
        )
    else:
        if (
            hooks.provenance.path != expected_hooks_path
            or hooks.document.thaw() != expected_hooks_document
            or f"{_NAMESPACE_PREFIX}hooks/hooks.json" not in _asset_paths(hooks.assets)
        ):
            raise ValueError("Generated Agent Plugin hooks changed during canonical reload")
        _validate_executable_facts(
            hooks.executables,
            declaration_path=expected_hooks_path,
            expected_output_files=expected_output_files,
            component="hooks",
        )


def _validate_agent_plugin_round_trip(
    staged_bundle: Path,
    *,
    expected_name: str,
    expected_version: str,
    expected_output_files: set[str],
    expected_mcp_names: set[str],
    expected_lsp_names: set[str],
    expected_hooks_document: dict | None,
) -> None:
    """Reload staged output through the canonical Agent Plugin interpreter."""
    plugin = load_agent_plugin(staged_bundle)
    errors = [
        diagnostic.message
        for diagnostic in plugin.diagnostics
        if diagnostic.severity is DiagnosticSeverity.ERROR
    ]
    if errors:
        raise ValueError("Generated Agent Plugin failed canonical reload: " + "; ".join(errors))
    if plugin.identity.name != expected_name or plugin.identity.version != expected_version:
        raise ValueError(
            "Generated Agent Plugin identity changed during canonical reload: "
            f"expected {expected_name}@{expected_version}, got "
            f"{plugin.identity.name}@{plugin.identity.version or '<missing>'}"
        )
    expected_skills = _expected_skill_assets(expected_output_files)
    loaded_skills = {
        skill.directory_name: _asset_paths(skill.assets) for skill in plugin.components.skills
    }
    if loaded_skills != expected_skills:
        raise ValueError(
            "Generated Agent Plugin skills changed during canonical reload: "
            f"expected {sorted(expected_skills)}, got {sorted(loaded_skills)}"
        )
    loaded_mcp = {server.name for server in plugin.components.mcp_servers}
    if loaded_mcp != expected_mcp_names:
        raise ValueError(
            "Generated Agent Plugin MCP servers changed during canonical reload: "
            f"expected {sorted(expected_mcp_names)}, got {sorted(loaded_mcp)}"
        )
    for server in plugin.components.mcp_servers:
        _validate_executable_facts(
            server.executables,
            declaration_path=plugin.root / "mcp.json",
            expected_output_files=expected_output_files,
            component=f"MCP server {server.name!r}",
        )
    _validate_apm_component_round_trip(
        plugin,
        expected_output_files=expected_output_files,
        expected_lsp_names=expected_lsp_names,
        expected_hooks_document=expected_hooks_document,
    )


def export_agent_plugin_bundle(
    project_root: Path,
    output_dir: Path,
    target: str | None = None,
    archive: bool = False,
    archive_format: str = "zip",
    dry_run: bool = False,
    force: bool = False,
    logger=None,
) -> PackResult:
    """Export the project as an Agent Plugin bundle."""
    migrate_lockfile_if_needed(project_root)
    lockfile_path = get_lockfile_path(project_root)
    lockfile = LockFile.read(lockfile_path)
    if lockfile is None:
        raise FileNotFoundError(
            "apm.lock.yaml not found -- run 'apm install' first to resolve dependencies."
        )

    apm_yml_path = project_root / "apm.yml"
    package = APMPackage.from_apm_yml(apm_yml_path)
    pkg_name = package.name
    pkg_version = package.version or "0.0.0"

    for dep_ref in package.get_apm_dependencies():
        if dep_ref.is_local:
            raise ValueError(
                "Cannot pack -- apm.yml contains local path dependency: "
                f"{dep_ref.local_path}\n"
                "Local dependencies are for development only. Replace them with "
                "remote references (e.g., 'owner/repo') before packing."
            )

    plugin_json = {"$schema": PLUGIN_SCHEMA_ID}
    plugin_json.update(synthesize_plugin_json_from_apm_yml(apm_yml_path))
    plugin_json["extensions"] = {
        COM_MICROSOFT_APM_NAMESPACE: {"schemaVersion": COM_MICROSOFT_APM_SCHEMA_VERSION}
    }

    warnings: list[str] = []
    transition_warning = agent_plugin_warning()
    if transition_warning:
        warnings.append(transition_warning)

    dev_dep_urls = _get_dev_dependency_urls(apm_yml_path)
    file_map: dict[str, tuple[Path, str]] = {}
    collisions: list[str] = []
    merged_hooks: dict = {}
    mcp_document = _agent_mcp_document(package, lockfile)
    lsp_document = _agent_lsp_document(package, lockfile)
    apm_modules_dir = project_root / "apm_modules"

    if lockfile:
        for dep in lockfile.get_all_dependencies():
            if (
                getattr(dep, "is_dev", False)
                or (
                    dep.repo_url,
                    getattr(dep, "virtual_path", "") or "",
                )
                in dev_dep_urls
            ):
                continue

            dep_name = dep.repo_url
            install_path = _dep_install_path(dep, apm_modules_dir)
            if dep.deployed_files:
                dep_components = [
                    (src, _namespace_output_rel(rel))
                    for src, rel in _collect_deployed_components(project_root, dep)
                ]
                if dep.skill_subset and not dep_components:
                    declared_skills = ", ".join(dep.skill_subset)
                    raise ValueError(
                        f"Cannot pack dependency {dep.repo_url}: the skills recorded "
                        f"in apm.lock.yaml (skill_subset: {declared_skills}) were not "
                        "found among its installed files. Run 'apm install' to "
                        "re-deploy the expected skills, then pack again."
                    )
            elif _cache_would_contribute_primitives(install_path, dep):
                raise ValueError(
                    f"Cannot pack dependency {dep.repo_url}: the lockfile records no "
                    "deployed files for it, but installed content that cannot be "
                    "verified exists in the apm_modules cache (a stale or partial "
                    "install). Run 'apm install' to record provenance in apm.lock.yaml, "
                    "then pack again."
                )
            else:
                dep_components = []

            if _cache_would_contribute_hooks_or_mcp(install_path):
                _warn = (
                    f"dependency {dep.repo_url} contributed hooks/MCP config that is "
                    "not attested in apm.lock.yaml; it will NOT be packed. "
                    "Attested primitives (skills/agents/etc.) are unaffected."
                )
                if logger:
                    logger.warning(_warn)
                else:
                    _rich_warning(_warn, symbol="warning")

            _merge_file_map(file_map, dep_components, dep_name, force, collisions)

    own_apm_dir = project_root / ".apm"
    if isinstance(package.includes, list):
        own_components, root_hooks = _collect_explicit_local_components(
            project_root, package.includes
        )
        own_components = [(src, _namespace_output_rel(rel)) for src, rel in own_components]
    else:
        own_components = [
            (src, _namespace_output_rel(rel)) for src, rel in _collect_apm_components(own_apm_dir)
        ]
        root_hooks = _collect_hooks_from_apm(own_apm_dir)
        if own_apm_dir.is_dir():
            _warn_skipped_root_components(project_root, logger)
        else:
            own_components.extend(
                (src, _namespace_output_rel(rel))
                for src, rel in _collect_root_plugin_components(project_root)
            )
            root_hooks_top = _collect_hooks_from_root(project_root)
            _deep_merge(root_hooks, root_hooks_top, overwrite=False)

    if (
        not isinstance(package.includes, list)
        and own_apm_dir.is_dir()
        and not own_components
        and not root_hooks
    ):
        _warn_no_local_primitives(logger)

    _merge_file_map(file_map, own_components, pkg_name, force, collisions)
    _deep_merge(merged_hooks, root_hooks, overwrite=True)

    for msg in collisions:
        if logger:
            logger.warning(msg)
        else:
            _rich_warning(msg)

    output_files = sorted(file_map.keys())
    if merged_hooks:
        output_files.append(f"{_NAMESPACE_PREFIX}hooks/hooks.json")
    output_files.append("mcp.json")
    if lsp_document:
        output_files.append(f"{_NAMESPACE_PREFIX}lsp.json")
    output_files.append("plugin.json")
    output_files.extend(
        name
        for name in ("README.md", "LICENSE", "CHANGELOG.md", "CHANGELOG")
        if (project_root / name).is_file() and not (project_root / name).is_symlink()
    )
    output_files.append("apm.lock.yaml")
    output_files.sort()

    safe_name = _sanitize_bundle_name(pkg_name)
    safe_version = _sanitize_bundle_name(pkg_version)
    bundle_dir = output_dir / f"{safe_name}-{safe_version}"
    ensure_path_within(bundle_dir, output_dir)

    if dry_run:
        bundle_path = (
            projected_archive_path(output_dir, bundle_dir.name, archive_format)
            if archive
            else bundle_dir
        )
        return PackResult(bundle_path=bundle_path, files=output_files, warnings=warnings)

    if archive:
        validate_archive_format(archive_format)
    output_dir.mkdir(parents=True, exist_ok=True)
    _scan_bundle_sources(file_map, logger)
    with tempfile.TemporaryDirectory(prefix=".apm-agent-plugin-", dir=output_dir) as temp_dir:
        staging_root = Path(temp_dir)
        staged_bundle = staging_root / bundle_dir.name
        ensure_path_within(staged_bundle, staging_root)
        _write_bundle_sources(file_map, staged_bundle, staging_root)

        if merged_hooks:
            hooks_path = staged_bundle / _NAMESPACE_PREFIX / "hooks" / "hooks.json"
            hooks_path.parent.mkdir(parents=True, exist_ok=True)
            hooks_path.write_text(
                json.dumps(merged_hooks, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        mcp_path = staged_bundle / "mcp.json"
        mcp_path.parent.mkdir(parents=True, exist_ok=True)
        mcp_path.write_text(
            json.dumps(mcp_document, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        if lsp_document:
            lsp_path = staged_bundle / _NAMESPACE_PREFIX / "lsp.json"
            lsp_path.parent.mkdir(parents=True, exist_ok=True)
            lsp_path.write_text(
                json.dumps(lsp_document, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )

        (staged_bundle / "plugin.json").write_text(
            json.dumps(plugin_json, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        for doc_name in ("README.md", "LICENSE", "CHANGELOG.md", "CHANGELOG"):
            _copy_optional_root_file(project_root, staged_bundle, doc_name)

        bundle_files: dict[str, str] = {}
        for fp in staged_bundle.rglob("*"):
            if not fp.is_file() or fp.is_symlink():
                continue
            rel = fp.relative_to(staged_bundle).as_posix()
            if rel == "apm.lock.yaml":
                continue
            bundle_files[rel] = hashlib.sha256(fp.read_bytes()).hexdigest()

        enriched_yaml = enrich_lockfile_for_pack(
            lockfile,
            BundleFormat.AGENT_PLUGIN.lock_value,
            target or "all",
            bundle_files=bundle_files,
            packed_at=lockfile.generated_at,
        )
        (staged_bundle / "apm.lock.yaml").write_text(enriched_yaml, encoding="utf-8")

        _validate_agent_plugin_round_trip(
            staged_bundle,
            expected_name=pkg_name,
            expected_version=pkg_version,
            expected_output_files=set(output_files),
            expected_mcp_names=set(mcp_document["mcpServers"]),
            expected_lsp_names=(
                set(lsp_document["lspServers"]) if lsp_document is not None else set()
            ),
            expected_hooks_document=merged_hooks or None,
        )

        if archive:
            archive_path = projected_archive_path(output_dir, bundle_dir.name, archive_format)
            staged_archive = staging_root / archive_path.name
            write_reproducible_archive(staged_bundle, staged_archive, archive_format)
            os.replace(staged_archive, archive_path)
            committed_path = archive_path
        else:
            if bundle_dir.exists():
                safe_rmtree(bundle_dir, output_dir)
            os.replace(staged_bundle, bundle_dir)
            committed_path = bundle_dir

    return PackResult(bundle_path=committed_path, files=output_files, warnings=warnings)
