"""Shared helpers for APM package download and validation."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..models.apm_package import APMPackage
    from ..models.dependency.reference import DependencyReference
    from ..models.validation import ValidationResult


def materialize_marketplace_manifest(dep_ref: DependencyReference, target_path: Path) -> bool:
    """Synthesize a package when deployable components exist only in the catalog."""
    manifest = getattr(dep_ref, "marketplace_manifest", None)
    declared = tuple(
        key
        for key in ("lspServers", "mcpServers")
        if isinstance(manifest, dict) and manifest.get(key)
    )
    if (target_path / "apm.yml").exists() or not declared:
        return False
    from apm_cli.deps.plugin_parser import synthesize_apm_yml_from_plugin
    from apm_cli.models.apm_package import APMPackage
    from apm_cli.utils.file_ops import robust_rmtree

    try:
        apm_yml = synthesize_apm_yml_from_plugin(target_path, dict(manifest))
        package = APMPackage.from_apm_yml(apm_yml)
        if "lspServers" in declared and not package.get_lsp_dependencies():
            raise ValueError(
                f"Marketplace LSP metadata for {dep_ref.repo_url} at {target_path} "
                "did not materialize a valid dependency"
            )
        if "mcpServers" in declared and not package.get_mcp_dependencies():
            raise ValueError(
                f"Marketplace MCP metadata for {dep_ref.repo_url} at {target_path} "
                "did not materialize a valid dependency"
            )
    except Exception:
        if target_path.exists():
            robust_rmtree(target_path, ignore_errors=True)
        raise
    return True


def _validate_and_load_package(
    validation_result: ValidationResult,
    target_path: Path,
    dep_ref: DependencyReference,
) -> APMPackage:
    """Check *validation_result*, clean up *target_path* on failure, and return the package.

    Args:
        validation_result: Result from ``validate_apm_package(target_path)``.
        target_path: Destination directory; removed on validation failure.
        dep_ref: Dependency reference (for error messages and ``source`` assignment).

    Returns:
        The :class:`~apm_cli.models.apm_package.APMPackage` from the validation
        result (with ``source`` already set to ``dep_ref.to_github_url()``).

    Raises:
        RuntimeError: If the package is invalid or metadata is missing.
        AgentPluginError: If *target_path* is a rejected Agent Plugin
            (unsupported or foreign schema); *target_path* is cleaned up
            before this propagates.
    """
    from ..agent_plugins.errors import AgentPluginError
    from ..bundle.local_bundle import route_agent_plugin_package
    from ..models.validation import validate_apm_package
    from ..utils.file_ops import robust_rmtree

    if materialize_marketplace_manifest(dep_ref, target_path):
        validation_result = validate_apm_package(target_path)

    if target_path.is_dir():
        try:
            route_agent_plugin_package(target_path)
        except AgentPluginError:
            if target_path.exists():
                robust_rmtree(target_path, ignore_errors=True)
            raise
    if not validation_result.is_valid:
        if target_path.exists():
            robust_rmtree(target_path, ignore_errors=True)
        error_msg = f"Invalid APM package {dep_ref.repo_url}:\n"
        for error in validation_result.errors:
            error_msg += f"  - {error}\n"
        raise RuntimeError(error_msg.strip())

    if not validation_result.package:
        if target_path.exists():
            robust_rmtree(target_path, ignore_errors=True)
        raise RuntimeError(
            f"Package validation succeeded but no package metadata found for {dep_ref.repo_url}"
        )

    package = validation_result.package
    package.source = dep_ref.to_github_url()
    return package
