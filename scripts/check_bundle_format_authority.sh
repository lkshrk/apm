#!/usr/bin/env bash
set -euo pipefail

repo_root="${1:-.}"
duplicates=$(
    grep -rEn --include='*.py' \
        '^(class BundleFormat|def resolve_bundle_format|def agent_plugin_warning)' \
        "$repo_root/src/apm_cli/bundle" \
        | grep -v '/src/apm_cli/bundle/formats.py:' \
        || true
)
if [ -n "$duplicates" ]; then
    echo "[x] Bundle format authority must live in src/apm_cli/bundle/formats.py"
    echo "$duplicates"
    exit 1
fi

format_owner="$repo_root/src/apm_cli/bundle/formats.py"
if ! grep -q '^PREFERRED_PLUGIN_FORMAT = BundleFormat.CLAUDE_PLUGIN$' "$format_owner"; then
    echo "[x] Agent Plugin preferred-default flip is reserved for T10 after G3"
    exit 1
fi
if ! grep -q '^    if len(selections) > 1:$' "$format_owner" \
    || ! grep -q '^    return PREFERRED_PLUGIN_FORMAT$' "$format_owner"; then
    echo "[x] Bundle selectors and no-flag behavior must route through the canonical format seam"
    exit 1
fi

agent_plugin_exporter="$repo_root/src/apm_cli/bundle/agent_plugin_exporter.py"
if [ -f "$agent_plugin_exporter" ]; then
    loader_line=$(grep -n 'plugin = load_agent_plugin(staged_bundle)' "$agent_plugin_exporter" \
        | head -1 | cut -d: -f1 || true)
    archive_line=$(grep -n 'write_reproducible_archive(staged_bundle' "$agent_plugin_exporter" \
        | head -1 | cut -d: -f1 || true)
    commit_line=$(grep -n 'os.replace(staged_bundle, bundle_dir)' "$agent_plugin_exporter" \
        | head -1 | cut -d: -f1 || true)
    if [ -z "$loader_line" ] \
        || [ -z "$archive_line" ] \
        || [ -z "$commit_line" ] \
        || [ "$loader_line" -ge "$archive_line" ] \
        || [ "$loader_line" -ge "$commit_line" ] \
        || ! grep -q '^    if errors:$' "$agent_plugin_exporter" \
        || ! grep -q '^    if loaded_skills != expected_skill_directories:$' \
            "$agent_plugin_exporter" \
        || ! grep -q '^    if loaded_mcp != expected_mcp_names:$' \
            "$agent_plugin_exporter" \
        || grep -Eq 'validate_(plugin_manifest|mcp_config|lsp_extension)_(document|file)' \
            "$agent_plugin_exporter"; then
        echo "[x] Agent Plugin production must canonically reload staged output before commit"
        exit 1
    fi
fi

init_owner="$repo_root/src/apm_cli/commands/init.py"
if [ -f "$init_owner" ] \
    && { ! grep -q 'PREFERRED_PLUGIN_FORMAT is BundleFormat.AGENT_PLUGIN' "$init_owner" \
        || ! grep -q 'plugin = load_agent_plugin(staged_root)' "$init_owner"; }; then
    echo "[x] Plugin scaffolding must share the preferred-format seam and canonical reload"
    exit 1
fi

client_projection="$repo_root/src/apm_cli/adapters/client/agent_plugin_projection.py"
if [ -f "$client_projection" ] \
    && { ! grep -q 'config = adapter.render_server_config(_server_info(server))' \
            "$client_projection" \
        || ! grep -q 'len(rendered) + len(diagnostics) != len(plugin.components.mcp_servers)' \
            "$client_projection" \
        || [ "$(grep -c 'diagnostics.append(' "$client_projection")" -lt 3 ]; }; then
    echo "[x] Agent Plugin client projection must type every unsupported component"
    exit 1
fi

agent_plugin_owner="$repo_root/src/apm_cli/agent_plugins/loader.py"
if [ -f "$agent_plugin_owner" ]; then
    agent_plugin_duplicates=$(
        grep -rEn --include='*.py' \
            '^(class AgentPlugin:|def (detect|load)_agent_plugin\()' \
            "$repo_root/src/apm_cli" \
            | grep -v '/src/apm_cli/agent_plugins/loader.py:.*def \(detect\|load\)_agent_plugin(' \
            | grep -v '/src/apm_cli/agent_plugins/ir.py:.*class AgentPlugin:' \
            || true
    )
    if [ -n "$agent_plugin_duplicates" ]; then
        echo "[x] Agent Plugin interpretation must live in src/apm_cli/agent_plugins/loader.py"
        echo "$agent_plugin_duplicates"
        exit 1
    fi
    if ! grep -q '^def detect_agent_plugin(' "$agent_plugin_owner" \
        || ! grep -q '^def load_agent_plugin(' "$agent_plugin_owner" \
        || ! grep -q '^def _read_admissible_root_manifest(' "$agent_plugin_owner" \
        || ! grep -q 'read_json_document(manifest_path, reject_duplicate_schema=True)' "$agent_plugin_owner" \
        || ! grep -q '^def _load_apm_configuration(' "$agent_plugin_owner"; then
        echo "[x] Agent Plugin loader must own admissibility, detection, loading, and manifest authority"
        exit 1
    fi

    model_validation="$repo_root/src/apm_cli/models/validation.py"
    format_detection="$repo_root/src/apm_cli/models/format_detection.py"
    legacy_parser="$repo_root/src/apm_cli/deps/plugin_parser.py"
    package_owner="$repo_root/src/apm_cli/models/apm_package.py"
    projection_owner="$repo_root/src/apm_cli/agent_plugins/projection.py"
    agent_validation_body=$(
        awk '
            /^def _validate_agent_plugin\(/ { capture = 1 }
            capture && /^def / && !/^def _validate_agent_plugin\(/ { exit }
            capture { print }
        ' "$model_validation"
    )
    if printf '%s\n' "$agent_validation_body" \
        | grep -Eq 'normalize_plugin_directory|synthesize_apm_yml_from_plugin' \
        || ! grep -q 'detect_agent_plugin(package_path)' "$format_detection" \
        || ! grep -q 'admit_legacy_plugin_manifest(package_path)' "$format_detection" \
        || ! grep -q 'admit_legacy_plugin_manifest(plugin_path)' "$legacy_parser"; then
        echo "[x] Agent Plugin classification must route through its loader, not Claude normalization"
        exit 1
    fi

    projection_duplicates=$(
        grep -rEn --include='*.py' \
            '^def project_agent_plugin_package\(' \
            "$repo_root/src/apm_cli" \
            | grep -v '/src/apm_cli/agent_plugins/projection.py:' \
            || true
    )
    normalization_callers=$(
        grep -rEn --include='*.py' \
            'normalize_plugin_directory\(' \
            "$repo_root/src/apm_cli" \
            | grep -v '/src/apm_cli/deps/plugin_parser.py:.*def normalize_plugin_directory(' \
            | grep -v '/src/apm_cli/models/validation.py:' \
            || true
    )
    raw_agent_package_construction=$(
        grep -rEn --include='*.py' \
            'APMPackage\(' \
            "$repo_root/src/apm_cli/agent_plugins" \
            || true
    )
    if [ ! -f "$projection_owner" ] \
        || [ "$(grep -Ec '^def project_agent_plugin_package\(' "$projection_owner")" -ne 1 ] \
        || [ -n "$projection_duplicates" ] \
        || [ "$(grep -Ec '^    def from_mapping\(' "$package_owner")" -ne 1 ] \
        || ! printf '%s\n' "$agent_validation_body" \
            | grep -q 'package = project_agent_plugin_package(plugin)' \
        || ! printf '%s\n' "$agent_validation_body" | grep -q 'result.package = package' \
        || grep -Eq 'read_json_document|json\.load|yaml\.' "$projection_owner" \
        || [ -n "$raw_agent_package_construction" ] \
        || [ -n "$normalization_callers" ]; then
        echo "[x] Agent Plugin compatibility packages must route through the projection owner"
        [ -n "$projection_duplicates" ] && echo "$projection_duplicates"
        [ -n "$raw_agent_package_construction" ] && echo "$raw_agent_package_construction"
        [ -n "$normalization_callers" ] && echo "$normalization_callers"
        exit 1
    fi
    if ! python3 "$(dirname "$0")/check_agent_plugin_projection_boundary.py" \
        --root "$repo_root"; then
        echo "[x] Agent Plugin projection AST boundary failed"
        exit 1
    fi
fi
