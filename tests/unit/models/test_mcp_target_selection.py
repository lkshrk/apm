"""Per-server runtime intent and declared header metadata round trips."""

import pytest

from apm_cli.integration.mcp_integrator import MCPIntegrator
from apm_cli.models.dependency.mcp import HEADER_HELPER_KEY, ManifestHeaderHelper, MCPDependency


def test_absent_targets_retain_all_active_runtime_behavior():
    dep = MCPDependency.from_dict({"name": "example"})
    assert dep.targets is None
    assert all(dep.targets_runtime(runtime) for runtime in ("claude", "codex", "omp"))
    assert "targets" not in dep.to_dict()


def test_explicit_targets_canonicalize_deduplicate_and_round_trip():
    dep = MCPDependency.from_dict(
        {"name": "example", "targets": ["vscode", "omp", "copilot", "omp"]}
    )
    assert dep.targets == ["copilot", "omp"]
    assert dep.targets_runtime("vscode")
    assert dep.targets_runtime("omp")
    assert not dep.targets_runtime("claude")
    assert MCPDependency.from_dict(dep.to_dict()).targets == dep.targets
    assert dep.extra is None


def test_empty_targets_select_no_runtime_and_remain_explicit():
    dep = MCPDependency.from_dict({"name": "example", "targets": []})
    assert not dep.targets_runtime("omp")
    assert dep.to_dict()["targets"] == []
    assert MCPDependency.from_dict(dep.to_dict()).targets == []


@pytest.mark.parametrize(
    "targets", [None, "omp", {}, [None], [1], ["all"], ["unknown"], ["agent-skills"], ["openclaw"]]
)
def test_invalid_or_non_mcp_targets_are_rejected(targets):
    with pytest.raises(ValueError, match="targets"):
        MCPDependency.from_dict({"name": "example", "targets": targets})


def test_target_selection_changes_are_persisted_config_drift():
    before = MCPDependency.from_dict({"name": "example", "targets": ["claude", "codex"]})
    after = MCPDependency.from_dict({"name": "example", "targets": ["omp"]})
    assert MCPIntegrator.get_server_configs([after])["example"]["targets"] == ["omp"]
    assert MCPIntegrator._detect_mcp_config_drift([after], {"example": before.to_dict()}) == {
        "example"
    }
    assert not MCPIntegrator._detect_mcp_config_drift([after], {"example": after.to_dict()})


@pytest.mark.parametrize(
    "keys", [None, [], "X-Key", [None], [1], [""], ["X Key"], ["X\nKey"], ["X-Key", "x-key"]]
)
def test_helper_key_metadata_is_validated(keys):
    with pytest.raises(ValueError, match="headersHelperKeys"):
        MCPDependency.from_dict(
            {"name": "example", "extra": {"headersHelper": "helper", "headersHelperKeys": keys}}
        )


@pytest.mark.parametrize("command", [None, "", " ", 1, ["helper"], "helper\x00"])
def test_helper_keys_require_a_shell_command_declaration(command):
    with pytest.raises(ValueError, match="helper command"):
        MCPDependency.from_dict(
            {"name": "example", "extra": {"headersHelper": command, "headersHelperKeys": ["X-Key"]}}
        )


def test_header_helper_intent_is_typed_and_not_forgeable_by_json():
    dep = MCPDependency.from_dict(
        {"name": "example", "extra": {"headersHelper": "helper", "headersHelperKeys": ["X-Key"]}}
    )
    restored = MCPDependency.from_dict(dep.to_dict())
    info = {HEADER_HELPER_KEY: {"command": "untrusted", "keys": ["X-Forged"]}}
    restored.apply_header_helper(info)
    assert info[HEADER_HELPER_KEY] == ManifestHeaderHelper("helper", ("X-Key",))
    MCPDependency.from_dict({"name": "example"}).apply_header_helper(info)
    assert HEADER_HELPER_KEY not in info


@pytest.mark.parametrize("helper_key", ["headersHelper", "http_headers_helper"])
@pytest.mark.parametrize("registry", [None, "https://registry.example.com"])
def test_direct_registry_declaration_can_create_header_helper(helper_key, registry):
    dep = MCPDependency.from_dict(
        {
            "name": "example",
            "registry": registry,
            "extra": {helper_key: "helper", "headersHelperKeys": ["X-Key"]},
        }
    )
    info = {HEADER_HELPER_KEY: {"command": "forged", "keys": ["X-Forged"]}}

    dep.apply_header_helper(info)

    assert dep.resolved_by is None
    assert info[HEADER_HELPER_KEY] == ManifestHeaderHelper("helper", ("X-Key",))


@pytest.mark.parametrize("helper_key", ["headersHelper", "http_headers_helper"])
@pytest.mark.parametrize("registry", [None, "https://registry.example.com"])
@pytest.mark.parametrize("resolved_by", ["dependency-package", ""])
@pytest.mark.parametrize(
    "forged",
    [
        {"command": "forged", "keys": ["X-Forged"]},
        ManifestHeaderHelper("forged", ("X-Forged",)),
    ],
)
def test_transitive_registry_declaration_cannot_create_header_helper(
    helper_key,
    registry,
    resolved_by,
    forged,
):
    dep = MCPDependency.from_dict(
        {
            "name": "example",
            "registry": registry,
            "extra": {helper_key: "helper", "headersHelperKeys": ["X-Key"]},
        }
    )
    dep.resolved_by = resolved_by
    info = {HEADER_HELPER_KEY: forged, "name": "example"}

    dep.apply_header_helper(info)

    assert info == {"name": "example"}


@pytest.mark.parametrize("helper_key", ["headersHelper", "http_headers_helper"])
def test_transitive_self_defined_header_helper_survives_existing_trust_gate(tmp_path, helper_key):
    from apm_cli.integration.mcp_config_view import _collect_unlocked_compat

    (tmp_path / "apm.yml").write_text(
        "name: dependency-package\n"
        "version: 1.0.0\n"
        "dependencies:\n"
        "  mcp:\n"
        "    - name: example\n"
        "      registry: false\n"
        "      transport: http\n"
        "      url: https://example.com/mcp\n"
        "      extra:\n"
        f"        {helper_key}: helper\n"
        "        headersHelperKeys: [X-Key]\n",
        encoding="utf-8",
    )
    assert (
        _collect_unlocked_compat(
            tmp_path,
            trust_transitive_self_defined=False,
            diagnostics=None,
            logger=None,
        )
        == []
    )
    admitted = _collect_unlocked_compat(
        tmp_path,
        trust_transitive_self_defined=True,
        diagnostics=None,
        logger=None,
    )
    assert len(admitted) == 1
    assert admitted[0].resolved_by == "dependency-package"
    info = {HEADER_HELPER_KEY: {"command": "forged", "keys": ["X-Forged"]}}

    admitted[0].apply_header_helper(info)

    assert info[HEADER_HELPER_KEY] == ManifestHeaderHelper("helper", ("X-Key",))
