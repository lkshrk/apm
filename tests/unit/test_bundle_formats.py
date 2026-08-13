"""Unit tests for canonical bundle format selection."""

from __future__ import annotations

import pytest

from apm_cli.bundle.formats import (
    BundleFormat,
    agent_plugin_warning,
    coerce_bundle_format,
    resolve_bundle_format,
)


class TestBundleFormatSelection:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            (None, BundleFormat.AGENT_PLUGIN),
            ("plugin", BundleFormat.AGENT_PLUGIN),
            ("agent-plugin", BundleFormat.AGENT_PLUGIN),
            ("claude", BundleFormat.CLAUDE_PLUGIN),
            ("claude-plugin", BundleFormat.CLAUDE_PLUGIN),
            ("apm", BundleFormat.APM),
        ],
    )
    def test_coerce_bundle_format(self, value, expected):
        assert coerce_bundle_format(value) is expected

    def test_default_bundle_format_is_agent_plugin(self):
        assert resolve_bundle_format(None) is BundleFormat.AGENT_PLUGIN

    def test_conflicting_selectors_raise(self):
        with pytest.raises(ValueError, match="mutually exclusive"):
            resolve_bundle_format("apm", plugin=True)

    def test_matching_selectors_are_accepted(self):
        assert resolve_bundle_format("plugin", plugin=True) is BundleFormat.AGENT_PLUGIN
        assert (
            resolve_bundle_format("claude-plugin", claude_plugin=True) is BundleFormat.CLAUDE_PLUGIN
        )


class TestAgentPluginWarningWindow:
    @pytest.mark.parametrize(
        ("version", "expected"),
        [
            ("0.28.9", None),
            ("0.29.0", "apm pack now defaults to Agent Plugin output"),
            ("0.33.99", "apm pack now defaults to Agent Plugin output"),
            ("0.34.0", None),
        ],
    )
    def test_warning_window(self, version, expected):
        warning = agent_plugin_warning(version)
        if expected is None:
            assert warning is None
        else:
            assert warning is not None
            assert expected in warning
