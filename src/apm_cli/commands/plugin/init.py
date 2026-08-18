"""``apm plugin init`` -- scaffold an Agent Plugin (plugin.json + apm.yml).

Thin wrapper that delegates to the shared ``_perform_init`` helper
in ``apm_cli.commands.init`` with ``plugin=True``. This guarantees
byte-for-byte output parity with the deprecated ``apm init --plugin``
flag while letting users discover the plugin-author noun namespace.
"""

from __future__ import annotations

import click

from ...core.target_detection import TargetParamType
from ..init import _perform_init


@click.command(help="Scaffold a plugin project (creates plugin.json + apm.yml)")
@click.argument("project_name", required=False)
@click.option(
    "--yes", "-y", is_flag=True, help="Skip interactive prompts and use auto-detected defaults"
)
@click.option(
    "--target",
    "target_flag",
    type=TargetParamType(),
    default=None,
    help="Comma-separated target list (skip prompt, write directly)",
)
@click.option(
    "--plugin", "plugin_flag", is_flag=True, help="Explicitly scaffold native Agent Plugins v1"
)
@click.option(
    "--claude-plugin",
    "claude_plugin",
    is_flag=True,
    help="Scaffold the legacy Claude-compatible layout (current no-flag default)",
)
@click.option("--verbose", "-v", is_flag=True, help="Show detailed output")
def init(project_name, yes, target_flag, plugin_flag, claude_plugin, verbose):
    """Initialize a plugin project (like ``cargo new --lib``).

    Equivalent to the deprecated ``apm init --plugin`` flag. Use
    ``apm marketplace init`` to publish a marketplace.
    """
    # Mutually exclusive selector enforcement: raise Click usage error (exit code 2)
    if plugin_flag and claude_plugin:
        raise click.UsageError("Options --plugin and --claude-plugin are mutually exclusive")

    plugin_mode = "agent" if plugin_flag else "claude" if claude_plugin else None

    _perform_init(
        project_name=project_name,
        yes=yes,
        plugin=True,
        marketplace_flag=False,
        target_flag=target_flag,
        verbose=verbose,
        source="plugin",
        plugin_mode=plugin_mode,
    )
