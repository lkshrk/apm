"""Native omp MCP configuration, with runtime-only declared header helpers."""

from __future__ import annotations

import os
import re
import shlex
from pathlib import Path

from ...models.dependency.mcp import HEADER_HELPER_KEY, ManifestHeaderHelper
from ...utils.console import _rich_error
from .cursor import CursorClientAdapter

_ENV_REFERENCE_RE = re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*\}")
_ENV_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


class OmpClientAdapter(CursorClientAdapter):
    """Read/write omp's plain JSON envelope without owning local controls."""

    target_name = "omp"
    supports_user_scope = True
    mcp_servers_key = "mcpServers"
    _supports_runtime_env_substitution = True
    _LOCAL_FIELDS = frozenset({"enabled", "instructions"})

    @staticmethod
    def config_path_for(project_root: Path, user_scope: bool) -> Path:
        if not user_scope:
            return Path(project_root) / ".omp" / "mcp.json"
        # Match omp's default profile: relative values are cwd-relative, and
        # a literal ~ is a directory name, not shell expansion. Do not resolve
        # symlinks here: the shared safe writer must still be able to see them.
        agent_dir = os.environ.get("PI_CODING_AGENT_DIR")
        root = Path(os.path.abspath(agent_dir)) if agent_dir else Path.home() / ".omp" / "agent"
        return root / "mcp.json"

    def get_config_path(self):
        return str(self.config_path_for(self.project_root, self.user_scope))

    def validate_config_for_install(self) -> bool:
        return self._read_json_config_for_update(Path(self.get_config_path())) is not None

    def _format_runtime_env_placeholder(self, name: str) -> str:
        return "${" + name + "}"

    @staticmethod
    def _merge_extra(config: dict, server_info: dict) -> dict:
        # Claude/Codex helper syntax is not understood by omp. Only the typed
        # manifest intent below is allowed to introduce shell-evaluated values.
        info = dict(server_info)
        info["_extra"] = {
            key: value
            for key, value in (server_info.get("_extra") or {}).items()
            if key not in {"headersHelper", "http_headers_helper", "headersHelperKeys"}
        }
        return CursorClientAdapter._merge_extra(config, info)

    def _format_server_config(self, server_info, env_overrides=None, runtime_vars=None):
        config = super()._format_server_config(server_info, env_overrides, runtime_vars)
        if config.get("url"):
            config["url"] = self._translate_env_placeholder_for_runtime(config["url"])
        remotes = server_info.get("remotes") or []
        if remotes and config.get("url"):
            remote = self._select_remote_with_url(remotes) or remotes[0]
            if (remote.get("transport_type") or "").strip() == "sse":
                config["type"] = "sse"
        # A leading ! has execution semantics in omp, unlike the other clients.
        # Never reinterpret an ordinary manifest/registry literal as a command.
        for field in ("env", "headers"):
            for value in config.get(field, {}).values():
                if not isinstance(value, str):
                    continue
                # omp expands placeholders before interpreting !commands and
                # bare environment names. Defaults or concatenated references
                # must not turn an innocent-looking value into executable text.
                literal = _ENV_REFERENCE_RE.sub("", value)
                if literal.startswith("!"):
                    raise ValueError(
                        f"omp {field} values beginning with ! require a declared header helper; "
                        "literal command expressions are not accepted"
                    )
                if "${" in literal:
                    raise ValueError(f"omp {field} supports only exact ${{NAME}} references")
                if _ENV_NAME_RE.fullmatch(literal):
                    raise ValueError(
                        f"omp {field} bare identifiers are ambiguous environment lookups; "
                        "use an explicit ${NAME} reference"
                    )
        extra = server_info.get("_extra") or {}
        helper = server_info.get(HEADER_HELPER_KEY)
        if isinstance(helper, ManifestHeaderHelper):
            if not config.get("url"):
                raise ValueError("omp header helpers require an HTTP MCP connection")
            headers = config.setdefault("headers", {})
            for key in helper.keys:
                # Preserve the authored shell command (including ~ expansion),
                # but shell-quote header names and never interpolate them into jq.
                headers[key] = f"!{helper.command} | jq -er --arg key {shlex.quote(key)} '.[$key]'"
        elif extra.get("headersHelper") or extra.get("http_headers_helper"):
            raise ValueError("omp header helpers require manifest-declared headersHelperKeys")
        if config.get("args") == []:
            config.pop("args")
        return config

    def managed_server_config(
        self, native: dict, *, declared_fields: set[str] | None = None
    ) -> dict:
        """Exclude auth/OAuth metadata only when not APM-declared."""
        return {
            key: value
            for key, value in native.items()
            if key not in self._LOCAL_FIELDS
            and not (
                key in {"auth", "oauth"}
                and declared_fields is not None
                and key not in declared_fields
            )
        }

    def matches_managed_server_config(self, native: object, expected: dict) -> bool:
        return (
            isinstance(native, dict)
            and self.managed_server_config(native, declared_fields=set(expected)) == expected
        )

    def update_config(self, config_updates, enabled=True, *, managed_fields=None):
        path = Path(self.get_config_path())
        document = self._read_json_config_for_update(path)
        if document is None:
            return False
        servers = document.setdefault(self.mcp_servers_key, {})
        for name, config in config_updates.items():
            previous = servers.get(name)
            local = (
                {
                    key: value
                    for key, value in previous.items()
                    if key in self._LOCAL_FIELDS
                    or (
                        key in {"auth", "oauth"}
                        and key not in config
                        and key not in (managed_fields or set())
                    )
                }
                if isinstance(previous, dict)
                else {}
            )
            servers[name] = {**config, **local}
        self._write_json_config(path, document)
        return True

    def configure_mcp_server(
        self,
        server_url,
        server_name=None,
        enabled=True,
        env_overrides=None,
        server_info_cache=None,
        runtime_vars=None,
        managed_fields=None,
    ):
        if not server_url:
            return False
        try:
            info = self._fetch_server_info(server_url, server_info_cache)
            if info is None:
                return False
            config = self.render_server_config(
                info, env_overrides=env_overrides, runtime_vars=runtime_vars
            )
            key = self._determine_config_key(server_url, server_name)
            if not self.update_config({key: config}, managed_fields=managed_fields):
                return False
            from ...install.mcp.ownership import mcp_native_hash

            self.written_mcp_hashes[server_url] = mcp_native_hash(
                self.managed_server_config(config, declared_fields=set(config))
            )
            return True
        except (OSError, TypeError, ValueError):
            # Do not print registry/header payloads or exception strings.
            _rich_error("Could not safely configure MCP server for omp")
            return False
