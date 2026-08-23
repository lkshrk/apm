"""Exact target-native instruction artifacts discovered for adoption."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from apm_cli.integration.targets import KNOWN_TARGETS

from .discovery import NativeResource, user_scope_mappings


@dataclass(frozen=True)
class CompiledInstruction:
    """One immutable deployed instruction, scoped to its source target."""

    target: str
    name: str
    format_id: str
    source: Path
    relative_path: Path
    content: bytes


def adopt_compiled_instruction(resource: NativeResource) -> CompiledInstruction:
    """Read a compiled resource exactly, without treating it as canonical source."""
    if resource.kind != "instruction" or resource.strategy != "compiled":
        raise ValueError("resource is not a compiled instruction")
    if len(resource.targets) != 1:
        raise ValueError("compiled instructions must have exactly one source target")
    target = resource.targets[0]
    profile = KNOWN_TARGETS[target].for_scope(user_scope=True)
    if profile is None:
        raise ValueError(f"{target} has no user-scope profile")
    mapping = user_scope_mappings(profile).get("instructions")
    if mapping is None or mapping.import_strategy != "compiled":
        raise ValueError(f"{target} has no compiled instruction mapping")
    source = resource.path.resolve(strict=True)
    root = resource.root.resolve(strict=True)
    if resource.path.is_symlink() or not source.is_file() or not source.is_relative_to(root):
        raise ValueError("compiled instruction must be a contained regular file")
    return CompiledInstruction(
        target=target,
        name=resource.name,
        format_id=mapping.format_id,
        source=source,
        relative_path=source.relative_to(root),
        content=source.read_bytes(),
    )
