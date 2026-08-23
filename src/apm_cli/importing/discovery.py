"""Registry-driven native filesystem discovery."""

from __future__ import annotations

import os
import stat
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, replace
from pathlib import Path

from apm_cli.integration.targets import KNOWN_TARGETS, PrimitiveMapping, TargetProfile

_KINDS = {
    "instructions": "instruction",
    "agents": "agent",
    "commands": "command",
    "prompts": "command",
    "skills": "skill",
    "hooks": "hook",
}


@dataclass(frozen=True)
class NativeResource:
    """One physical native resource and every target that owns that path."""

    root: Path
    path: Path
    kind: str
    name: str
    targets: tuple[str, ...]
    strategy: str
    blocked_reason: str | None = None


PresenceHook = Callable[[str, TargetProfile, Path], bool]
CustomHook = Callable[[str, TargetProfile, Path], Iterable[NativeResource]]


def user_scope_mappings(profile: TargetProfile) -> dict[str, PrimitiveMapping]:
    """Return user mappings without resolving optional machine-local roots."""
    mappings = {
        kind: mapping
        for kind, mapping in profile.primitives.items()
        if kind not in profile.unsupported_user_primitives
    }
    if profile.user_primitive_overrides:
        mappings.update(profile.user_primitive_overrides)
    return mappings


def validate_import_strategies(
    profiles: Mapping[str, TargetProfile] = KNOWN_TARGETS,
) -> None:
    """Fail when a user-deployable primitive lacks reverse-import metadata."""
    missing = [
        f"{target}:{kind}"
        for target, profile in sorted(profiles.items())
        if profile.user_supported
        for kind, mapping in sorted(user_scope_mappings(profile).items())
        if mapping.import_strategy is None
    ]
    if missing:
        raise ValueError(f"missing import strategy: {', '.join(missing)}")


def target_root(profile: TargetProfile, *, home: Path) -> Path:
    """Resolve a user-scope profile root without inventing target paths."""
    if profile.resolved_deploy_root is not None:
        return Path(os.path.abspath(profile.resolved_deploy_root.expanduser()))
    root = Path(profile.root_dir).expanduser()
    return Path(os.path.abspath(root if root.is_absolute() else home / root))


def mapping_root(profile: TargetProfile, mapping: PrimitiveMapping, *, home: Path) -> Path:
    """Resolve a primitive root from its scope-resolved deployment metadata."""
    if mapping.deploy_root is None:
        return target_root(profile, home=home)
    root = Path(mapping.deploy_root).expanduser()
    return Path(os.path.abspath(root if root.is_absolute() else home / root))


def path_boundary_error(root: Path, path: Path) -> str | None:
    """Reject lexical escapes and symlink/reparse components without opening content."""
    root = Path(os.path.abspath(root.expanduser()))
    path = Path(os.path.abspath(path.expanduser()))
    if not path.is_relative_to(root):
        return "source-outside-root"
    components = [root]
    current = root
    for part in path.relative_to(root).parts:
        current /= part
        components.append(current)
    for current in components:
        try:
            info = current.lstat()
        except FileNotFoundError:
            continue
        except OSError:
            return "unreadable-source-path"
        reparse = bool(getattr(info, "st_file_attributes", 0) & 0x400)
        if stat.S_ISLNK(info.st_mode) or reparse:
            return "unsafe-source-path"
    try:
        if path.exists() and not path.resolve(strict=True).is_relative_to(
            root.resolve(strict=True)
        ):
            return "source-outside-root"
    except OSError:
        return "unreadable-source-path"
    return None


def _mapping_resources(
    target: str,
    profile: TargetProfile,
    kind: str,
    mapping: PrimitiveMapping,
    *,
    home: Path,
) -> Iterable[NativeResource]:
    strategy = mapping.import_strategy
    canonical_kind = _KINDS.get(kind)
    if strategy is None or strategy == "custom" or canonical_kind is None:
        return
    root = mapping_root(profile, mapping, home=home)
    base = root / mapping.subdir
    if error := path_boundary_error(root, base):
        yield NativeResource(
            root, base, "unsupported", f"{target}-{kind}", (target,), strategy, error
        )
        return
    if not base.is_dir():
        return
    if mapping.extension.startswith("/"):
        marker = mapping.extension[1:]
        sources = []
        try:
            children = sorted(base.iterdir())
        except OSError:
            yield NativeResource(
                root,
                base,
                "unsupported",
                f"{target}-{kind}",
                (target,),
                strategy,
                "unreadable-source-path",
            )
            return
        for child in children:
            error = path_boundary_error(root, child)
            if error:
                yield NativeResource(
                    root, child, "unsupported", child.name, (target,), strategy, error
                )
                continue
            marker_path = child / marker
            error = path_boundary_error(root, marker_path)
            if error:
                yield NativeResource(
                    root, marker_path, "unsupported", child.name, (target,), strategy, error
                )
            elif marker_path.is_file():
                sources.append(child)
    elif mapping.extension.startswith("."):
        try:
            sources = [
                child for child in sorted(base.iterdir()) if child.name.endswith(mapping.extension)
            ]
        except OSError:
            yield NativeResource(
                root,
                base,
                "unsupported",
                f"{target}-{kind}",
                (target,),
                strategy,
                "unreadable-source-path",
            )
            return
    elif mapping.extension:
        source = base / mapping.extension
        sources = [source]
    else:
        return
    for source in sources:
        if error := path_boundary_error(root, source):
            yield NativeResource(
                root, source, "unsupported", source.name, (target,), strategy, error
            )
            continue
        if not source.exists():
            continue
        if source.is_dir():
            name = source.name
        elif mapping.extension.startswith("."):
            name = source.name[: -len(mapping.extension)]
        else:
            name = f"{target}-hooks" if canonical_kind == "hook" else source.stem
        yield NativeResource(root, source, canonical_kind, name, (target,), strategy)


def discover_filesystem_resources(
    targets: Iterable[str],
    *,
    home: Path | None = None,
    presence_hook: PresenceHook | None = None,
    custom_hook: CustomHook | None = None,
) -> list[NativeResource]:
    """Enumerate registry mappings, then aggregate identical physical resources."""
    home = (home or Path.home()).expanduser().resolve(strict=False)
    grouped: dict[tuple[Path, str, str], NativeResource] = {}
    for target in sorted(set(targets)):
        try:
            profile = KNOWN_TARGETS[target].for_scope(user_scope=True)
        except OSError:
            grouped[(home, "unsupported", target)] = NativeResource(
                home,
                home,
                "unsupported",
                target,
                (target,),
                "custom",
                "source-resolver-error",
            )
            continue
        if profile is None:
            continue
        root = target_root(profile, home=home)
        if presence_hook is not None and not presence_hook(target, profile, root):
            continue
        resources = (
            custom_hook(target, profile, root)
            if custom_hook is not None
            else (
                resource
                for kind, mapping in sorted(profile.primitives.items())
                for resource in _mapping_resources(target, profile, kind, mapping, home=home)
            )
        )
        for resource in resources:
            path = resource.path if resource.blocked_reason else resource.path.resolve(strict=False)
            key = (path, resource.kind, resource.name)
            previous = grouped.get(key)
            if previous is None:
                grouped[key] = replace(resource, path=path)
            else:
                grouped[key] = replace(
                    previous,
                    targets=tuple(sorted(set(previous.targets) | set(resource.targets))),
                    strategy=(
                        "shared"
                        if "shared" in {previous.strategy, resource.strategy}
                        else previous.strategy
                    ),
                )
    return sorted(grouped.values(), key=lambda value: (str(value.path), value.kind, value.name))
