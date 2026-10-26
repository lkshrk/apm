"""Discover explicitly declared native extensions without importing executable code."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

_NATIVE_SUFFIXES = frozenset({".ts", ".js", ".mjs", ".cjs"})
_SOURCE_DIRS = (".omp/extensions", ".pi/extensions", ".apm/extensions")


@dataclass(frozen=True)
class ExtensionBundle:
    """A package snapshot and its package-relative native entry points."""

    source_root: Path
    name: str
    entries: tuple[str, ...]


def native_extension_name(path: Path) -> str:
    """Match omp's capability identity for an explicitly resolved entry path."""
    return path.parent.name if path.name in ("index.ts", "index.js") else path.stem


def native_extension_declaration(package_path: Path) -> list[str] | None:
    """Return the authoritative omp/pi declaration, including unbuilt entries.

    Presence, not successful artifact discovery, determines precedence. A bad
    native declaration must never silently enable the portable hook adapter.
    """
    manifest = package_path / "package.json"
    if not manifest.is_file():
        return None
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError(f"Cannot read native package manifest {manifest}: {exc}") from exc
    if not isinstance(data, dict):
        return None
    for namespace in ("omp", "pi"):
        section = data.get(namespace)
        if section is None:
            continue
        # Native discovery selects the omp object before considering pi,
        # rather than merging fields from the two namespaces.
        if not isinstance(section, dict) or "extensions" not in section:
            return None
        if isinstance(section, dict) and "extensions" in section:
            entries = section["extensions"]
            if (
                not isinstance(entries, list)
                or not entries
                or not all(isinstance(entry, str) and entry for entry in entries)
            ):
                raise ValueError(
                    f"{manifest}: {namespace}.extensions must be a non-empty list of paths"
                )
            return entries
    return None


def has_native_extension_manifest(package_path: Path) -> bool:
    """Whether a package explicitly declares native executable entry points."""
    return native_extension_declaration(package_path) is not None


def _entry(root: Path, value: str) -> str:
    # Reject traversal rather than normalizing it: declared entries are portable
    # package-relative paths, never host paths or links outside the snapshot.
    path = PurePosixPath(value)
    if "\\" in value or path.is_absolute() or ".." in path.parts or ":" in value:
        raise ValueError(f"Unsafe native extension entry {value!r} in {root}")
    source = root.joinpath(*path.parts)
    if source.is_dir():
        source = next(
            (source / name for name in ("index.ts", "index.js") if (source / name).is_file()),
            source,
        )
    try:
        relative = source.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"Unsafe native extension entry {value!r} in {root}") from exc
    cursor = root
    for component in relative.parts:
        cursor = cursor / component
        if cursor.is_symlink():
            raise ValueError(f"Symlinked native extension entry {value!r} in {root}")
    if source.suffix not in _NATIVE_SUFFIXES or not source.is_file():
        raise ValueError(
            f"Missing or unsupported declared native extension {value!r} in {root}. "
            "Ship the built or vendored artifact; APM does not run npm installs or builds."
        )
    return relative.as_posix()


def find_extension_bundles(
    package_path: Path, *, validate_entries: bool = True, is_first_party: bool = False
) -> list[ExtensionBundle]:
    """Find native package manifests or designated extension source directories.

    Dependencies keep their full package root to preserve imports and resources.
    First-party project content is bounded to .apm/extensions; ambient native
    deployment directories are never promoted back into executable source.
    Arbitrary root index.js files never opt a package into executable deployment.
    """
    package_root = Path(package_path)
    root = package_root
    if is_first_party:
        if native_extension_declaration(package_root) is not None:
            raise ValueError(
                "Project-root native extension manifests are not deployable: copying "
                "the whole project could include private files. Put a self-contained "
                "extension package and its assets under .apm/extensions instead."
            )
        root = package_root / ".apm" / "extensions"
        from apm_cli.utils.path_security import has_symlink_component

        if has_symlink_component(package_root, root):
            raise ValueError(f"Symlinked first-party extension source directory: {root}")
        if not root.is_dir():
            return []
    source_directories = (
        (root,) if is_first_party else tuple(root / source for source in _SOURCE_DIRS)
    )

    def entry(base: Path, value: str) -> str:
        return _entry(base, value) if validate_entries else value

    declaration = native_extension_declaration(root)
    entries: list[str] = []
    if declaration is not None:
        entries.extend(entry(root, value) for value in declaration)
    else:
        for base in source_directories:
            if validate_entries and base.is_symlink():
                raise ValueError(f"Symlinked native extension source directory: {base}")
            if not base.is_dir():
                continue
            for child in sorted(base.iterdir()):
                if child.is_dir() and (child / ".apm-extension.json").is_file():
                    continue
                if validate_entries and child.is_symlink():
                    raise ValueError(f"Symlinked native extension source: {child}")
                if child.is_file() and child.suffix in (".ts", ".js"):
                    entries.append(entry(root, child.relative_to(root).as_posix()))
                elif child.is_dir():
                    nested = native_extension_declaration(child)
                    if nested is not None:
                        entries.extend(
                            entry(root, (child.relative_to(root) / entry(child, value)).as_posix())
                            for value in nested
                        )
                    else:
                        index = next(
                            (
                                child / name
                                for name in ("index.ts", "index.js")
                                if (child / name).is_file()
                            ),
                            None,
                        )
                        if index is not None:
                            entries.append(entry(root, index.relative_to(root).as_posix()))
    if not entries:
        return []
    name = "_local" if is_first_party else root.name
    return [ExtensionBundle(root, name, tuple(dict.fromkeys(entries)))]


def has_native_extension_sources(project_root: Path) -> bool:
    """Report authored first-party native extension factories without validating entries.

    Existence probe for callers that must keep native sources out of portable
    layouts or fail closed on them. Structural problems (symlinked or
    root-manifest sources) count as present; they are reported by the validating
    :func:`find_extension_bundles` callers, not hidden here.
    """
    try:
        bundles = find_extension_bundles(project_root, validate_entries=False, is_first_party=True)
        return bool(bundles)
    except ValueError:
        return True


def is_native_extension_path(relative: str) -> bool:
    """Identify native executable deployment payloads (not Copilot canvases)."""
    parts = PurePosixPath(relative.replace("\\", "/")).parts
    for index, part in enumerate(parts):
        if part != "extensions":
            continue
        if index and parts[index - 1] in (".omp", ".pi"):
            return True
        if index >= 2 and parts[index - 2 : index] == (".omp", "agent"):
            return True
        if index == 0 or parts[index - 1].startswith("."):
            return False
    return False
