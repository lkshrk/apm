APM_VERSION = 0.39.1
UPSTREAM = https://github.com/microsoft/apm.git
# Branch the patch series is authored on (upstream tag + one commit per patch).
PATCH_BRANCH = lk-patches/v$(APM_VERSION)

CHECKOUT = checkouts/apm
PYTHON = 3.12
DIST = dist
# Fixed so zip timestamps, and therefore the wheel digest, don't depend on when it's built.
export SOURCE_DATE_EPOCH = 1700000000

.PHONY: help checkouts patches test wheel verify refresh-patches next-version clean

help:
	@echo "make checkouts patches test wheel verify   build and check the patched wheel"
	@echo "make refresh-patches                       re-export patches/ from $(PATCH_BRANCH)"
	@echo "make next-version                          the version the next release gets"

checkouts:
	rm -rf $(CHECKOUT)
	git -c advice.detachedHead=false clone --quiet --depth 1 --branch v$(APM_VERSION) $(UPSTREAM) $(CHECKOUT)

patches:
	git -C $(CHECKOUT) -c user.name=lk-build -c user.email=lk-build@localhost am --quiet --committer-date-is-author-date $(abspath patches)/*.patch

# Same Python line and command as upstream's release workflow; uv's managed build tracks the latest 3.12.x.
test: export UV_PYTHON_PREFERENCE = only-managed
test:
	cd $(CHECKOUT) && uv sync --frozen --extra dev --python $(PYTHON) --quiet
	cd $(CHECKOUT) && uv run --frozen --extra dev --python $(PYTHON) pytest -p no:cacheprovider -q tests/unit tests/test_console.py -n auto --dist worksteal

# VERSION defaults to the next release version; CI passes it explicitly.
wheel:
	@test -n "$(VERSION)" || { echo "VERSION is required, e.g. make wheel VERSION=$$(make -s next-version)" >&2; exit 1; }
	rm -rf $(DIST) build-tree && mkdir -p $(DIST) build-tree
	git -C $(CHECKOUT) archive HEAD | tar -x -C build-tree
	sed -i.bak 's/^version = "$(APM_VERSION)"$$/version = "$(VERSION)"/' build-tree/pyproject.toml && rm build-tree/pyproject.toml.bak
	grep -qx 'version = "$(VERSION)"' build-tree/pyproject.toml
	cd build-tree && uv build --wheel --out-dir $(abspath $(DIST)) >/dev/null
	rm -rf build-tree
	cd $(DIST) && sha256sum *.whl > SHA256SUMS && cat SHA256SUMS

verify:
	tests/secret-references.sh "$$(ls $(abspath $(DIST))/apm_cli-*.whl)"

refresh-patches:
	rm -f patches/*.patch
	git format-patch --quiet --no-signature --zero-commit -o patches v$(APM_VERSION)..$(PATCH_BRANCH)
	@ls patches

next-version:
	@n=$$(git tag -l 'v$(APM_VERSION)+lk.*' | sed 's/.*+lk\.//' | sort -n | tail -1); echo "$(APM_VERSION)+lk.$$(( $${n:-0} + 1 ))"

clean:
	rm -rf checkouts build-tree $(DIST)
