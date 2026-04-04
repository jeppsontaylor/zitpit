#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <version> [target]" >&2
  exit 1
fi

VERSION="$1"
TARGET="${2:-$(rustc -vV | sed -n 's/^host: //p')}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT_DIR}/dist/release"
STAGE_DIR="${OUT_DIR}/stage/zitpit-${VERSION}-${TARGET}"
TARBALL="${OUT_DIR}/zitpit-${VERSION}-${TARGET}.tar.gz"
SBOM_BASENAME="zitpit-${VERSION}-${TARGET}-sbom"
SBOM_BUNDLE="${OUT_DIR}/zitpit-${VERSION}-${TARGET}-sboms.tar.gz"

BINS=(
  xtask
  zitpit-battle-cli
  zitpit-gateway
  zitpit-lab
  zitpit-manifest
  zitpit-node-agent
  zitpit-sessiond
  zitpit-tui
  zitpit-watch
)

rm -rf "${STAGE_DIR}" "${TARBALL}" "${SBOM_BUNDLE}" "${OUT_DIR}/SHA256SUMS.txt"
mkdir -p "${STAGE_DIR}/bin" "${OUT_DIR}"

pushd "${ROOT_DIR}" >/dev/null
rustup target add "${TARGET}"
cargo build --release --locked --bins --target "${TARGET}"

for bin in "${BINS[@]}"; do
  cp "target/${TARGET}/release/${bin}" "${STAGE_DIR}/bin/${bin}"
done

cp README.md LICENSE "${STAGE_DIR}/"
tar -C "${OUT_DIR}/stage" -czf "${TARBALL}" "zitpit-${VERSION}-${TARGET}"

cargo cyclonedx \
  --format json \
  --all-features \
  --target "${TARGET}" \
  --override-filename "${SBOM_BASENAME}"

SBOM_FILES=()
while IFS= read -r sbom_file; do
  SBOM_FILES+=("${sbom_file}")
done < <(find "${ROOT_DIR}" -path "${ROOT_DIR}/target" -prune -o -name "${SBOM_BASENAME}.json" -print | sort)
if [[ ${#SBOM_FILES[@]} -eq 0 ]]; then
  echo "no CycloneDX outputs were produced" >&2
  exit 1
fi
tar -czf "${SBOM_BUNDLE}" "${SBOM_FILES[@]}"
rm -f "${SBOM_FILES[@]}"

(
  cd "${OUT_DIR}"
  shasum -a 256 "$(basename "${TARBALL}")" "$(basename "${SBOM_BUNDLE}")" > SHA256SUMS.txt
)
popd >/dev/null

echo "release bundle ready under ${OUT_DIR}"
