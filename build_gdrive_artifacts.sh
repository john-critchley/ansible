#!/bin/bash
# Build all pre-built artifacts for upload to Google Drive.
#
# Outputs to gdrive-artifacts/:
#   google-jwt-asserter-1.0.jar      — shaded provider JAR (contains nimbus-jose-jwt)
#   google-jwt-asserter-1.0-mjf.jar  — WebLogic MBean metadata JAR
#
# Requirements (all present on pomelo):
#   - WebLogic installed at ~/Oracle/Middleware/Oracle_Home
#   - Java 21
#   - Maven
#
# Run from ~/ansible:
#   bash build_gdrive_artifacts.sh

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ASSERTER_DIR="$REPO_DIR/files/jwt-asserter"
OUT_DIR="$REPO_DIR/gdrive-artifacts"

WLS_HOME="${WLS_HOME:-$HOME/Oracle/Middleware/Oracle_Home/wlserver}"

echo "==> Output directory: $OUT_DIR"
mkdir -p "$OUT_DIR"

# ── JWT asserter ──────────────────────────────────────────────────────────────

echo ""
echo "==> Building JWT asserter JARs"
cd "$ASSERTER_DIR"

WLS_HOME="$WLS_HOME" bash build.sh

cp target/google-jwt-asserter-1.0.jar     "$OUT_DIR/"
cp target/google-jwt-asserter-1.0-mjf.jar "$OUT_DIR/"

echo "==> Cleaning up Maven build artefacts"
mvn clean -q
rm -rf target/

# ── Done ──────────────────────────────────────────────────────────────────────

echo ""
echo "==> Artifacts ready for Google Drive upload:"
ls -lh "$OUT_DIR"
