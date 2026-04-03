#!/bin/bash
# Build the Google JWT Identity Asserter JAR.
#
# Steps:
#   1. Run WebLogicMBeanMaker to generate MBean interface/impl stubs from the MDF.
#   2. Run Maven to compile everything (hand-written + generated) and produce the
#      shaded JAR containing nimbus-jose-jwt.
#
# Environment variables:
#   WLS_HOME   — WebLogic wlserver directory (default: Oracle_Home/wlserver)
#   JAVA_HOME  — JDK home (uses PATH java if unset)
#   MVN        — mvn binary (default: mvn)
#
# Output: target/google-jwt-asserter-1.0.jar

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

WLS_HOME="${WLS_HOME:-/home/john/Oracle/Middleware/Oracle_Home/wlserver}"
JAVA="${JAVA_HOME:+$JAVA_HOME/bin/}java"
JAR="${JAVA_HOME:+$JAVA_HOME/bin/}jar"
MVN="${MVN:-mvn}"

WLS_JAR="$WLS_HOME/server/lib/weblogic.jar"
MDF="src/main/mdf/GoogleJwtAssertionProvider.xml"
GENERATED="target/generated-sources/mdf"
FINAL_JAR="target/google-jwt-asserter-1.0.jar"
MJF_JAR="target/google-jwt-asserter-1.0-mjf.jar"

if [ ! -f "$WLS_JAR" ]; then
    echo "ERROR: weblogic.jar not found at $WLS_JAR" >&2
    echo "Set WLS_HOME to point to the wlserver directory." >&2
    exit 1
fi

echo "==> MBeanMaker: generating stubs from $MDF"
mkdir -p "$GENERATED"
"$JAVA" -classpath "$WLS_JAR" \
    weblogic.management.commo.WebLogicMBeanMaker \
    -MDF "$MDF" \
    -files "$GENERATED" \
    -createStubs

echo "==> Maven: compile + shade"
$MVN package -q -DweblogicJar="$WLS_JAR" -DskipTests

echo "==> MBeanMaker: packaging WebLogic provider metadata"
rm -f "$MJF_JAR"
"$JAVA" -classpath "$WLS_JAR" \
    weblogic.management.commo.WebLogicMBeanMaker \
    -MDF "$MDF" \
    -files "$GENERATED" \
    -MJF "$MJF_JAR" \
    -createStubs

echo "==> Embedding the MDF in both jars for WebLogic type discovery"
$JAR uf "$FINAL_JAR" -C src/main/mdf GoogleJwtAssertionProvider.xml
$JAR uf "$MJF_JAR" -C src/main/mdf GoogleJwtAssertionProvider.xml

echo "==> Done: $SCRIPT_DIR/$FINAL_JAR"
echo "==> MBean metadata jar: $SCRIPT_DIR/$MJF_JAR"
