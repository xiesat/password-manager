#!/usr/bin/env bash
# 用 Maven Central 上的 Kotlin 编译器校验 Android core 是否与 Python 参考实现一致。
# 不需要 Android SDK；在 Windows(Git Bash/WSL)、Linux、macOS 上均可运行。
set -euo pipefail

HERE="$( cd "$( dirname "$0" )" && pwd )"
ROOT="$( dirname "$HERE" )"
KOTLIN_VERSION="${KOTLIN_VERSION:-2.4.21}"
CACHE="${KOTLIN_CACHE_DIR:-$ROOT/.kotlin-cache}"
LIB="$CACHE/lib"
OUT="$CACHE/out"
BASE="https://repo1.maven.org/maven2"

mkdir -p "$LIB"

fetch() {
  if [ ! -f "$LIB/$2" ]; then
    echo "downloading $2"
    curl -fsSL -o "$LIB/$2" "$1"
  fi
}

fetch "$BASE/org/jetbrains/kotlin/kotlin-compiler-embeddable/$KOTLIN_VERSION/kotlin-compiler-embeddable-$KOTLIN_VERSION.jar" "kotlin-compiler-embeddable-$KOTLIN_VERSION.jar"
fetch "$BASE/org/jetbrains/kotlin/kotlin-stdlib/$KOTLIN_VERSION/kotlin-stdlib-$KOTLIN_VERSION.jar" "kotlin-stdlib-$KOTLIN_VERSION.jar"
fetch "$BASE/org/jetbrains/kotlin/kotlin-script-runtime/$KOTLIN_VERSION/kotlin-script-runtime-$KOTLIN_VERSION.jar" "kotlin-script-runtime-$KOTLIN_VERSION.jar"
fetch "$BASE/org/jetbrains/kotlin/kotlin-reflect/$KOTLIN_VERSION/kotlin-reflect-$KOTLIN_VERSION.jar" "kotlin-reflect-$KOTLIN_VERSION.jar"
fetch "$BASE/org/jetbrains/intellij/deps/trove4j/1.0.20200330/trove4j-1.0.20200330.jar" "trove4j-1.0.20200330.jar"
fetch "$BASE/org/jetbrains/annotations/13.0/annotations-13.0.jar" "annotations-13.0.jar"
fetch "$BASE/org/jetbrains/kotlinx/kotlinx-coroutines-core-jvm/1.11.0/kotlinx-coroutines-core-jvm-1.11.0.jar" "kotlinx-coroutines-core-jvm-1.11.0.jar"
fetch "$BASE/org/jetbrains/kotlin/kotlin-daemon-embeddable/$KOTLIN_VERSION/kotlin-daemon-embeddable-$KOTLIN_VERSION.jar" "kotlin-daemon-embeddable-$KOTLIN_VERSION.jar"
fetch "$BASE/org/json/json/20240303/json-20240303.jar" "json-20240303.jar"

STDLIB="$LIB/kotlin-stdlib-$KOTLIN_VERSION.jar"
JSON="$LIB/json-20240303.jar"

SEP=":"
case "$( uname -s )" in
  MINGW*|MSYS*|CYGWIN*) SEP=";" ;;
esac

COMPILER_CP="$( find "$LIB" -name '*.jar' | tr '\n' "$SEP" )"
rm -rf "$OUT"
SOURCES="$( find "$ROOT/android/core/src" -name '*.kt' )"

echo "compiling Android core..."
java -cp "$COMPILER_CP" org.jetbrains.kotlin.cli.jvm.K2JVMCompiler \
  -nowarn -no-stdlib -classpath "$STDLIB$SEP$JSON" -d "$OUT" $SOURCES

echo "running spec vectors..."
java -cp "$OUT$SEP$STDLIB$SEP$JSON" com.pmvault.core.SpecVectorsKt "$ROOT"
