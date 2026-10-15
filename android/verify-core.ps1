param(
    [string]$CacheRoot = ""
)
# Verify the Android core against the Python-generated spec vectors.
# Downloads the Kotlin compiler from Maven Central (cached under android/.kotlin-cache),
# compiles android/core and runs the cross-language checks. No Android SDK required.
$ErrorActionPreference = "Stop"

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Split-Path -Parent $here
$cache = if ($CacheRoot) { $CacheRoot } else { Join-Path $root ".kotlin-cache" }
$libDir = Join-Path $cache "lib"
$outDir = Join-Path $cache "out"
$ktVersion = if ($env:KOTLIN_VERSION) { $env:KOTLIN_VERSION } else { "2.4.21" }
$maven = "https://repo1.maven.org/maven2"

New-Item -ItemType Directory -Force -Path $libDir | Out-Null

function Get-Jar([string]$Url, [string]$Name) {
    $target = Join-Path $libDir $Name
    if (-not (Test-Path -LiteralPath $target)) {
        Write-Host ("downloading " + $Name)
        curl.exe -fsSL --max-time 600 -o $target $Url
        if ($LASTEXITCODE -ne 0) { throw ("download failed: " + $Name) }
    }
}

Get-Jar "$maven/org/jetbrains/kotlin/kotlin-compiler-embeddable/$ktVersion/kotlin-compiler-embeddable-$ktVersion.jar" "kotlin-compiler-embeddable-$ktVersion.jar"
Get-Jar "$maven/org/jetbrains/kotlin/kotlin-stdlib/$ktVersion/kotlin-stdlib-$ktVersion.jar" "kotlin-stdlib-$ktVersion.jar"
Get-Jar "$maven/org/jetbrains/kotlin/kotlin-script-runtime/$ktVersion/kotlin-script-runtime-$ktVersion.jar" "kotlin-script-runtime-$ktVersion.jar"
Get-Jar "$maven/org/jetbrains/kotlin/kotlin-reflect/$ktVersion/kotlin-reflect-$ktVersion.jar" "kotlin-reflect-$ktVersion.jar"
Get-Jar "$maven/org/jetbrains/intellij/deps/trove4j/1.0.20200330/trove4j-1.0.20200330.jar" "trove4j-1.0.20200330.jar"
Get-Jar "$maven/org/jetbrains/annotations/13.0/annotations-13.0.jar" "annotations-13.0.jar"
Get-Jar "$maven/org/jetbrains/kotlinx/kotlinx-coroutines-core-jvm/1.11.0/kotlinx-coroutines-core-jvm-1.11.0.jar" "kotlinx-coroutines-core-jvm-1.11.0.jar"
Get-Jar "$maven/org/jetbrains/kotlin/kotlin-daemon-embeddable/$ktVersion/kotlin-daemon-embeddable-$ktVersion.jar" "kotlin-daemon-embeddable-$ktVersion.jar"
Get-Jar "$maven/org/json/json/20240303/json-20240303.jar" "json-20240303.jar"

$stdlib = Join-Path $libDir ("kotlin-stdlib-" + $ktVersion + ".jar")
$jsonJar = Join-Path $libDir "json-20240303.jar"
$compilerCp = (Get-ChildItem -LiteralPath $libDir -Filter *.jar | ForEach-Object { $_.FullName }) -join ";"
$classpath = "$stdlib;$jsonJar"

Remove-Item -Recurse -Force $outDir -ErrorAction SilentlyContinue
$sources = Get-ChildItem -Recurse -Path (Join-Path $root "android\core\src") -Filter *.kt | ForEach-Object { $_.FullName }

Write-Host "compiling Android core..."
java -cp $compilerCp org.jetbrains.kotlin.cli.jvm.K2JVMCompiler -nowarn -no-stdlib -classpath $classpath -d $outDir $sources
if ($LASTEXITCODE -ne 0) { throw "kotlin compile failed" }

Write-Host "running spec vectors..."
java -cp ("$outDir;" + $classpath) com.pmvault.core.SpecVectorsKt $root
exit $LASTEXITCODE
