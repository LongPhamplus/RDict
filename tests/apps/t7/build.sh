#!/bin/sh
# Build app test t7 (JNI flow). Cần Android SDK (build-tools + android-34), JDK (jni.h) và ziglang trong .venv
# (pip install ziglang) để biên dịch chéo libt7.so cho arm64.
set -e; cd "$(dirname "$0")"
BT=${BT:-$HOME/Android/Sdk/build-tools/36.0.0}; AJ=${AJ:-$HOME/Android/Sdk/platforms/android-34/android.jar}
PY=${PY:-$(cd ../../.. && pwd)/.venv/bin/python}; JH=${JH:-/usr/lib/jvm/default-java/include}
rm -rf cls out lib t7.apk; mkdir -p cls out lib/arm64-v8a
$PY -m ziglang cc -target aarch64-linux-musl -O2 -fPIC -shared -s -I$JH -I$JH/linux -o lib/arm64-v8a/libt7.so jni/t7.c
javac -nowarn --release 11 -cp $AJ -d cls src/com/rdict/t7/*.java 2>&1 | grep -v "^Note" || true
$BT/d8 --min-api 24 --lib $AJ --output out $(find cls -name "*.class")
$BT/aapt2 link -o t7.apk -I $AJ --manifest AndroidManifest.xml && (cd out && zip -q ../t7.apk classes.dex) && zip -q -r t7.apk lib
rm -rf cls out lib
