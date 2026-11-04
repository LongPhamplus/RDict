#!/bin/sh
# Build app test t3 (cần Android SDK; gen.py của t3 cần thư viện cryptography trong .venv của rdict).
set -e; cd "$(dirname "$0")"
BT=${BT:-$HOME/Android/Sdk/build-tools/36.0.0}; AJ=${AJ:-$HOME/Android/Sdk/platforms/android-34/android.jar}
"$(cd ../../.. && pwd)/.venv/bin/python" gen.py
rm -rf cls out t3.apk; mkdir -p cls out
javac -nowarn --release 11 -cp $AJ -d cls $(find src -name "*.java") 2>&1 | grep -v "^Note\|warning" || true
$BT/d8 --min-api 21 --lib $AJ --output out $(find cls -name "*.class")
$BT/aapt2 link -o t3.apk -I $AJ --manifest AndroidManifest.xml && (cd out && zip -q ../t3.apk classes.dex)
rm -rf cls out
