#!/bin/sh
# Build app test t4 (ICC). Cần Android SDK (build-tools + platform android-34).
set -e; cd "$(dirname "$0")"
BT=${BT:-$HOME/Android/Sdk/build-tools/36.0.0}; AJ=${AJ:-$HOME/Android/Sdk/platforms/android-34/android.jar}
rm -rf cls out t4.apk; mkdir -p cls out
javac -nowarn --release 11 -cp $AJ -d cls src/com/rdict/t4/*.java 2>&1 | grep -v "^Note" || true
$BT/d8 --min-api 24 --lib $AJ --output out $(find cls -name "*.class")
$BT/aapt2 link -o t4.apk -I $AJ --manifest AndroidManifest.xml && (cd out && zip -q ../t4.apk classes.dex)
rm -rf cls out
