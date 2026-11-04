#!/bin/sh
# Build t2 (string mã hóa, cần ký để cài lên máy test --frida-decrypt).
set -e; cd "$(dirname "$0")"
BT=${BT:-$HOME/Android/Sdk/build-tools/36.0.0}; AJ=${AJ:-$HOME/Android/Sdk/platforms/android-34/android.jar}
python3 gen.py
rm -rf cls out; mkdir -p cls out
javac -nowarn --release 11 -cp $AJ -d cls src/com/rdict/t2/*.java 2>&1 | grep -v "^Note\|warning" || true
$BT/d8 --min-api 24 --lib $AJ --output out $(find cls -name "*.class")
$BT/aapt2 link -o un.apk -I $AJ --manifest AndroidManifest.xml && (cd out && zip -q ../un.apk classes.dex)
$BT/zipalign -f 4 un.apk al.apk
[ -f k.jks ] || keytool -genkeypair -keystore k.jks -storepass android -keypass android -alias k -keyalg RSA -keysize 2048 -validity 3650 -dname CN=rdict >/dev/null 2>&1
$BT/apksigner sign --ks k.jks --ks-pass pass:android --out t2.apk al.apk
rm -rf cls out un.apk al.apk t2.apk.idsig
