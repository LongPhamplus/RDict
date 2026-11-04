#!/bin/sh
# Hồi quy nhanh: build app test rồi kiểm tra rule mong đợi (có / không có).
cd "$(dirname "$0")/.." || exit 1
PY=.venv/bin/python; OUT=$(mktemp -d); fail=0
check() {  # check <apk> <rule phải có...> -- <rule không được có...>
  apk=$1; shift
  $PY rdict.py "$apk" -q --json "$OUT/r.json" >/dev/null 2>&1 || { echo "FAIL chạy $apk"; fail=1; return; }
  ids=$(python3 -c "import json;print(' '.join(f['id'] for f in json.load(open('$OUT/r.json'))['findings']))")
  neg=0
  for r in "$@"; do
    if [ "$r" = "--" ]; then neg=1; continue; fi
    case " $ids " in *" $r "*) [ $neg = 1 ] && { echo "FAIL $apk: không mong đợi $r"; fail=1; } ;;
                     *) [ $neg = 0 ] && { echo "FAIL $apk: thiếu $r"; fail=1; } ;; esac
  done
  echo "ok   $(basename $apk): $ids"
}
for t in tests/apps/*/build.sh; do [ -f "${t%/build.sh}/$(basename ${t%/build.sh}).apk" ] || sh $t; done
check tests/apps/t2/t2.apk OB-STRING-DECRYPTOR OB-REFLECTION AA-FRIDA
check tests/apps/t3/t3.apk CR-AUTO-DECRYPT CR-HARDCODED-KEY CR-ECB CR-HEX-CONST CR-WEAK-CIPHER
check tests/apps/testapp/test.apk FLOW-PRIVACY-LEAK BHV-SMS-EXFIL BHV-DROPPER OB-STRING-DECRYPTOR OB-REFLECTION NET-INSECURE-TLS ST-SQLI
check tests/apps/t4/t4.apk FLOW-RCE FLOW-SQLI FLOW-WEBVIEW-LOAD FLOW-PATH-TRAVERSAL FLOW-INTENT-REDIRECT
check tests/apps/t5/t5.apk FLOW-RCE FLOW-PRIVACY-LEAK
# t5: đúng 4 luồng rò rỉ (UploadReceiver, KeySink, DynReceiver, onActivityResult), không báo gửi Intent nội bộ, key "title", Show/Ghost
n=$($PY rdict.py tests/apps/t5/t5.apk -q -i FLOW-PRIVACY --json "$OUT/p.json" >/dev/null 2>&1; python3 -c "
import json;print(sum(len(f['hits']) for f in json.load(open('$OUT/p.json'))['findings']))")
[ "$n" = 4 ] && echo "ok   t5 privacy: 4 luồng" || { echo "FAIL t5 privacy: $n luồng (mong đợi 4)"; fail=1; }
# t3: đủ 4 plaintext, không giải nhầm ca mồi
$PY rdict.py tests/apps/t3/t3.apk -q -i CR-AUTO --json "$OUT/c.json" >/dev/null 2>&1
python3 - "$OUT/c.json" <<'PY' || fail=1
import json, sys
t = json.dumps(json.load(open(sys.argv[1])), ensure_ascii=False)
want = ["http://c2.evil-panel.top/api/v2", "7712:AAx", "FLAG{iv_prepended}", "des-secret"]
miss = [w for w in want if w not in t]
bad = "should not decrypt" in t
print(("FAIL" if miss or bad else "ok  ") + f" t3 crypto: {4 - len(miss)}/4 giải được" + (", giải nhầm ca mồi" if bad else ""))
sys.exit(1 if miss or bad else 0)
PY
# t6: độ chính xác (key map/JSON/mảng/list, dispatch, exception, prefs, reflection): đúng các tag *_LEAK
got=$($PY tests/flowtags.py tests/apps/t6/t6.apk 2>/dev/null)
want="B_MAP_LEAK E_ARR_LEAK G_DISPATCH_LEAK J_RANGE_LEAK L_LIST_LEAK M_LOOP_LEAK N_EXC_LEAK P_PREFS_LEAK Q_REFL_LEAK http://x.example/?"
[ "$got" = "$want" ] && echo "ok   t6 precision: $got" || { echo "FAIL t6: '$got' (mong đợi '$want')"; fail=1; }
# t7: JNI (lib arm64 -O2 strip): native gửi qua socket / gọi SmsManager qua JNI / tự đọc IMEI / gọi ngược Java /
# RegisterNatives; không báo native chỉ strcmp và callback nhận hằng
got=$($PY tests/flowtags.py tests/apps/t7/t7.apk 2>/dev/null)
want="A_LIBC_LEAK B_JNI_SINK_LEAK C_SRC_NATIVE_LEAK E_CALLBACK_LEAK F_REGNAT_LEAK"
[ "$got" = "$want" ] && echo "ok   t7 JNI: $got" || { echo "FAIL t7: '$got' (mong đợi '$want')"; fail=1; }
check tests/apps/t7/t7.apk FLOW-PRIVACY-LEAK
# t8: payload DEX ẩn (assets/data.bin XOR 0x5a; jar đội lốt assets/logo.png): luồng trong payload và xuyên app chính -> payload
got=$($PY tests/flowtags.py tests/apps/t8/t8.apk 2>/dev/null)
want="UPLOAD http://c2.evil-panel.top/s?d="
[ "$got" = "$want" ] && echo "ok   t8 payload: $got" || { echo "FAIL t8: '$got' (mong đợi '$want')"; fail=1; }
check tests/apps/t8/t8.apk OB-PAYLOAD-DEX FLOW-PRIVACY-LEAK BHV-DROPPER-ASSET
# t9: cổng chặn (anti-emulator, geofence, time bomb tuyệt đối + trì hoãn sau cài, lệnh C2 qua SMS, mật khẩu ô nhập);
# mồi: throttle cache (now - last > 1h) và so action Intent không được báo; script Frida ép đủ các cổng
check tests/apps/t9/t9.apk BHV-TIME-BOMB BHV-SECRET-GATE BHV-GEO-GATE FLOW-PRIVACY-LEAK
$PY rdict.py tests/apps/t9/t9.apk -q -i BHV- -i FLOW --json "$OUT/g.json" --gate-script "$OUT/g.js" >/dev/null 2>&1
python3 - "$OUT/g.json" "$OUT/g.js" <<'PY' || fail=1
import json, sys
d = json.load(open(sys.argv[1])); js = open(sys.argv[2]).read()
n = {f["id"]: len(f["hits"]) for f in d["findings"]}
gates = {g["cond"] for f in d["findings"] for h in f["hits"] for g in h.get("gates") or []}
bad = []
if n.get("BHV-TIME-BOMB") != 2: bad.append(f"time bomb {n.get('BHV-TIME-BOMB')} hit (mong đợi 2)")
if n.get("BHV-SECRET-GATE") != 2: bad.append(f"secret gate {n.get('BHV-SECRET-GATE')} hit (mong đợi 2)")
for w in ["!Env.isEmulator()", "1798761600000", "> 259200000", '.equals("#steal")', '.equals("ru")']:
    if not any(w in g for g in gates): bad.append("thiếu cổng " + w)
for w in ['"0p3n-s3s4m3"', '"#steal"', '"isEmulator", [], false', '"getSimCountryIso", [], "us"', "1798761600001", "+ 259260000"]:
    if w not in js: bad.append("script thiếu " + w)
print(("FAIL t9 gates: " + "; ".join(bad)) if bad else f"ok   t9 gates: {len(gates)} cổng, script đủ")
sys.exit(1 if bad else 0)
PY
rm -rf "$OUT"; exit $fail
