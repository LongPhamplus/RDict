# rdict — Reverse Dictionary (v0.3)

Đưa vào một APK (hoặc DEX / .so / thư mục source), rdict đối chiếu với **từ điển kỹ thuật**
(`rules/*.yaml`) và trả về các kỹ thuật nghi ngờ, mỗi kỹ thuật kèm **bằng chứng có ngữ cảnh**:

- đoạn source (jadx), bytecode Dalvik (`-b`) hoặc assembly ARM64/x86 của chỗ bị phát hiện;
- **class.method / hàm native** chứa nó, và **đường gọi từ entry point**
  (`MainActivity.onCreate → ⇢(callback) Loader.run`, `[.init_array] sub_31b0 → ⇢(callback) sub_30d0`);
- **độ tin cậy** của bằng chứng, kèm gợi ý bypass / phân tích, mã MITRE ATT&CK Mobile, và Frida hook (`--hook`).

## Kiến trúc: 3 engine + phân tích luồng + giả lập native

| Engine | Thư viện | Làm gì | Tin cậy |
|---|---|---|---|
| **dex** | androguard | Khớp trên **lệnh thật** (`invoke-*`, `const-string`, `iget/sget`). Có call graph và đường gọi từ component trong manifest (kể cả callback như Thread/AsyncTask/listener). Theo dõi hằng trong thanh ghi để giải tên đích reflection. Phát hiện hàm giải mã string. Combo hành vi. | ●●○ / ●●● |
| **native** | lief + capstone | Imports/exports thật. Phân giải PLT nên ra **call site** của `ptrace`, `strstr`... Xref chuỗi (`adrp+add`, `adr`, `lea [rip+x]`, literal pool ARM32). ARM32: tự nhận hàm ARM hay Thumb. Call graph native gồm cả con trỏ hàm (`pthread_create(.., fn)`). Root: `JNI`, `JNI_OnLoad`, `.init_array`. Entropy, section header bị xóa. | ●●○ |
| **flow** (trong dex) | tự viết | Taint/value-flow liên thủ tục: theo **chính giá trị** từ nguồn (IMEI, Intent extra...) qua biến, field, method, object tới đích (mạng, SQL, exec...). Dùng CHA + vòng đời/callback. Cũng giải hằng cho reflection và cặp key/ciphertext cho crypto. | ●●● |
| **emu** (trong native) | unicorn | Chạy `.init_array` + `JNI_OnLoad` với JNIEnv giả, quét từng hàm: lấy chuỗi giải mã lúc init, stack string, đối số `strcmp/strstr...`, `RegisterNatives`. arm64 + x86_64. | ●●● |
| **text** | regex | Fallback: manifest, resource, danh sách file, và source khi không có bytecode. Comment bị loại trước khi khớp. | ●○○ |

**Vì sao không chỉ dùng regex?** Tên API framework (`SmsManager.sendTextMessage`...) không thể bị
ProGuard đổi tên, nên khớp trên lệnh `invoke` vẫn đúng với app đã obfuscate, không bị comment hay dead
code đánh lừa, và có thêm thông tin ai gọi, gọi từ đâu.

Độ tin cậy:
- `●○○ text`: chỉ khớp chữ.
- `●●○ code`: khớp cấu trúc (bytecode / asm / manifest).
- `●●● behavior`: nhiều API cấu thành một hành vi trong cùng luồng gọi, hoặc reflection giấu API nhạy cảm, hoặc hàm giải mã string đã được xác nhận.

## Cài đặt

Cần `jadx` trong PATH, Python 3.10+. Thư viện phân tích nằm trong `.venv` của project và
`rdict.py` tự chạy lại bằng `.venv` khi cần:

```bash
python3 -m venv --system-site-packages .venv && .venv/bin/pip install androguard lief
.venv/bin/pip install frida==<bản của frida-server> frida-tools   # chỉ cần cho --frida-decrypt
ln -s ~/tools/rdict/rdict.py ~/.local/bin/rdict   # tùy chọn
```

## Sử dụng

```bash
rdict app.apk                          # quét đầy đủ
rdict app.apk -t code                  # bỏ bằng chứng chỉ khớp text (●○○)
rdict app.apk --reachable              # chỉ giữ code gọi tới được từ entry point
rdict app.apk -s medium -c anti-analysis -c native
rdict app.apk -i AA- -i NAT-           # lọc theo prefix ID
rdict app.apk --hook -b                # kèm Frida hook + bytecode Dalvik
rdict app.apk -a                       # quét cả thư viện bên thứ ba (androidx, RN, libc++...)
rdict app.apk --md report.md --json report.json -q
rdict libfoo.so                        # chỉ phân tích một file ELF
rdict ./jadx_output/                   # thư mục đã decompile (chỉ engine text)
rdict app.apk --no-dex / --no-native   # tắt từng engine
rdict app.apk --no-flow / --no-emu     # tắt phân tích luồng / giả lập native
rdict app.apk --flow-budget 60         # giới hạn thời gian phân tích luồng (giây, mặc định 180)
rdict app.apk --flow-libs              # phân tích luồng cả trong thư viện (chậm hơn nhiều)
rdict app.apk --gate-script gates.js     # script Frida ép các điều kiện chặn (🔒) về phía mở khóa

rdict -l                               # xem từ điển (cột Engine cho biết rule dùng engine nào)
rdict -e BHV-SMS-EXFIL                 # chi tiết một rule
```

Cache jadx: `~/.cache/rdict/<sha256>` (dùng `--fresh` để decompile lại). App nhỏ chạy trong vài giây.
App lớn (RN/Flutter, 60MB) mất khoảng 1 phút, chủ yếu do androguard dựng call graph.

## Giải mã string (Frida)

Engine dex tìm hàm giải mã string (static, trả về String, có XOR/Base64/Cipher, gọi nhiều nơi với
tham số trông như ciphertext) và ghi lại **mọi lời gọi có tham số hằng**, kể cả ở nhánh code không bao giờ chạy.
Với `--frida-decrypt`, rdict khởi động app trên thiết bị, **gọi thẳng hàm đó** với từng bộ tham số
rồi nạp chuỗi gốc vào lại index tại đúng chỗ gọi. Sau đó mọi rule `strings:` / `str:`, combo và
reflection đều khớp như thể string chưa từng bị mã hóa:

```bash
rdict app.apk --frida-decrypt --dump-strings     # spawn app qua USB, giải, quét lại, in bảng chuỗi
rdict app.apk --frida-decrypt --attach           # app có anti-Frida: tự bypass + mở app trước, rồi attach
rdict app.apk --frida-script dec.js              # chỉ sinh script để chạy tay:
frida -U -f <pkg> -l dec.js -q -t 30 > rdict.log
rdict app.apk --strings rdict.log
```

Kết quả được cache ở `~/.cache/rdict/<sha>.strings.json` và tự dùng lại cho các lần quét sau
(`--fresh` để bỏ). Hit lấy từ chuỗi đã giải có dòng `🔓 Chuỗi đã giải mã: Z.a('…', 55) → 'frida-server'`.
JSON xuất ra có thêm `decrypted_strings`.

Vì gọi hàm thật trong process thật nên đúng với mọi thuật toán (AES, key per-class, key từ stack
trace...). Không giải được: tham số không phải hằng (byte[] dựng bằng fill-array-data, giá trị tính lúc chạy),
và string native.

## Tự giải ciphertext hardcode (CR-AUTO-DECRYPT)

Khi app chứa cả ciphertext lẫn key, rdict tự giải luôn:
- **ciphertext**: hằng base64 hoặc hex, độ dài bội 8/16 byte;
- **key**: hằng hex, base64 hoặc chuỗi 8/16/24/32 byte, hoặc MD5/SHA-256/SHA-1 của một chuỗi ngắn (key derive từ passphrase);
- **IV**: hằng 8/16 byte gần đó, IV toàn 0, IV = key, hoặc IV nằm ở 16 byte đầu ciphertext;
- **thuật toán**: AES-128/192/256, DES, 3DES; mode ECB/CBC; padding PKCS#5/7.

Chỉ ghép key với ciphertext nằm gần nhau (cùng class, caller, callee) và vùng đó phải có dùng `javax.crypto`.
Kết quả chỉ được nhận khi padding hợp lệ **và** plaintext là văn bản đọc được. Chuỗi đã giải bằng Frida
cũng được đưa vào, nên ciphertext hay key bị giấu sau hàm giải mã string vẫn giải được.

```
[HIGH] CR-AUTO-DECRYPT — Dữ liệu mã hóa giải được bằng key hardcode
  📄 sources/sg/vantagepoint/uncrackable1/a.java:12  → a.a()   ●●● hành vi
     match: 'I want to believe'
     ℹ   thuật toán: AES-128/ECB/PKCS5Padding
     ℹ   key: '8d127684cbc37c17616d806cf50473cc' (hex)
```

Chưa hỗ trợ: GCM/CTR, key/ciphertext dạng mảng `byte[]` (fill-array-data), key derive bằng PBKDF2, RC4.

## Phân tích luồng dữ liệu (rules/flows.yaml)

Khác `combo` (chỉ cần 2 API nằm gần nhau trong call graph), rule `flow` chỉ báo khi **chính giá trị**
đọc từ nguồn đi tới đối số của API đích:

```
[!] FLOW-PRIVACY-LEAK  Dữ liệu riêng tư chảy ra ngoài
     ℹ   Nguồn: SmsMessage.getMessageBody() @ SmsReceiver.onReceive
     ℹ   Đường dữ liệu: SmsReceiver.onReceive → Net.post
     ℹ   Đích: OutputStream.write() @ Net.post
```

Cách làm: dựng IR từ bytecode → call graph CHA (dispatch ảo/interface, `invoke-super`, callback framework,
handler `android:onClick` trong layout, AsyncTask, `Method.invoke` đã giải được) → phân tích từng method theo
thứ tự ngược (callee trước), sinh **summary** (tham số → return / sink / field), lặp tới điểm bất động.
Có mô hình cho StringBuilder/collection, SharedPreferences/Bundle (theo key), exception, gấp hằng số và
bỏ nhánh chết. Để giảm báo nhầm:
- **Container theo key/chỉ số**: `map.put("imei", id); map.get("name")`, JSONObject, ContentValues, Bundle, mảng có
  chỉ số hằng (kể cả mảng lưu trong field) không bị coi là bẩn; dùng cả object (`json.toString()`) thì vẫn bẩn.
- **List theo thứ tự `add`** (biến cục bộ): `l.add("a"); l.add(id); l.get(0)` không bẩn. Qua vòng lặp, `remove`
  hay `add(i, x)` thì không còn biết thứ tự nên coi cả list là bẩn.
- **Exception**: giá trị bẩn trong exception ném ra khỏi method đi tới đúng `catch` bao quanh lời gọi ở method gọi.
  Mỗi `catch` có kho riêng, nên exception được bắt ngay trong method con không làm bẩn `catch` khác.
- **SharedPreferences / Bundle**: `getString(k)` với key không phải hằng (duyệt `getAll()`, listener
  `onSharedPreferenceChanged`) đọc được mọi key. `onSaveInstanceState` → `onRestoreInstanceState` cũng được nối.
- **Gấp hằng chuỗi** cho reflection: `StringBuilder.reverse()`, `substring`, `replace`, `toLowerCase`...
  (`"dIeciveDteg"` đảo ngược thành `getDeviceId`, rồi `Method.invoke` được coi là nguồn).
- **Dispatch theo kiểu thật**: `Provider p = factory(); p.get()` chỉ gọi hiện thực của object mà factory thực sự tạo.
- **Opaque predicate**: khoảng giá trị (`nextInt(n)` ∈ [0, n-1], `length()` ≥ 0) để bỏ nhánh `if`/`switch` không bao giờ chạy. Để chạy nhanh: chỉ phân tích code app (không thư viện), chỉ lát cắt quanh nguồn/đích, có ngân sách thời gian.

Kiểm tra trên DroidBench (177 APK, mức app):

| Cách | Precision | Recall | F1 |
|---|---|---|---|
| combo cũ | 0.78 | 0.63 | 0.69 |
| flow, chưa có JNI | 0.93 | 0.86 | 0.89 |
| flow + JNI | 0.94 | 0.89 | 0.91 |
| + exception, list, prefs, gấp hằng chuỗi (v0.3) | 0.94 | 0.93 | 0.93 |

**Luồng giữa các component (ICC).** Tool theo dõi đích của Intent: `new Intent(ctx, B.class)`, `setClass`,
`setClassName`, `setComponent`, `X.class.getName()`, `obj.getClass()`, hoặc action khớp `<intent-filter>`.
Dữ liệu `putExtra` ở A sẽ xuất hiện lại ở `getIntent()` / `onReceive(.., intent)` / `onStartCommand(intent, ..)` của B.
Messenger/Handler (`send(msg)` → `handleMessage`) cũng được nối.
- Phân biệt key: `putExtra("imei", x)` chỉ đi tới `getStringExtra("imei")`, không tới `getStringExtra("title")`.
- Receiver đăng ký lúc chạy: `registerReceiver(new R(), new IntentFilter("ACTION"))` (bỏ qua nếu có `RECEIVER_NOT_EXPORTED`).
- `startActivityForResult(A → B)` + `setResult` trong B → `onActivityResult` của A (đúng cặp).
- `setPackage(getPackageName())` = Intent chỉ trong app; `setResult` trong component không exported không bị coi là rò rỉ.
- Intent tường minh tới component nội bộ không còn bị báo là "rò rỉ" ở `startActivity`; tool theo tiếp sang B.
- Đích không có trong manifest thì bỏ, vì Android không khởi chạy được component đó.
- Không rõ đích (Intent đi qua list/tham số) thì vẫn báo ở chỗ gửi, và đi tiếp tới mọi component của app với ghi chú "Intent không rõ đích".
- Với rule pentest, Intent chỉ được coi là "dữ liệu do app khác gửi" khi component **exported**. Component nội bộ chỉ bị báo nếu
  dữ liệu được chuyển tới từ một component exported:
  `EntryActivity.onCreate ⇢(Intent: EntryActivity.onCreate+0x32 → WorkerService) → WorkerService.onStartCommand`.

DroidBench nhóm ICC: 21/27 app ra được đích thật bên component nhận (trước: 5/27).

**Luồng qua JNI (Java ↔ native).** Mỗi method `native` được nối với hàm hiện thực: export `Java_*` (cả bản overload
`__sig`) hoặc `RegisterNatives` trong `JNI_OnLoad` (tìm bằng giả lập, kể cả hàm static đã strip). Từ mã máy, tool lấy:
- **method Java mà native gọi qua JNI**: ghép chuỗi tên + chữ ký đứng cạnh nhau (`"getDeviceId"`, `"()Ljava/lang/String;"`),
  class lấy từ chuỗi `FindClass` gần nhất. Nếu app có method trùng tên + chữ ký thì cũng coi là đích, vì `GetObjectClass` không để lại chuỗi;
- **hàm libc tới được** (3 tầng call graph): `send/write/fwrite/__android_log_print...`, `system/popen/exec*`.

Khi Java gọi method native, tool xấp xỉ bằng một "bể dữ liệu" gồm:
- đối số của method native;
- **nguồn mà native tự đọc** (vd `getDeviceId` qua JNI);
- giá trị trả về của **method Java mà native gọi ngược**. Các method này được phân tích như đích gọi thật: đối số của chúng lấy từ bể.

Bể chảy vào đích native gọi tới (`SmsManager.sendTextMessage` qua JNI hoặc `native.libc.send`) và vào giá trị trả về:
```
match: getDeviceId() ⟶ native.libc.sendto
  Đích nằm trong mã native: libt7.so!sub_1102c gọi native.libc.sendto (hàm libc) ...
  Hook: Interceptor.attach(Process.getModuleByName('libt7.so').base.add(0x1102c), ...)
Đường dữ liệu: MainActivity.onCreate ⇢(JNI: libt7.so!Java_..._relay gọi ngược) → MainActivity.onData
```
Bên trong mã máy không theo từng thanh ghi: mọi đối số coi như tới được mọi đích mà hàm native gọi tới.
DroidBench nhóm Native: 5/5 (trước: 1/5).

Rule: `FLOW-PRIVACY-LEAK`, `FLOW-RCE`, `FLOW-SQLI`, `FLOW-WEBVIEW-LOAD`, `FLOW-PATH-TRAVERSAL`, `FLOW-INTENT-REDIRECT`.
Đích native dùng chữ ký giả `Lnative/libc;-><hàm>()V`, nên có thể thêm vào `sink:` của rule.

## Cổng chặn (🔒) và logic bomb

Malware hay giấu hành vi sau một điều kiện: không chạy trên máy ảo, chỉ chạy sau ngày X hoặc sau N ngày kể từ khi
cài, chỉ chạy khi nhận đúng lệnh C2, hoặc chỉ ở một số nước. Phân tích luồng là tĩnh nên vẫn thấy hành vi phía sau.
Ngoài ra rdict chỉ ra **điều kiện phải đúng để tới được đó**:

```
📄 Net.java:14  → com.rdict.t9.Net.post()   ●●● hành vi
   match: getSimSerialNumber() ⟶ java.io.OutputStream.write
   🔒 cần 🛡 !Env.isEmulator()                                              [MainActivity.onCreate]
   🔒 cần ⏰ (System.currentTimeMillis() - ...firstInstallTime) > 259200000 [MainActivity.onCreate]
   🔒 cần 🌍 !this.getSystemService("phone").getSimCountryIso().equals("ru") [MainActivity.onCreate]
```

- **Cách tìm** (`rdict_core/gates.py`): một `if` chặn lệnh L khi chỉ một nhánh của nó tới được L, và L không quay lại
  được `if` đó (bỏ qua điều kiện vòng lặp). Xét trong method chứa L và tại các chỗ gọi dọc đường từ entry point
  (với luồng dữ liệu thì dọc đường dữ liệu, kể cả điều kiện quanh chỗ đọc nguồn). Có nhiều chỗ gọi thì chỉ giữ điều
  kiện chung cho mọi chỗ gọi.
- **Dựng biểu thức**: lùi ngược trong block và predecessor để ghép lời gọi, hằng, field, `cmp-long`, phép toán.
  Biểu thức được in ở chiều cần thỏa.
- **Phân loại**:
  - 🛡 env: root/emulator/debug/Frida. Với method bị obfuscate như `c.a()`, xét thân hàm: chuỗi `su`, `test-keys`,
    `Build.TAGS`...
  - ⏰ time, 🌍 geo.
  - 🔑 secret: dữ liệu vào (SMS, JSON, extra, ô nhập...) so với chuỗi hằng.
  - ⚙ other.
  - Bỏ qua null-check và `SDK_INT`.

Rule mới dùng cùng engine:

| Rule | Bắt gì |
|---|---|
| `BHV-TIME-BOMB` | so `currentTimeMillis`/`Calendar`/`Date` với mốc 2014–2040, hoặc `now - firstInstallTime > N` (không báo throttle kiểu `now - last > 1h`) |
| `BHV-SECRET-GATE` | dữ liệu từ ngoài `.equals/startsWith/...("hằng")`: bảng lệnh C2, mật khẩu ẩn, mã kích hoạt (so trên hash thì ghi rõ) |
| `BHV-GEO-GATE` | `getSimCountryIso`/`Locale`/`TimeZone` so với hằng |

**Mở khóa trên thiết bị**: `--gate-script` sinh script Frida ép mọi cổng 🔒 trong báo cáo về phía mở khóa.

```bash
rdict app.apk --gate-script gates.js
frida -U -f <pkg> -l gates.js
```

| Loại cổng | Script làm gì |
|---|---|
| method boolean của app (`isEmulator`, `c.a()`...) | trả về giá trị cần |
| `String.equals("hằng")` | trả `true` |
| `getSimCountryIso`/`getCountry` | trả mã nước cần |
| `currentTimeMillis` | kẹp sau mốc thời gian, hoặc cộng thêm N ms cho kiểu trì hoãn sau khi cài |

Cổng ⚙ other được để dạng comment, bỏ comment nếu muốn ép. Class nạp muộn (payload) được thử hook lại.

## Payload DEX ẩn (dropper / packer)

Khi nạp APK, rdict đọc 8 byte đầu của **mọi** file (không xét đuôi, vì payload hay đội lốt `.png`/`.bin`). Các dạng tìm được:
- DEX trần;
- zip/jar/apk chứa DEX (lồng tối đa 2 tầng);
- DEX/zip bị **XOR 1 byte** (key tự suy ra từ magic).

Class trong payload được nạp chung vào bộ phân tích với code chính. Vì vậy call graph, CHA, reflection (`loadClass("…").getMethod("run").invoke`), luồng dữ liệu
và mọi rule khác đều chạy xuyên qua code được nạp động:
```
[HIGH] OB-PAYLOAD-DEX   assets/data.bin → 1 class
     ℹ Payload: assets/data.bin (1396 byte, giải XOR 1 byte (key 0x5a)), 1 class — gói: com.evil
[HIGH] FLOW-PRIVACY-LEAK  com.evil.Stealer.run()
     ↳ đường gọi: MainActivity.onCreate → ⇢(reflection) Stealer.run
     ℹ 📦 Code nằm trong payload ẩn assets/data.bin (nạp động lúc chạy)
```
DroidBench nhóm DynamicLoading: 4/4 (trước: 2/4). Payload mã hóa mạnh hơn (AES, nén tùy biến) thì không giải tĩnh được:
dùng Frida hook `DexClassLoader` để dump.

## Giả lập native (unicorn)

- `NAT-INIT-DECRYPT`: chuỗi xuất hiện trong `.data/.bss` sau khi chạy `.init_array`/`JNI_OnLoad` (string được giải mã lúc nạp).
- `NAT-STACK-STRING`: chuỗi được dựng từng byte trên stack (không nằm sẵn trong file).
- `NAT-CMP-CONST`: đối số thật của `strcmp/strncmp/strstr/memcmp/fopen...`, ví dụ UnCrackable L2 → `strncmp(…, 'Thanks for all the fish')`.
- `NAT-REGISTER-NATIVES`: method Java ↔ hàm native đăng ký động; `NAT-JNI-BRIDGE` cũng dùng kết quả này.

Kiểm thử: `tests/regress.sh` (build app test t2–t9 rồi kiểm tra rule mong đợi; t7 cần `pip install ziglang` trong
`.venv` để biên dịch chéo `libt7.so` arm64), `tests/flowtags.py app.apk [-v]` (liệt kê luồng theo tag, `-v` in tóm tắt JNI),
`bench/run.py out.json` (`NO_NATIVE=1` để tắt nạp lib native)
(DroidBench, clone vào `~/.cache/rdict/bench/DroidBench`; `bench/dbg.py <app>` để xem chi tiết luồng), `tests/flowtags.py <apk>` (liệt kê luồng theo tag của sink).

## Viết rule

```yaml
rules:
  - id: MY-001
    name: Tên kỹ thuật
    category: Anti-Analysis
    severity: high                     # info | low | medium | high
    mitre: [T1622]
    target: [code, native]             # code | manifest | resource | native | filelist
    description: ...
    hint: Cách phân tích / bypass

    # --- engine dex (bytecode) ---
    api:     ['Landroid/os/Debug;->isDebuggerConnected']   # chữ ký method được invoke
    strings: ['^/proc/self/status$']                       # hằng const-string
    fields:  ['Landroid/os/Build;->TAGS']                  # field get/put
    in_method: '^onReceivedSslError$'                      # (tuỳ chọn) chỉ trong method tên khớp
    combo:                                                 # hành vi: mọi nhóm phải cùng luồng gọi
      depth: 2                                             # cách nhau tối đa N tầng gọi
      groups:
        - label: Đọc SMS
          items: ['api:Landroid/telephony/SmsMessage;->getMessageBody', 'str:^content://sms']
        - label: Gửi đi
          items: ['api:Ljava/net/URL;->openConnection']

    # --- engine native (ELF) ---
    imports: ['^ptrace$']              # ra call site thật + hàm chứa + đường gọi
    exports: ['^Java_']

    # --- engine text (fallback / manifest / resource / strings .so) ---
    any: ['Debug\.isDebuggerConnected']
    all: ['...']                       # file phải chứa tất cả
    exclude: ['res/values-[\w-]+/']    # bỏ hit có file/class khớp

    # --- luồng dữ liệu ---
    flow:
      source: ['api:<regex chữ ký>',   # giá trị trả về là nguồn
               'cb:<regex chữ ký>',    # tham số callback override method framework này
               'field:<regex field>']  # đọc field này
      sink:   ['<regex chữ ký>']       # đối số bị bẩn khi gọi API này -> báo
```

Builtin (logic Python, không viết được bằng regex): `reflection`, `string_decryptor`, `insecure_tls`,
`jni_bridge`, `crypto_autodecrypt`, `exported_components`, `native_init_array`, `native_entropy`, `native_stripped`,
`native_cmp_const`, `native_stack_strings`, `native_init_decrypt`, `native_register_natives`, `payload_dex`, `gate_time`, `gate_secret`, `gate_geo`.

## Hạn chế / hướng phát triển

- Phân tích luồng: không theo luồng ngầm (`if (imei.startsWith("3")) send("1")`). ICC: Intent tạo bằng reflection
  (`Constructor.newInstance`) hoặc lấy ra từ list/tham số thì không rõ đích; Bundle trong extra (`getExtras().getString(k)`)
  chưa phân biệt key; chưa nối luồng giữa 2 app khác nhau. List lưu trong field chưa phân biệt phần tử; field vẫn
  không phân biệt object (2 object cùng class dùng chung field); thứ tự đọc/ghi field không được xét. Code nạp động chỉ theo được khi payload nằm sẵn trong APK (dạng trần, zip hoặc XOR 1 byte); native chỉ xấp xỉ
  (xem phần JNI): chuỗi tên method bị mã hóa trong `.so` thì không ghép được, trừ khi giả lập dựng ra trên stack.
  App lớn có thể chạm ngân sách thời gian (báo cáo ghi "truncated").
- Cổng chặn: điều kiện qua `switch` (kể cả `switch` trên String), qua biến cờ lưu vào field, hoặc nằm trong native thì
  chưa dựng được. Script chỉ ép được method boolean, `equals` với hằng, getter quốc gia và đồng hồ. So khớp trên hash
  thì không đảo ngược tĩnh được.
- Giả lập native: quét tuyến tính từng hàm, không giải điều kiện; hàm cần dữ liệu từ Java/thiết bị có thể không ra chuỗi.
  Giả lập chưa hỗ trợ ARM32 (phân tích tĩnh ARM32 thì có).
- Native: ABI ưu tiên arm64 → armv7 → armeabi → x86_64 → x86 (khi bench/test tự giải nén lib).
- Giải mã string Java không chuẩn cần thiết bị + Frida; chưa hỗ trợ tham số mảng.
- Chưa có: hỗ trợ IPA/PE/ELF Linux, rule YARA cho native.
