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
| **native** | lief + capstone | Imports/exports thật. Phân giải PLT nên ra **call site** của `ptrace`, `strstr`... Xref chuỗi (`adrp+add`, `lea [rip+x]`). Call graph native gồm cả con trỏ hàm (`pthread_create(.., fn)`). Root: `JNI`, `JNI_OnLoad`, `.init_array`. Entropy, section header bị xóa. | ●●○ |
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
bỏ nhánh chết. Để chạy nhanh: chỉ phân tích code app (không thư viện), chỉ lát cắt quanh nguồn/đích, có ngân sách thời gian.

Kiểm tra trên DroidBench (177 APK, mức app):

| Cách | Precision | Recall | F1 |
|---|---|---|---|
| combo cũ | 0.78 | 0.63 | 0.69 |
| flow (v0.3) | 0.88 | 0.85 | 0.86 |

Rule: `FLOW-PRIVACY-LEAK`, `FLOW-RCE`, `FLOW-SQLI`, `FLOW-WEBVIEW-LOAD`, `FLOW-PATH-TRAVERSAL`, `FLOW-INTENT-REDIRECT`.

## Giả lập native (unicorn)

- `NAT-INIT-DECRYPT`: chuỗi xuất hiện trong `.data/.bss` sau khi chạy `.init_array`/`JNI_OnLoad` (string được giải mã lúc nạp).
- `NAT-STACK-STRING`: chuỗi được dựng từng byte trên stack (không nằm sẵn trong file).
- `NAT-CMP-CONST`: đối số thật của `strcmp/strncmp/strstr/memcmp/fopen...`, ví dụ UnCrackable L2 → `strncmp(…, 'Thanks for all the fish')`.
- `NAT-REGISTER-NATIVES`: method Java ↔ hàm native đăng ký động; `NAT-JNI-BRIDGE` cũng dùng kết quả này.

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
`native_cmp_const`, `native_stack_strings`, `native_init_decrypt`, `native_register_natives`.

## Hạn chế / hướng phát triển

- Phân tích luồng: không theo luồng ngầm (`if (imei.startsWith("3")) send("1")`), chưa nối luồng qua ICC
  (Intent giữa các component), field/mảng không phân biệt object/chỉ số (có thể báo dư), code nạp động/native không theo được.
  App lớn có thể chạm ngân sách thời gian (báo cáo ghi "truncated").
- Giả lập native: quét tuyến tính từng hàm, không giải điều kiện; hàm cần dữ liệu từ Java/thiết bị có thể không ra chuỗi.
  Phần init chỉ kiểm thử trên x86_64; chưa hỗ trợ ARM32.
- Native: xref chuỗi chưa hỗ trợ ARM32 Thumb (literal pool). ABI ưu tiên arm64 → x86_64 → armv7.
- Giải mã string Java không chuẩn cần thiết bị + Frida; chưa hỗ trợ tham số mảng.
- Chưa có: hỗ trợ IPA/PE/ELF Linux, rule YARA cho native.
