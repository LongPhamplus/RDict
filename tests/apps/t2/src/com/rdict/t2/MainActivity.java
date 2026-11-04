package com.rdict.t2;
import android.app.Activity; import android.os.Bundle; import android.widget.TextView;
public class MainActivity extends Activity {
    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        StringBuilder sb = new StringBuilder("rdict test2\n");
        sb.append("rooted=").append(RootCheck.isRooted()).append("\n");
        sb.append("frida=").append(AntiHook.scan()).append("\n");
        try {
            Class<?> c = Class.forName(Z.a("e3NldTt6dnZ+NElpc2p2TUQ=", 17));
            Object rt = c.getMethod(Z.a("TU5Yf1tBRFhfVg==", 42)).invoke(null);
            java.lang.reflect.Method m = c.getMethod(Z.a("BhwABQ==", 99), String.class);
            sb.append("resolved=").append(m.getName()).append("\n");
            Crypt.make();
            if (System.currentTimeMillis() < 0) C2.send("x");
        } catch (Exception e) { sb.append(e); }
        android.util.Log.d(Z.a("dzY=", 3), sb.toString());
        TextView t = new TextView(this); t.setText(sb); setContentView(t);
    }
}