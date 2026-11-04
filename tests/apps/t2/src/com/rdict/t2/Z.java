package com.rdict.t2;
public class Z {
    public static String a(String s, int k) {
        byte[] b = android.util.Base64.decode(s, 0);
        for (int i = 0; i < b.length; i++) b[i] = (byte) (b[i] ^ ((k + i) & 0xff));
        return new String(b, java.nio.charset.StandardCharsets.UTF_8);
    }
}