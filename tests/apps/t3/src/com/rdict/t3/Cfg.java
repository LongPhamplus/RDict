package com.rdict.t3;
import javax.crypto.Cipher; import javax.crypto.spec.*; import android.util.Base64;
public class Cfg {
    static byte[] aes(byte[] k, byte[] iv, byte[] d, String t) throws Exception {
        Cipher c = Cipher.getInstance(t);
        if (iv == null) c.init(2, new SecretKeySpec(k, "AES")); else c.init(2, new SecretKeySpec(k, "AES"), new IvParameterSpec(iv));
        return c.doFinal(d);
    }
    public static String c2() throws Exception { return new String(aes("Sup3rS3cr3tK3y!!".getBytes(), "0102030405060708".getBytes(), Base64.decode("Qgmqa3jIWwlBlCdJVJO+UheWJFZeKdxyQeZZHVwilCs=", 0), "AES/CBC/PKCS5Padding")); }
    public static String conf() throws Exception {
        byte[] k = java.security.MessageDigest.getInstance("SHA-256").digest("malw4re_pass".getBytes());
        return new String(aes(k, null, Base64.decode("OBrLJSx3F1XkzERMcDpOSM/w2uZiDu6nCDhr4Ab+5CwfiG0EB5oGqTVJeU+GtLs4", 0), "AES/ECB/PKCS5Padding"));
    }
    static byte[] hex(String s) {
        byte[] o = new byte[s.length() / 2];
        for (int i = 0; i < o.length; i++) o[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        return o;
    }
    public static String flag() throws Exception {   // IV nằm ở 16 byte đầu ciphertext
        byte[] all = hex("496498e474be652dff4f60c99a88789d3503efadb983a5b7e0d54a8cc64db7f199a0da256a46054cf2ec5a19e9eadf4c");
        byte[] iv = java.util.Arrays.copyOfRange(all, 0, 16);
        return new String(aes(hex("00112233445566778899aabbccddeeff"), iv, java.util.Arrays.copyOfRange(all, 16, all.length), "AES/CBC/PKCS5Padding"));
    }
    public static String des() throws Exception {
        Cipher c = Cipher.getInstance("DES/ECB/PKCS5Padding"); c.init(2, new SecretKeySpec("12345678".getBytes(), "DES"));
        return new String(c.doFinal(Base64.decode("1Tu1IeI3MT2L2rH/mF8eMA==", 0)));
    }
    public static String neg() throws Exception { return new String(aes("Sup3rS3cr3tK3y!!".getBytes(), null, Base64.decode("bd+3GZ965GfNgsrzKBVTpCh/UwwB5CZLQSuxSD9ChNA=", 0), "AES") ) + "anVzdCBzb21lIG5vcm1hbCBiYXNlNjQgZGF0YSBoZXJl"; }
}