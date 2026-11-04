"""Sinh source app test t3."""
import os
os.makedirs("src/com/rdict/t3", exist_ok=True)
import base64,hashlib,os
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
def enc(alg,mode,pt,bs):
    p=padding.PKCS7(bs*8).padder(); d=p.update(pt.encode())+p.finalize()
    e=Cipher(alg,mode).encryptor(); return e.update(d)+e.finalize()
b64=lambda b: base64.b64encode(b).decode()
iv=b"0102030405060708"
c1=b64(enc(algorithms.AES(b"Sup3rS3cr3tK3y!!"),modes.CBC(iv),"http://c2.evil-panel.top/api/v2",16))
k2=hashlib.sha256(b"malw4re_pass").digest()
c2=b64(enc(algorithms.AES(k2),modes.ECB(),'{"bot":"7712:AAx","admin":"root"}',16))
riv=os.urandom(16); k3=bytes.fromhex("00112233445566778899aabbccddeeff")
c3=(riv+enc(algorithms.AES(k3),modes.CBC(riv),"FLAG{iv_prepended}",16)).hex()
c4=b64(enc(TripleDES(b"12345678"*3),modes.ECB(),"des-secret",8))
wrong=b64(enc(algorithms.AES(b"AnotherKey123456"),modes.ECB(),"should not decrypt",16))
plain=b64(b"just some normal base64 data here!!!!!!!")[:44]
java=f'''package com.rdict.t3;
import javax.crypto.Cipher; import javax.crypto.spec.*; import android.util.Base64;
public class Cfg {{
    static byte[] aes(byte[] k, byte[] iv, byte[] d, String t) throws Exception {{
        Cipher c = Cipher.getInstance(t);
        if (iv == null) c.init(2, new SecretKeySpec(k, "AES")); else c.init(2, new SecretKeySpec(k, "AES"), new IvParameterSpec(iv));
        return c.doFinal(d);
    }}
    public static String c2() throws Exception {{ return new String(aes("Sup3rS3cr3tK3y!!".getBytes(), "0102030405060708".getBytes(), Base64.decode("{c1}", 0), "AES/CBC/PKCS5Padding")); }}
    public static String conf() throws Exception {{
        byte[] k = java.security.MessageDigest.getInstance("SHA-256").digest("malw4re_pass".getBytes());
        return new String(aes(k, null, Base64.decode("{c2}", 0), "AES/ECB/PKCS5Padding"));
    }}
    static byte[] hex(String s) {{
        byte[] o = new byte[s.length() / 2];
        for (int i = 0; i < o.length; i++) o[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        return o;
    }}
    public static String flag() throws Exception {{   // IV nằm ở 16 byte đầu ciphertext
        byte[] all = hex("{c3}");
        byte[] iv = java.util.Arrays.copyOfRange(all, 0, 16);
        return new String(aes(hex("00112233445566778899aabbccddeeff"), iv, java.util.Arrays.copyOfRange(all, 16, all.length), "AES/CBC/PKCS5Padding"));
    }}
    public static String des() throws Exception {{
        Cipher c = Cipher.getInstance("DES/ECB/PKCS5Padding"); c.init(2, new SecretKeySpec("12345678".getBytes(), "DES"));
        return new String(c.doFinal(Base64.decode("{c4}", 0)));
    }}
    public static String neg() throws Exception {{ return new String(aes("Sup3rS3cr3tK3y!!".getBytes(), null, Base64.decode("{wrong}", 0), "AES") ) + "{plain}"; }}
}}'''
open("src/com/rdict/t3/Cfg.java","w").write(java)
open("src/com/rdict/t3/MainActivity.java","w").write('''package com.rdict.t3;
public class MainActivity extends android.app.Activity {
    @Override protected void onCreate(android.os.Bundle b) { super.onCreate(b);
        try { Cfg.c2(); Cfg.conf(); Cfg.flag(); Cfg.des(); Cfg.neg(); } catch (Exception e) {} }
}''')
open("AndroidManifest.xml","w").write('''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.rdict.t3">
  <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="34"/>
  <application android:label="t3"><activity android:name=".MainActivity" android:exported="true"/></application>
</manifest>''')
