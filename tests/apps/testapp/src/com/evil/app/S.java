package com.evil.app;
public class S {
    public static String d(String s) {
        char[] k = "K3y!".toCharArray();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) sb.append((char) (s.charAt(i) ^ k[i % k.length]));
        return sb.toString();
    }
}