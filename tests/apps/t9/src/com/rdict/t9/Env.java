package com.rdict.t9;

import android.os.Build;

public class Env {
    public static boolean isEmulator() {
        return Build.FINGERPRINT.contains("generic") || Build.MODEL.contains("sdk");
    }
}
