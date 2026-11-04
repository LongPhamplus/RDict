package com.rdict.t5;
import android.app.Activity; import android.content.Intent; import android.os.Bundle; import android.telephony.TelephonyManager;
public class LeakActivity extends Activity {
    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        TelephonyManager tm = (TelephonyManager) getSystemService(TELEPHONY_SERVICE);
        Intent i = new Intent("com.rdict.t5.UPLOAD");
        i.setClass(this, UploadReceiver.class);
        i.putExtra("id", tm.getDeviceId());
        sendBroadcast(i);
        Intent show = new Intent(this, ShowActivity.class);     // an toàn: chỉ hiển thị
        show.putExtra("id", tm.getDeviceId());
        startActivity(show);
        Intent ghost = new Intent(this, GhostActivity.class);   // không có trong manifest
        ghost.putExtra("id", tm.getDeviceId());
        startActivity(ghost);
    }
}
