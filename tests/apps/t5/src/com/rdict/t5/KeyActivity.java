package com.rdict.t5;
import android.app.Activity; import android.content.*; import android.os.Bundle; import android.telephony.TelephonyManager;
// Key extra: chỉ "imei" bị bẩn, "title" là hằng -> chỉ 1 luồng
public class KeyActivity extends Activity {
    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        TelephonyManager tm = (TelephonyManager) getSystemService(TELEPHONY_SERVICE);
        Intent i = new Intent(this, KeySink.class);
        i.putExtra("imei", tm.getDeviceId());
        i.putExtra("title", "hello");
        startActivity(i);
        // receiver đăng ký động
        registerReceiver(new DynReceiver(), new IntentFilter("com.rdict.t5.DYN"));
        Intent d = new Intent("com.rdict.t5.DYN");
        d.setPackage(getPackageName());
        d.putExtra("v", tm.getSimSerialNumber());
        sendBroadcast(d);
        // kết quả trả về
        startActivityForResult(new Intent(this, PickActivity.class), 7);
    }
    @Override protected void onActivityResult(int req, int res, Intent data) {
        android.util.Log.d("t5", data.getStringExtra("picked"));   // rò rỉ: PickActivity trả về số SIM
    }
}
