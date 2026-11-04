package com.rdict.t7;
import android.app.Activity; import android.content.Context; import android.os.Bundle;
import android.telephony.TelephonyManager; import android.util.Log;
// App test JNI flow: tag X_..._LEAK phải bị báo, X_..._SAFE thì không (xem tests/flowtags.py)
public class MainActivity extends Activity {
    static { System.loadLibrary("t7"); }
    static native void up(String tag, String data);          // A: native gửi qua socket (libc send)
    native boolean sms(String tag, String msg);               // B: native gọi SmsManager.sendTextMessage qua JNI
    native String imei(Context c);                            // C: native tự đọc getDeviceId qua JNI
    static native boolean check(String tag, String s);        // D: native chỉ strcmp, không gửi đi đâu
    native void relay(String tag);                            // E: native đọc IMEI rồi gọi ngược onData()
    static native void z(String tag, String s);               // F: đăng ký động (RegisterNatives), sendto
    native void relay2(String tag);                           // G: native gọi ngược onSafe() với hằng

    public void onData(String s) { Log.i("E_CALLBACK_LEAK", s); }
    public void onSafe(String s) { Log.i("G_CALLBACK_SAFE", s); }

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        String id = ((TelephonyManager) getSystemService(TELEPHONY_SERVICE)).getDeviceId();
        up("A_LIBC_LEAK", id);
        sms("B_JNI_SINK_LEAK", id);
        Log.i("C_SRC_NATIVE_LEAK", imei(this));
        if (check("D_NOSINK_SAFE", id)) setTitle("x");
        relay("E_RELAY");
        z("F_REGNAT_LEAK", id);
        relay2("G_RELAY");
    }
}
