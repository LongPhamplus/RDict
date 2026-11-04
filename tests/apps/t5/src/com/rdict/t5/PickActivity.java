package com.rdict.t5;
import android.app.Activity; import android.content.Intent; import android.os.Bundle; import android.telephony.TelephonyManager;
public class PickActivity extends Activity {
    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        TelephonyManager tm = (TelephonyManager) getSystemService(TELEPHONY_SERVICE);
        Intent r = new Intent(); r.putExtra("picked", tm.getLine1Number());
        setResult(RESULT_OK, r); finish();
    }
}
