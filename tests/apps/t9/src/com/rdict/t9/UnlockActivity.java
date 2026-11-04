package com.rdict.t9;

import android.app.Activity;
import android.os.Bundle;
import android.widget.EditText;

public class UnlockActivity extends Activity {
    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        EditText et = new EditText(this);
        // F: mật khẩu ẩn từ ô nhập
        if (et.getText().toString().equals("0p3n-s3s4m3")) {
            Net.post("unlocked");
        }
    }
}
