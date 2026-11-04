package com.rdict.t5;
import android.app.Activity; import android.os.Bundle;
public class GhostActivity extends Activity {
    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        android.util.Log.i("t5", getIntent().getStringExtra("id"));
    }
}
