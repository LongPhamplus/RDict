package com.rdict.t5;
import android.app.Activity; import android.os.Bundle; import android.widget.TextView;
public class ShowActivity extends Activity {
    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        TextView t = new TextView(this); t.setText(getIntent().getStringExtra("id")); setContentView(t);
    }
}
