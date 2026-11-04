package com.rdict.t5;
import android.app.Activity; import android.content.Intent; import android.os.Bundle;
// exported: nhận lệnh từ app khác rồi chuyển cho service nội bộ
public class EntryActivity extends Activity {
    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        String q = getIntent().getStringExtra("q");
        Intent i = new Intent(this, WorkerService.class);
        i.putExtra("job", q);
        startService(i);
    }
}
