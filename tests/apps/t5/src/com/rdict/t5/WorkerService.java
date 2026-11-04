package com.rdict.t5;
import android.app.Service; import android.content.Intent; import android.os.IBinder;
public class WorkerService extends Service {
    @Override public int onStartCommand(Intent intent, int flags, int id) {
        String job = intent.getStringExtra("job");
        try { Runtime.getRuntime().exec("sh -c " + job); } catch (Exception e) {}   // RCE qua ICC
        return START_NOT_STICKY;
    }
    @Override public IBinder onBind(Intent i) { return null; }
}
