package com.rdict.t6;
import android.app.Activity; import android.os.Bundle; import android.telephony.TelephonyManager; import android.util.Log;
import java.util.*; import org.json.JSONObject;
public class MainActivity extends Activity {
    static String[] slots = new String[3];
    interface Provider { String get(MainActivity a); }
    static class SafeP implements Provider { public String get(MainActivity a) { return "const"; } }
    static class ImeiP implements Provider {
        public String get(MainActivity a) { return ((TelephonyManager) a.getSystemService(TELEPHONY_SERVICE)).getDeviceId(); }
    }
    static Provider safe() { return new SafeP(); }
    String leakId() { throw new IllegalStateException(((TelephonyManager) getSystemService(TELEPHONY_SERVICE)).getDeviceId()); }
    String safeThrow() { try { throw new RuntimeException(((TelephonyManager) getSystemService(TELEPHONY_SERVICE)).getDeviceId()); }
                         catch (RuntimeException e) { return "ok"; } }
    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        String id = ((TelephonyManager) getSystemService(TELEPHONY_SERVICE)).getDeviceId();
        Map<String, String> m = new HashMap<>();
        m.put("imei", id); m.put("name", "bob");
        Log.i("A_MAP_SAFE", m.get("name"));            // không rò rỉ
        Log.i("B_MAP_LEAK", m.get("imei"));            // rò rỉ
        try {
            JSONObject j = new JSONObject();
            j.put("ver", "1.0"); j.put("dev", id);
            Log.i("C_JSON_SAFE", j.getString("ver"));  // không rò rỉ
            new java.net.URL("http://x.example/?" + j.toString());   // rò rỉ (cả object)
        } catch (Exception e) { }
        slots[0] = "hello"; slots[1] = id;
        Log.w("D_ARR_SAFE", slots[0]);                 // không rò rỉ
        Log.w("E_ARR_LEAK", slots[1]);                 // rò rỉ
        Log.e("F_FACTORY_SAFE", safe().get(this));     // không rò rỉ: chỉ SafeP
        Random r = new Random();
        if (r.nextInt(10) > 20) Log.d("H_OPAQUE_SAFE", id);          // không bao giờ chạy
        switch (r.nextInt(3)) { case 7: Log.d("I_SWITCH_SAFE", id); break; default: break; }
        if (r.nextInt(10) < 5) Log.d("J_RANGE_LEAK", id);            // có thể chạy -> rò rỉ
        List<String> l = new ArrayList<>();
        l.add("first"); l.add(id); l.add("third");
        Log.v("K_LIST_SAFE", l.get(0));                // không rò rỉ: phần tử 0 là hằng
        Log.v("L_LIST_LEAK", l.get(1));                // rò rỉ
        List<String> q = new ArrayList<>();
        for (int i = 0; i < 3; i++) q.add(i == 1 ? id : "x");
        Log.v("M_LOOP_LEAK", q.get(0));                // qua vòng lặp: không biết chỉ số -> vẫn báo
        try { leakId(); } catch (IllegalStateException e) { Log.e("N_EXC_LEAK", e.getMessage()); }
        try { safeThrow(); } catch (RuntimeException e) { Log.e("O_EXC_SAFE", e.getMessage()); }
        android.content.SharedPreferences sp = getSharedPreferences("s", 0);
        sp.edit().putString("dev", id).apply();
        for (String k : sp.getAll().keySet()) Log.d("P_PREFS_LEAK", sp.getString(k, ""));
        try {
            String mn = new StringBuilder("dIeciveDteg").reverse().toString();
            Object tm = getSystemService(TELEPHONY_SERVICE);
            Object v = Class.forName("android.telephony.TelephonyManager").getMethod(mn).invoke(tm);
            Log.d("Q_REFL_LEAK", (String) v);
        } catch (Exception e) { }
        Provider p = new ImeiP();
        Log.e("G_DISPATCH_LEAK", p.get(this));         // rò rỉ
    }
}
