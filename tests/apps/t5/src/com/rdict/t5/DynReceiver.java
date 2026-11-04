package com.rdict.t5;
import android.content.*;
public class DynReceiver extends BroadcastReceiver {
    @Override public void onReceive(Context c, Intent in) {
        android.util.Log.w("t5", in.getStringExtra("v"));   // rò rỉ qua receiver động
    }
}
