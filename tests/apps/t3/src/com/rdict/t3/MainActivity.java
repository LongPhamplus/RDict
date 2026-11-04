package com.rdict.t3;
public class MainActivity extends android.app.Activity {
    @Override protected void onCreate(android.os.Bundle b) { super.onCreate(b);
        try { Cfg.c2(); Cfg.conf(); Cfg.flag(); Cfg.des(); Cfg.neg(); } catch (Exception e) {} }
}