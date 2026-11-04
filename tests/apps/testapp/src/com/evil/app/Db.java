package com.evil.app;
import android.database.sqlite.SQLiteDatabase; import android.util.Log;
public class Db {
    public static void login(SQLiteDatabase db, String user, String pass) {
        Log.d("auth", "login password=" + pass);
        db.rawQuery("SELECT * FROM users WHERE name='" + user + "' AND pass='" + pass + "'", null);
    }
}