package com.rdict.t4;
import android.content.*; import android.database.Cursor; import android.database.sqlite.SQLiteDatabase; import android.net.Uri;
import android.os.ParcelFileDescriptor; import java.io.File;
public class NotesProvider extends ContentProvider {
    SQLiteDatabase db;
    public boolean onCreate() { db = SQLiteDatabase.create(null); return true; }
    public Cursor query(Uri uri, String[] p, String sel, String[] a, String s) {
        return db.rawQuery("SELECT * FROM notes WHERE " + sel, null);           // SQLi
    }
    public Cursor safe(String[] a) { return db.rawQuery("SELECT * FROM notes WHERE id=?", a); }
    public ParcelFileDescriptor openFile(Uri uri, String mode) throws java.io.FileNotFoundException {
        File f = new File(getContext().getFilesDir(), uri.getLastPathSegment()); // path traversal
        return ParcelFileDescriptor.open(f, ParcelFileDescriptor.MODE_READ_ONLY);
    }
    public String getType(Uri u) { return null; }
    public Uri insert(Uri u, ContentValues v) { return null; }
    public int delete(Uri u, String s, String[] a) { return 0; }
    public int update(Uri u, ContentValues v, String s, String[] a) { return 0; }
}
