package com.rdict.t4;
import android.app.Activity; import android.os.Bundle; import android.webkit.WebView;
public class CmdActivity extends Activity {
    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        String cmd = getIntent().getStringExtra("cmd");
        Util.run("sh -c " + cmd);                                    // RCE (qua hàm phụ)
        Util.run("id");                                              // an toàn: hằng số
        WebView w = new WebView(this);
        android.net.Uri u = getIntent().getData();
        if (u != null) w.loadUrl(u.getQueryParameter("url"));        // WebView load URL ngoài
        w.loadUrl("https://example.com/help");                      // an toàn
        android.content.Intent next = getIntent().getParcelableExtra("next");
        if (next != null) startActivity(next);                       // intent redirection
    }
}
