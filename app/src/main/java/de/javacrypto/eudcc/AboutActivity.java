package de.javacrypto.eudcc;

import android.os.Bundle;
import android.text.method.LinkMovementMethod;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

public class AboutActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_about);
        TextView tv = (TextView) findViewById(R.id.appVersion);
        tv.setText(getResources().getString(R.string.appVersionData));
        TextView tv3 = (TextView) findViewById(R.id.projectpage);
        tv3.setMovementMethod(LinkMovementMethod.getInstance());
        TextView tv4 = (TextView) findViewById(R.id.sourcecodepage);
        tv4.setMovementMethod(LinkMovementMethod.getInstance());
    }
}