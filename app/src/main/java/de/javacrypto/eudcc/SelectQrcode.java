package de.javacrypto.eudcc;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.widget.ArrayAdapter;
import android.widget.Spinner;

import java.io.File;
import java.io.FilenameFilter;

public class SelectQrcode extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_select_qrcode);


        Spinner spinner = (Spinner) findViewById(R.id.spSelectQRcode);
        String path = getApplicationContext().getFilesDir().toString();

//if you want to list from a specific directory you created
//String path = getApplicationContext().getFilesDir().toString()+"/your_Directory";

        File directory = new File(path);
        //File fileList[] = directory.listFiles();
        File fileList[] = directory.listFiles(
                new FilenameFilter() {
                    public boolean accept(File dir, String name) {
                        return name.toLowerCase().endsWith(".eudc");
                    }
                }

        );



        String[] list = new String[fileList.length];
        String[] spinnerList = new String[fileList.length];

        for (int i = 0; i < fileList.length; i++) {
            list[i] = fileList[i].getAbsolutePath().toString();
            spinnerList[i] = list[i].substring(list[i].lastIndexOf("/") + 1);
        }
        ArrayAdapter<String> adapter = new ArrayAdapter<String>(this,
                android.R.layout.simple_spinner_item, spinnerList);
        spinner.setAdapter(adapter);

    }
/*
        File path = getFilesDir();
        String[] arraySpinner = Storage.getAllFiles(path).toArray(new String[0]);
        Spinner s = (Spinner) findViewById(R.id.spSelectQRcode);
        ArrayAdapter<String> adapter = new ArrayAdapter<String>(this,
                android.R.layout.simple_spinner_item, arraySpinner);
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        s.setAdapter(adapter);
    }*/
}