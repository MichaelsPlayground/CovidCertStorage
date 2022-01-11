package de.javacrypto.eudcc;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.graphics.Typeface;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.ImageButton;
import android.widget.TableLayout;
import android.widget.TableRow;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import com.google.gson.Gson;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.zip.ZipException;

import se.digg.dgc.encoding.Base45;
import se.digg.dgc.encoding.DGCConstants;
import se.digg.dgc.encoding.Zlib;

public class ShowQrcodeDetail extends AppCompatActivity {

    String filenameCertificateDetail;
    String qrcodeFromMainActivity;
    ConstantsClass constantsClass = new ConstantsClass();

    Intent mainIntent;
    static String APP_TAG = "EUDCC";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_show_qrcode_detail);

        mainIntent = new Intent(this, MainActivity.class);
        // important: if filenameCertificateDetail <> "" this activity is called
        // from ShowCertificateOverview
        // if filenameCertificateDetail = "" and qrcodeToCheck <> "" this activity
        // is called from VerifyCertificate

        // get filename
        filenameCertificateDetail = MainActivity.filenameSelected;
        // get qrcode
        qrcodeFromMainActivity = MainActivity.qrcodeToCheck;
        if (!filenameCertificateDetail.equals("")) {
            // do nothing
        }

        if (!qrcodeFromMainActivity.equals("")) {
            dataToView(qrcodeFromMainActivity, false);
        }
    }


    private void dataToView(String data, boolean showCertificateBtn) {
        // data holds the qrcode data

        // strip off the first 4 chars HC1:
        String compressedString = data.substring(DGCConstants.DGC_V1_HEADER.length());
        // base45 decoding
        byte[] base45Decoded = Base45.getDecoder().decode(compressedString); // HEX data
        // dezip data
        byte[] decompressed = new byte[0]; // = cose
        try {
            decompressed = Zlib.decompress(base45Decoded, true);
        } catch (ZipException e) {
            e.printStackTrace();
            Log.e(APP_TAG, "Zip exception: " + e.getMessage());
        }
        // decompressed = cose

        List<Pair> listData = null;
        listData = AnalyzeDigitalVaccinationCertificate.analyzeDigitalVaccinationCertificate3(decompressed);

        DscList dscList;
        if (MainActivity.productionModeEnabledStatic) {
            dscList = decodeDscListData(loadFileFromInternalStorage(constantsClass.getFileNameDscListProd()));
        } else {
            dscList = decodeDscListData(loadFileFromInternalStorage(constantsClass.getFileNameDscListTest()));
        }

        int certificateStatus = VerifyDigitalCovidCertificate.verifyDccSignature(decompressed, dscList);

        // dynamically add the data rows
        // Find Tablelayout defined in main.xml
        TableLayout tl = (TableLayout) findViewById(R.id.tableCertificate);
        // Create a new row to be added.
        TableRow tr = new TableRow(this);
        tr.setLayoutParams(new TableRow.LayoutParams(TableRow.LayoutParams.MATCH_PARENT, TableRow.LayoutParams.WRAP_CONTENT));

        Collections.sort(listData, new PairComparator()); // sort data
        // print header data
        try {
            // header
            tl.addView(addTableRowColorLarge(listData.get(0).getKey(), listData.get(0).getValue(), R.color.black));
            // next 5 lines
            for (int i = 1; i < 5; i++) {
                //System.out.println("entry " + i + " key: " + listData.get(i).getKey() + " value: " + listData.get(i).getValue());
                tl.addView(addTableRow(listData.get(i).getKey(), listData.get(i).getValue()));
            }
        } catch (Exception e) {
            Log.e(APP_TAG, "wrong data structure: " + e.getMessage());
        }

        // print certificateStatus
        tl.addView(addTableRow("Status", String.valueOf(certificateStatus)));
        switch (certificateStatus) {
            case 0: {
                tl.addView(addTableRowColor("Zertifikat\nStatus", "0 Zertifikat konnte nicht\ngeprüft werden", R.color.red));
                break;
            }
            case 1: {
                tl.addView(addTableRowColor("Zertifikat\nStatus", "1 Zertifikat ist gültig\nund nicht abgelaufen", R.color.green));
                break;
            }
            case 2: {
                tl.addView(addTableRowColor("Zertifikat\nStatus", "2 Zertifikat ist ungültig", R.color.red));
                break;
            }
            case 3: {
                tl.addView(addTableRowColor("Zertifikat\nStatus", "3 Zertifikat ist gültig\naber abgelaufen", R.color.orange));
                break;
            }
        }

        // show save button
        ImageButton ibs = new ImageButton(this);
        ibs.setImageResource(R.drawable.ic_outline_save_24);
        ibs.setMinimumHeight(250);
        ibs.setLayoutParams(new TableRow.LayoutParams(TableRow.LayoutParams.MATCH_PARENT, TableRow.LayoutParams.WRAP_CONTENT));
        tl.addView(ibs);
        ibs.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String filename = "";
                String filenameExtension = ".eudc";
                // get filename from dialog
                filename = "m1" + filenameExtension;

                Storage.writeToFile(v.getContext(), filename, data);


                /* old copy to clipboard code
                // copy to clipboard
                // Gets a handle to the clipboard service.
                ClipboardManager clipboard = (ClipboardManager)
                        getSystemService(Context.CLIPBOARD_SERVICE);
                ClipData clip = ClipData.newPlainText("simple text", data);
                // Set the clipboard's primary clip.
                clipboard.setPrimaryClip(clip);
                */

                // back to main activity
                Intent i=new Intent(ShowQrcodeDetail.this, MainActivity.class);
                i.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP);
                startActivity(i);
            }
        });

        // show copy to clipboard button
        ImageButton ib = new ImageButton(this);
        ib.setImageResource(R.drawable.outline_content_paste_black_24);
        ib.setMinimumHeight(250);
        ib.setLayoutParams(new TableRow.LayoutParams(TableRow.LayoutParams.MATCH_PARENT, TableRow.LayoutParams.WRAP_CONTENT));
        tl.addView(ib);
        ib.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                // copy to clipboard
                // Gets a handle to the clipboard service.
                ClipboardManager clipboard = (ClipboardManager)
                        getSystemService(Context.CLIPBOARD_SERVICE);
                ClipData clip = ClipData.newPlainText("simple text", data);
                // Set the clipboard's primary clip.
                clipboard.setPrimaryClip(clip);
                // back to main activity
                Intent i=new Intent(ShowQrcodeDetail.this, MainActivity.class);
                i.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP);
                startActivity(i);
            }
        });

        // print following data
        for (int i = 5; i < listData.size(); i++) {
            tl.addView(addTableRow(listData.get(i).getKey(), listData.get(i).getValue()));
        }
    }

    private TableRow addTableRow(String left, String right) {
        TableRow tr = new TableRow(this);
        tr.setLayoutParams(new TableRow.LayoutParams(TableRow.LayoutParams.MATCH_PARENT, TableRow.LayoutParams.WRAP_CONTENT));
        TextView tvL = new TextView(this);
        tvL.setText(left);
        tvL.setTextSize(18);
        tvL.setTextColor(getResources().getColor(R.color.black));
        tvL.setLayoutParams(new TableRow.LayoutParams(TableRow.LayoutParams.MATCH_PARENT, TableRow.LayoutParams.WRAP_CONTENT));
        tr.addView(tvL);
        TextView tvR = new TextView(this);
        tvR.setText(right.replaceAll("^\"|\"$", ""));
        tvR.setTextSize(18);
        tvR.setTextColor(getResources().getColor(R.color.black));
        tvR.setLayoutParams(new TableRow.LayoutParams(TableRow.LayoutParams.MATCH_PARENT, TableRow.LayoutParams.WRAP_CONTENT));
        tr.addView(tvR);
        return tr;
    }

    private TableRow addTableRowColor(String left, String right, int color) {
        TableRow tr = new TableRow(this);
        tr.setLayoutParams(new TableRow.LayoutParams(TableRow.LayoutParams.MATCH_PARENT, TableRow.LayoutParams.WRAP_CONTENT));
        TextView tvL = new TextView(this);
        tvL.setText(left);
        tvL.setTextSize(18);
        tvL.setTextColor(getResources().getColor(R.color.black));
        tvL.setLayoutParams(new TableRow.LayoutParams(TableRow.LayoutParams.MATCH_PARENT, TableRow.LayoutParams.WRAP_CONTENT));
        tr.addView(tvL);
        TextView tvR = new TextView(this);
        tvR.setText(right.replaceAll("^\"|\"$", ""));
        tvR.setTextSize(18);
        tvR.setTypeface(tvR.getTypeface(), Typeface.BOLD);
        tvR.setTextColor(getResources().getColor(color));
        tvR.setLayoutParams(new TableRow.LayoutParams(TableRow.LayoutParams.MATCH_PARENT, TableRow.LayoutParams.WRAP_CONTENT));
        tr.addView(tvR);
        return tr;
    }

    private TableRow addTableRowColorLarge(String left, String right, int color) {
        TableRow tr = new TableRow(this);
        tr.setLayoutParams(new TableRow.LayoutParams(TableRow.LayoutParams.MATCH_PARENT, TableRow.LayoutParams.WRAP_CONTENT));
        TextView tvL = new TextView(this);
        tvL.setText(left);
        tvL.setTextSize(22);
        tvL.setTextColor(getResources().getColor(R.color.black));
        tvL.setLayoutParams(new TableRow.LayoutParams(TableRow.LayoutParams.MATCH_PARENT, TableRow.LayoutParams.WRAP_CONTENT));
        tr.addView(tvL);
        TextView tvR = new TextView(this);
        tvR.setText(right.replaceAll("^\"|\"$", ""));
        tvR.setTextSize(22);
        tvR.setTypeface(tvR.getTypeface(), Typeface.BOLD);
        tvR.setTextColor(getResources().getColor(color));
        tvR.setLayoutParams(new TableRow.LayoutParams(TableRow.LayoutParams.MATCH_PARENT, TableRow.LayoutParams.WRAP_CONTENT));
        tr.addView(tvR);
        return tr;
    }

    private DscList decodeDscListData(String data) {
        // find the beginning v=vaccination, r=recovery, t=test vertificate
        int posRound = data.indexOf("{");

        String signatureBase64 = data.substring(0,posRound);
        String trustedList = data.substring(signatureBase64.length()).trim();
        // get public key
        String publicKeyPem;
        if (MainActivity.productionModeEnabledStatic) {
            publicKeyPem = loadFileFromInternalStorage(constantsClass.getFileNamePublicKeyProd());
        } else {
            publicKeyPem = loadFileFromInternalStorage(constantsClass.getFileNamePublicKeyTest());
        }
        PublicKey publicKey = getEcPublicKeyFromString(publicKeyPem);
        // here validate signature
        // todo validate trustedList
        boolean validated = ecVerifySignatureDerFromBase64(publicKey, trustedList.getBytes(StandardCharsets.UTF_8), signatureBase64);
        Gson g = new Gson();
        return g.fromJson(trustedList, DscList.class);
    }

    private static Boolean ecVerifySignatureDerFromBase64(PublicKey publicKey, byte[] messageByte, String signatureBase64) {
        // convert signature from P1363 encoding to DER
        String signatureDerBase64 = convertSignatureP1363ToDerBase64(signatureBase64);
        byte[] signature = base64Decoding(signatureDerBase64);
        Signature publicSignature = null;
        try {
            publicSignature = Signature.getInstance("SHA256withECDSA");
            publicSignature.initVerify(publicKey);
            publicSignature.update(messageByte);
            return publicSignature.verify(signature);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
            Log.e(APP_TAG, "Error in validating: " + e.getMessage());
            return false;
        }
    }

    private String loadFileFromInternalStorage(String filename) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (FileInputStream in = openFileInput(filename))
        {
            byte[] buffer = new byte[8192];
            int nread;
            while ((nread = in.read(buffer)) > 0) {
                out.write(buffer, 0, nread);
            }
            out.flush();
        } catch (IOException e) {
            e.printStackTrace();
            Log.e(APP_TAG, "Error loading file from internal storage: " + e.getMessage());
            return "";
        }
        return new String(out.toByteArray());
    }

   public static PublicKey getEcPublicKeyFromString(String key) {
        String publicKeyPEM = key;
        publicKeyPEM = publicKeyPEM.replace("-----BEGIN PUBLIC KEY-----", "");
        publicKeyPEM = publicKeyPEM.replace("-----END PUBLIC KEY-----", "");
        publicKeyPEM = publicKeyPEM.replaceAll("[\\r\\n]+", "");
        byte[] encoded = base64Decoding(publicKeyPEM);
        KeyFactory kf = null;
        try {
            kf = KeyFactory.getInstance("EC");
            PublicKey pubKey = (PublicKey) kf.generatePublic(new X509EncodedKeySpec(encoded));
            return pubKey;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
            Log.e(APP_TAG, "Error get publicKey from string: " + e.getMessage());
            return null;
        }
    }

    private static String base64Encoding(byte[] input) {
        return Base64.encodeToString(input, Base64.NO_WRAP);
    }

    private static byte[] base64Decoding(String input) {
        return Base64.decode(input, Base64.NO_WRAP);
    }

    // convertPlainToDer and convertDerToPlain
    // source https://stackoverflow.com/a/61873962/8166854  answered May 18 at 16:07 dave_thompson_085
    // secp384r1 (aka P-384) has 384-bit order so use 384/8 which is 48 for n
    private static String convertSignatureP1363ToDerBase64 (String plainBase64) {
        byte[] plain = base64Decoding(plainBase64);
        int n = 32; // for example assume 256-bit-order curve like P-256
        BigInteger r = new BigInteger (+1, Arrays.copyOfRange(plain,0,n));
        BigInteger s = new BigInteger (+1, Arrays.copyOfRange(plain,n,n*2));
        byte[] x1 = r.toByteArray(), x2 = s.toByteArray();
        // already trimmed two's complement, as DER wants
        int len = x1.length + x2.length + (2+2), idx = len>=128? 3: 2;
        // the len>=128 case can only occur for curves of 488 bits or more,
        // and can be removed if you will definitely not use such curve(s)
        byte[] out = new byte[idx+len];
        out[0] = 0x30;
        if( idx==3 ){
            out[1] = (byte)0x81;
            out[2] = (byte)len; }
        else {
            out[1] = (byte)len; }
        out[idx] = 2;
        out[idx+1] = (byte)x1.length;
        System.arraycopy(x1, 0, out, idx+2, x1.length);
        idx += x1.length + 2;
        out[idx] = 2;
        out[idx+1] = (byte)x2.length;
        System.arraycopy(x2, 0, out, idx+2, x2.length);
        return base64Encoding(out);
    }
}