package de.javacrypto.eudcc;

import android.util.Base64;
import android.util.Log;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;

import se.digg.dgc.signatures.CertificateProvider;
import se.digg.dgc.signatures.DGCSignatureVerifier;
import se.digg.dgc.signatures.impl.DefaultDGCSignatureVerifier;

public class VerifyDigitalCovidCertificate {
    // verifies the signature of the dcc

    static String APP_TAG = "EUDCC";

    public static int verifyDccSignature(byte[] decompressedData, DscList dscList) {
        // todo check certificateStatus da spanische zertifikate als abgelaufen markiert sind
        // siehe https://github.com/eu-digital-green-certificates/dgc-testdata/tree/main/ES/png

        int certificateStatus = 0;
        // 0 = not checked, 1 = signature valid and not expired
        // 2 = signature NOT valid, 3 = signature valid but expired

        int returnListSize = dscList.certificates.size();

        // generate an array of X509 certificates
        X509Certificate[] x509Certificates = new X509Certificate[returnListSize];
        for (int i = 0; i < returnListSize; i++) {
            DscListEntry dscListEntry = dscList.certificates.get(i);
            String rawData = dscListEntry.rawData;
            X509Certificate x509Certificate = getCertificateFromBase64String(rawData);
            x509Certificates[i] = x509Certificate;
        }
        CertificateProvider certProvider3 = (c, k) -> x509Certificates != null ? Arrays.asList(x509Certificates)
                : Collections.emptyList();

        DefaultDGCSignatureVerifier verifier3 = new DefaultDGCSignatureVerifier();

        try {
            DGCSignatureVerifier.Result result = verifier3.verify(decompressedData, certProvider3);
            certificateStatus = 1;
        } catch (SignatureException e) {
            e.printStackTrace();
            Log.e(APP_TAG, "Signature exception: " + e.getMessage());
            certificateStatus = 2;
        } catch (CertificateExpiredException e) {
            e.printStackTrace();
            Log.e(APP_TAG, "Certificate expired exception: " + e.getMessage());
            certificateStatus = 3;
        }
        return certificateStatus;
    }

    private static X509Certificate getCertificateFromBase64String(String data) {
        byte[] certByte = base64Decoding(data);
        X509Certificate signerCertificate = null;
        CertificateFactory certFactory;
        try {
            certFactory  = CertificateFactory.getInstance("X.509");
            InputStream in = new ByteArrayInputStream(certByte);
            signerCertificate = (X509Certificate)certFactory.generateCertificate(in);
            return signerCertificate;
        } catch (CertificateException e) {
            e.printStackTrace();
            Log.e(APP_TAG, "Certificate exception: " + e.getMessage());
            return null;
        }
    }

    private static String base64Encoding(byte[] input) {
        return Base64.encodeToString(input, Base64.NO_WRAP);
    }

    private static byte[] base64Decoding(String input) {
        return Base64.decode(input, Base64.NO_WRAP);
    }

}
