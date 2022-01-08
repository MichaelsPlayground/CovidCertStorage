package de.javacrypto.eudcc;

public class ConstantsClass {

    // constants for DSC files download & storage
    private final String urlDscListProd = "https://de.dscg.ubirch.com/trustList/DSC/";
    private final String urlPublicKeyProd = "https://de.dscg.ubirch.com/pubkey.pem";
    private final String urlDscListTest = "https://de.test.dscg.ubirch.com/trustList/DSC/";
    private final String urlPublicKeyTest = "https://de.test.dscg.ubirch.com/pubkey.pem";
    private final String fileNameDscListProd = "dsclist_prod.json";
    private final String fileNamePublicKeyProd = "pubkey_prod.pem";
    private final String fileNameDscListTest = "dsclist_test.json";
    private final String fileNamePublicKeyTest = "pubkey_test.pem";
    private final String fileNameDownloadTimestampProd = "downloadtimestamp_prod.txt";
    private final String fileNameDownloadTimestampTest = "downloadtimestamp_test.txt";
    // if dslListAge <= 20 footer is in blue
    private final int dslListAgeOrangeWarningDays = 20; // age > 20 = orange warning in footer
    private final int dslListAgeRedWarningDays = 40; // age > 40 = red warning in footer

    public String getUrlDscListProd() {
        return urlDscListProd;
    }

    public String getUrlPublicKeyProd() {
        return urlPublicKeyProd;
    }

    public String getUrlDscListTest() {
        return urlDscListTest;
    }

    public String getUrlPublicKeyTest() {
        return urlPublicKeyTest;
    }

    public String getFileNameDscListProd() {
        return fileNameDscListProd;
    }

    public String getFileNamePublicKeyProd() {
        return fileNamePublicKeyProd;
    }

    public String getFileNameDscListTest() {
        return fileNameDscListTest;
    }

    public String getFileNamePublicKeyTest() {
        return fileNamePublicKeyTest;
    }

    public String getFileNameDownloadTimestampProd() {
        return fileNameDownloadTimestampProd;
    }

    public String getFileNameDownloadTimestampTest() {
        return fileNameDownloadTimestampTest;
    }

    public int getDslListAgeOrangeWarningDays() {
        return dslListAgeOrangeWarningDays;
    }

    public int getDslListAgeRedWarningDays() {
        return dslListAgeRedWarningDays;
    }
}
