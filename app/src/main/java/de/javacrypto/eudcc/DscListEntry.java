package de.javacrypto.eudcc;

/**
 * Represents a Document Signer Certificate as raw data.
 */

public class DscListEntry {
    String certificateType;
    String country;
    String kid;
    String rawData;
    String signature;
    String thumbprint;
    String timestamp;

    public String getRawData() {
        return rawData;
    }
}
