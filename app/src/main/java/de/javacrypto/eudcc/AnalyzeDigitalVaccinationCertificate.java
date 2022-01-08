package de.javacrypto.eudcc;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.upokecenter.cbor.CBORObject;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import se.digg.dgc.signatures.cose.CoseSign1_Object;
import se.digg.dgc.signatures.cwt.Cwt;

public class AnalyzeDigitalVaccinationCertificate {
    private static List<Pair> listPair;
    private static String keySaved;


    /*
    * usage:
    * define a list variable: private static List<Pair> listPair;
    * call the function analyzeDigitalVaccinationCertificate with a string from a QR-code for a digital vaccination certificate
    * functions return a List<Pair>
    *
        List<Pair> listData = AnalyzeDigitalVaccinationCertificate.analyzeDigitalVaccinationCertificate(orgQrcodeData);
        System.out.println("\n*** final output ***");
        try {
                for (int i = 0; i < listData.size(); i++) {
                System.out.println("entry " + i + " key: " + listData.get(i).getKey() + " value: " + listData.get(i).getValue());
            }
        } catch (Exception e) {
            System.out.println("wrong data structure");
        }
    * sample data from https://github.com/eu-digital-green-certificates/dgc-testdata
    * HC1:6BF+70790T9WJWG.FKY*4GO0.O1CV2 O5 N2FBBRW1*70HS8WY04AC*WIFN0AHCD8KD97TK0F90KECTHGWJC0FDC:5AIA%G7X+AQB9746HS80:54IBQF60R6$A80X6S1BTYACG6M+9XG8KIAWNA91AY%67092L4WJCT3EHS8XJC$+DXJCCWENF6OF63W5NW6WF6%JC QE/IAYJC5LEW34U3ET7DXC9 QE-ED8%E.JCBECB1A-:8$96646AL60A60S6Q$D.UDRYA 96NF6L/5QW6307KQEPD09WEQDD+Q6TW6FA7C466KCN9E%961A6DL6FA7D46JPCT3E5JDLA7$Q6E464W5TG6..DX%DZJC6/DTZ9 QE5$CB$DA/D JC1/D3Z8WED1ECW.CCWE.Y92OAGY8MY9L+9MPCG/D5 C5IA5N9$PC5$CUZCY$5Y$527B+A4KZNQG5TKOWWD9FL%I8U$F7O2IBM85CWOC%LEZU4R/BXHDAHN 11$CA5MRI:AONFN7091K9FKIGIY%VWSSSU9%01FO2*FTPQ3C3F
    *
    * these libraries are neccessary:
    * https://mvnrepository.com/artifact/com.fasterxml.jackson.core/jackson-core/2.12.3
    * https://mvnrepository.com/artifact/com.fasterxml.jackson.dataformat/jackson-dataformat-cbor/2.12.3
    * https://mvnrepository.com/artifact/com.fasterxml.jackson.core/jackson-databind/2.12.3
    * https://mvnrepository.com/artifact/com.fasterxml.jackson.core/jackson-annotations/2.12.3
    * -or- load with Gradel:
    * // https://mvnrepository.com/artifact/com.fasterxml.jackson.core/jackson-core
    * implementation group: 'com.fasterxml.jackson.core', name: 'jackson-core', version: '2.12.3'
    * // https://mvnrepository.com/artifact/com.fasterxml.jackson.dataformat/jackson-dataformat-cbor
    * implementation group: 'com.fasterxml.jackson.dataformat', name: 'jackson-dataformat-cbor', version: '2.12.3'
    * // https://mvnrepository.com/artifact/com.fasterxml.jackson.core/jackson-databind
    * implementation group: 'com.fasterxml.jackson.core', name: 'jackson-databind', version: '2.12.3'
    * // https://mvnrepository.com/artifact/com.fasterxml.jackson.core/jackson-annotations
    * implementation group: 'com.fasterxml.jackson.core', name: 'jackson-annotations', version: '2.12.3'
    *
    * The class Pair is used for the storage of key - value data pairs in a List<Pair> variable.
    *
    * Important note: this is NOT an individual analyze function but specified for German vaccination certificates.
    * A lot of data field identification is hard coded so any other certificate will fail and the function returns a null object.
    *
    * See the output when using the sample data at the end.
    *
    * The country of certification generation (entry 0, key="cou") is hard coded to DE=Germany
    * The date of vaccination (entry 1, key="dov") is the interpreted data from the unix timestamp
    * The date of certificate expiration (entry 2, key="doe") is the interpreted data from the unix timestamp
    * The signature (entry 3, key="sig") is a hex encoded string
    * The output of the following fields is mapped:
    *
    *
     */


    public static List<Pair> analyzeDigitalVaccinationCertificate3(byte[] decompressedData) {
        analyzeDVC3(decompressedData);
        dataMapping();
        return listPair;
    }

    private static void analyzeDVC3(byte[] decompressedData) {
        listPair = new ArrayList<Pair>();

        // get payload
        byte[] payload = CoseSign1_Object.decode(decompressedData).getCwt().getDgcV1();
        // get json from CBORObject
        String cborNormalizedJson = CBORObject.DecodeFromBytes(payload).ToJSONString();
        // get type of certificate
        String typeOfCertificate = getTypeOfCertificate(cborNormalizedJson);
        Pair pairHeader = new Pair("toc", typeOfCertificate, 99); // DE
        addKeyValuePair(pairHeader);
        // get header data
        final CoseSign1_Object coseObject = CoseSign1_Object.decode(decompressedData);
        final Cwt cwt = coseObject.getCwt();
        String issuer = cwt.getIssuer();
        pairHeader = new Pair("cou", issuer, 99); // DE
        addKeyValuePair(pairHeader);
        Instant issueDate = cwt.getIssuedAt();
        pairHeader = new Pair("dov", getInstantTimeString(issueDate), 99); // date of vaccination
        addKeyValuePair(pairHeader);
        Instant expirationDate = cwt.getExpiration();
        pairHeader = new Pair("doe", getInstantTimeString(expirationDate),99); // date of vaccination
        addKeyValuePair(pairHeader);

        // json mapping
        try {
            ObjectMapper mapperJson = new ObjectMapper();
            JsonNode node = mapperJson.readTree(cborNormalizedJson);
            processNodeModified(node);
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    private static String getInstantTimeString(Instant instant) {
        String instantString = instant.toString();
                return instantString.substring(0, 10); // 2021-07-18
    }

    private static void addKeyValuePair(Pair pair) {
        listPair.add(pair);
    }

    private static String getTypeOfCertificate(String jsonString) {
        // returns "Impfzertifikat", "Testzertifikat", "Genesenenzertifikat" oder "unbekanntes Zertifikat"
        String returnString = "unbekanntes Zertifikat";
        if (jsonString.contains("{\"v\":")) returnString = "Impfzertifikat";
        if (jsonString.contains("{\"r\":")) returnString = "Genesenenzertifikat";
        if (jsonString.contains("{\"t\":")) returnString = "Testzertifikat";
        return returnString;
    }

    // print out recursively the data
    // https://stackoverflow.com/a/61213877/8166854
    private static void processNodeModified(JsonNode node) {
        boolean verbose  = false;
        if (node.isArray()) {
            // if the node is a list of items,
            //  go through all the items and process them individually
            if (verbose) System.out.println("=== Array start ===");
            for (final JsonNode objInArray : node) {
                if (verbose) System.out.println("--- Array element start ---");
                // process the item in the array
                processNodeModified(objInArray);
                if (verbose)  System.out.println("--- Array element end ---");
            }
            if (verbose) System.out.println("=== Array end ===");
        } else if (node.isContainerNode()) {
            // if the node is an object,
            //  go through all fields within the object
            if (verbose) System.out.println("/// Object start ///");
            Iterator<Map.Entry<String, JsonNode>> it = node.fields();
            while (it.hasNext()) {
                Map.Entry<String, JsonNode> field = it.next();
                if (verbose) System.out.println("key: " + field.getKey());
                keySaved = field.getKey();
                //process every field in the array
                processNodeModified(field.getValue());
            }
            if (verbose) System.out.println("/// Object end ///");
        } else {
            // if node is a simple value (like string or int) so let's print it
            if (verbose) System.out.println("value: " + node);
            String valueSaved = node.toString().replaceAll("\"","");
            Pair pair = new Pair(keySaved, valueSaved, 99);
            addKeyValuePair(pair);
        }
    }

    // data mapping
    private static void dataMapping() {
        // searches for some keys and mapps the data to corresponding tables
        // second: sets the sort order
        // data: https://github.com/ehn-dcc-development/ehn-dcc-schema/blob/release/1.3.0/DCC.Types.schema.json
        for (int i = 0; i < listPair.size(); i++) {
            Pair pair = listPair.get(i);
            if (pair.getKey().equals("ma")) {
                String ma = pair.getValue();
                pair.setValue(getProducerName(ma) + " (" + ma + ")");
                pair.setKey("Impfstoff-\nHersteller ");
                pair.setSort(8);
            }
            if (pair.getKey().equals("mp")) {
                String mp = pair.getValue();
                pair.setValue(getProductName(mp) + " (" + mp + ")");
                pair.setKey("Impfstoff ");
                pair.setSort(6);
            }
            if (pair.getKey().equals("tg")) {
                String tg = pair.getValue();
                pair.setValue(getDiseaseAgent(tg) + " (" + tg + ")");
                pair.setKey("Zielkrankheit ");
                pair.setSort(5);
            }
            if (pair.getKey().equals("vp")) {
                String vp = pair.getValue();
                pair.setValue(getVaccineProphylaxis(vp) + " (" + vp + ")");
                pair.setKey("Impfstoffart ");
                pair.setSort(7);
            }
            // just naming
            if (pair.getKey().equals("dob")) {
                pair.setKey("Geburtsdatum ");
                pair.setSort(4);
            }
            if (pair.getKey().equals("fn")) {
                pair.setKey("Familienname ");
                pair.setSort(2);
            }
            if (pair.getKey().equals("fnt")) {
                pair.setKey("Familienname\nAusweis ");
                pair.setSort(99);
            }
            if (pair.getKey().equals("gn")) {
                pair.setKey("Vorname ");
                pair.setSort(3);
            }
            if (pair.getKey().equals("gnt")) {
                pair.setKey("Vorname\nAusweis ");
                pair.setSort(99);
            }
            if (pair.getKey().equals("ci")) {
                pair.setKey("ID Zertifikat ");
                pair.setSort(14);
            }
            if (pair.getKey().equals("co")) {
                pair.setKey("Impf-/Testland ");
                pair.setSort(12);
            }
            if (pair.getKey().equals("dn")) {
                pair.setKey("Nummer Dosis ");
                pair.setSort(9);
            }
            if (pair.getKey().equals("dt")) {
                pair.setKey("Impfdatum ");
                pair.setSort(11);
            }
            if (pair.getKey().equals("is")) {
                pair.setKey("Zertifikat-\nAussteller ");
                pair.setSort(13);
            }
            if (pair.getKey().equals("sd")) {
                pair.setKey("Gesamtzahl\nImpfdosen ");
                pair.setSort(10);
            }
            if (pair.getKey().equals("ver")) {
                pair.setKey("Version\nZertifikat ");
                pair.setSort(90);
            }
            if (pair.getKey().equals("cou")) {
                pair.setKey("Zertifikatsland ");
                pair.setSort(91);
            }
            if (pair.getKey().equals("doe")) {
                pair.setKey("Ablaufdatum ");
                pair.setSort(92);
            }
            if (pair.getKey().equals("dov")) {
                pair.setKey("Ausstellung\nZertifkat ");
                pair.setSort(93);
            }
            if (pair.getKey().equals("toc")) { // type of certificate, header
                pair.setKey("Typ ");
                pair.setSort(00);
            }
            // test keys
            if (pair.getKey().equals("tt")) {
                pair.setKey("Test Typ ");
                pair.setSort(20);
            }
            if (pair.getKey().equals("nm")) {
                pair.setKey("Test Name ");
                pair.setSort(20);
            }
            if (pair.getKey().equals("ma")) {
                pair.setKey("RAT Test Name ");
                pair.setSort(20);
            }
            if (pair.getKey().equals("sc")) {
                pair.setKey("Datum Test ");
                pair.setSort(20);
            }
            if (pair.getKey().equals("dr")) {
                pair.setKey("Datum Testergebnis ");
                pair.setSort(20);
            }
            if (pair.getKey().equals("tr")) {
                pair.setKey("Testergebnis ");
                pair.setSort(20);
            }
            if (pair.getKey().equals("tc")) {
                pair.setKey("Testcenter ");
                pair.setSort(20);
            }
            // recovery keys
            if (pair.getKey().equals("fr")) {
                pair.setKey("Datum des\npositiven Tests ");
                pair.setSort(30);
            }
            if (pair.getKey().equals("df")) {
                pair.setKey("Zertifikat gültig ab ");
                pair.setSort(30);
            }
            if (pair.getKey().equals("du")) {
                pair.setKey("Zertifikat gültig bis ");
                pair.setSort(30);
            }
            /*
            if (pair.getKey().equals("")) {
                pair.setKey(" ");
                pair.setSort(20);
            }
            */
        }
    }

    // data mapping tables - hardcoded as of 2021-07-01
    private static String getProducerName(String input) {
        switch (input) {
            case "ORG-100001699": return "AstraZeneca AB";
            case "ORG-100030215": return "Biontech Manufacturing GmbH";
            case "ORG-100031184": return "Moderna Biotech Spain S.L.";
            case "ORG-100006270": return "Curevac AG";
            default: return "unbekannter Hersteller";
        }
    }

    private static String getProductName(String input) {
        switch (input)  {
            case "EU/1/20/1528": return "Comirnaty";
            case "EU/1/20/1507": return "COVID-19 Vaccine Moderna";
            case "EU/1/21/1529": return "Vaxzevria";
            case "EU/1/20/1525": return "COVID-19 Vaccine Janssen";
            default: return "unbekanntes Produkt";
        }
    }

    private static String getDiseaseAgent(String input) {
        switch (input)  {
            case "840539006": return "COVID-19";
            default: return "unbekannter Verwendungszweck";
        }
    }

    private static String getVaccineProphylaxis(String input) {
        switch (input)  {
            case "1119349007": return "SARS-CoV-2 mRNA vaccine";
            case "1119305005": return "SARS-CoV-2 antigen vaccine";
            case "J07BX03": return "covid-19 vaccines";
            default: return "unbekannte Vorsorge";
        }
    }
}
