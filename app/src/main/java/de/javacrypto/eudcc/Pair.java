package de.javacrypto.eudcc;

import java.util.Comparator;

class Pair {
    private String key;
    private String value;
    private int sort;
    Pair(String key, String value, int sort) {
        this.key = key;
        this.value = value;
        this.sort = sort;
    }
    public String getKey() {
        return key;
    }
    public void setKey(String key) {
        this.key = key;
    }
    public String getValue() {
        return value;
    }
    public void setValue(String value) {
        this.value = value;
    }
    public int getSort() {
        return sort;
    }
    public void setSort(int sort) {
        this.sort = sort;
    }
}

class PairComparator implements Comparator<Pair> {
    public int compare(Pair pair1, Pair pair2) {
        return pair1.getSort() - pair2.getSort();
    }
}
