error on Android 5

java.lang.NoSuchMethodError: No interface method sort(Ljava/util/Comparator;) exception in sorting arraylist android

https://stackoverflow.com/a/66775562/8166854

In Zxing no need to downgrade version

just add following in App level gradle

android{
....
    compileOptions {
        coreLibraryDesugaringEnabled true
        sourceCompatibility = '1.8'
        targetCompatibility = '1.8'
    }

}
and

dependencies {
    ......
    coreLibraryDesugaring 'com.android.tools:desugar_jdk_libs:1.1.5'
}