package com.slipkprojects.ultrasshservice.util;

import android.content.Context;
import android.os.Build;
import android.provider.Settings;

import java.lang.reflect.Method;
import java.util.UUID;

public class UtilsId{
    public static String getIdHardware(Context context) throws Throwable {
        UUID uuid = null;
        Context context2 = context;
        String serialNumber = getSerialNumber();
        String str = "o rato roeu a roupa do rei de roma";
        if (serialNumber == null) {
            serialNumber = "0000000000000000";
        }
        new UUID((long) str.hashCode(), (long) serialNumber.hashCode());
        return uuid.toString().toUpperCase();
    }

    public static String getIdHardwareNovo(Context context) {
        UUID uuid = null;
        String string = Settings.Secure.getString(context.getContentResolver(), "android_id");
        String str = "la rata mordió la ropa del rey de roma";
        if (string == null) {
            string = "0000000000000000";
        }
        new UUID((long) str.hashCode(), (long) string.hashCode());
        return uuid.toString().toUpperCase();
    }

    private static String getSerialNumber() throws Throwable {
        String str;
        Throwable th = null;
        try {
            Class<?> cls = Class.forName("android.os.SystemProperties");
            Class<?> cls2 = cls;
            Class[] clsArr = new Class[1];
            Class[] clsArr2 = clsArr;
            clsArr[0] = Class.forName("java.lang.String");
            Method method = cls2.getMethod("get", clsArr2);
            str = (String) method.invoke(cls, new Object[]{"gsm.sn1"});
            if (str.equals("")) {
                str = (String) method.invoke(cls, new Object[]{"ril.serialnumber"});
            }
            if (str.equals("")) {
                str = (String) method.invoke(cls, new Object[]{"ro.serialno"});
            }
            if (str.equals("")) {
                str = (String) method.invoke(cls, new Object[]{"sys.serialnumber"});
            }
            if (str.equals("")) {
                str = Build.SERIAL;
            }
            if (str.equals("")) {
                str = null;
            }
        } catch (ClassNotFoundException e) {
            ClassNotFoundException classNotFoundException = e;
            Throwable th2 = th;
            new NoClassDefFoundError(classNotFoundException.getMessage());
            throw th2;
        } catch (Exception e2) {
            Exception exc = e2;
            str = null;
        }
        return str;
    }

    /*public UtilsId() {
    }*/
}
