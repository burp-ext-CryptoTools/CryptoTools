package config;

import java.util.LinkedHashMap;
import java.util.Map;

public class allCryptoConfig {
    public static Map<String, String[]> cryptoMap = new LinkedHashMap<>();
    public static String[] titles4encode = {"raw", "hex", "base64"};
    public static String[] titles4location = {"url", "headers", "body"};

    static {
        cryptoMap.put("-- 请选择 --", new String[]{});
        cryptoMap.put("AES", new String[]{"AES/ECB/NoPadding", "AES/CBC/NoPadding", "AES/ECB/PKCS5Padding", "AES/CBC/PKCS5Padding"});
        cryptoMap.put("DES", new String[]{"DES/ECB/NoPadding", "DES/CBC/NoPadding", "DES/ECB/PKCS5Padding", "DES/CBC/PKCS5Padding"});
        cryptoMap.put("RSA", new String[]{"RSA/ECB/PKCS1Padding", "RSA/ECB/OAEPWithSHA-1AndGEF1Padding", "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"});
        cryptoMap.put("SM4", new String[]{"SM4/ECB/NoPadding", "SM4/CBC/NoPadding", "SM4/ECB/PKCS7Padding", "SM4/CBC/PKCS7Padding"});
        cryptoMap.put("SM2", new String[]{"SM2"});
    }
}
