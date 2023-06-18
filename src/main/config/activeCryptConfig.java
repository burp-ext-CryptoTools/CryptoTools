package config;

import ui.ActiveCryptConfigUI.CryptoCards;

import java.util.ArrayList;
import java.util.LinkedHashMap;

public class activeCryptConfig {
    public static ArrayList<String> optionList = new ArrayList<>();

    static {
        optionList.add("urlEncode");
        optionList.add("urlDecode");
        optionList.add("base64Encode");
        optionList.add("base64Decode");
        optionList.add("hexEncode");
        optionList.add("hexDecode");
        optionList.add("htmlEncode");
        optionList.add("htmlDecode");
        optionList.add("DESEncrypt");
        optionList.add("DESDecrypt");
        optionList.add("AESEncrypt");
        optionList.add("AESDecrypt");
        optionList.add("RSAEncrypt");
        optionList.add("RSADecrypt");
        optionList.add("SM4Encrypt");
        optionList.add("SM4Decrypt");
        optionList.add("SM2Encrypt");
        optionList.add("SM2Decrypt");
        optionList.add("convertCharset");
        optionList.add("hash");


    }
}
