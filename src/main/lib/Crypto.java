package lib;

import burp.BurpExtender;
import com.tencent.kona.crypto.KonaCryptoProvider;
import lib.Cryptos.RSACrypto;
import lib.Cryptos.SM2Crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Security;
import java.util.Base64;

public class Crypto {
    String algorithm;
    String method;
    byte[] key;
    byte[] iv;
    String coding;

    public Crypto(String algorithm, String method, byte[] key, byte[] iv, String coding) {
        this.algorithm = algorithm;
        this.method = method;
        this.key = key;
        this.iv = iv;
        this.coding = coding;

        Security.insertProviderAt(new KonaCryptoProvider(), 1);
    }

    public String encrypt(String content) {
        if (algorithm == null || method == null)
            return content;

        try {
            switch (algorithm) {
                case "SM2" -> {
                    byte[] priKey = key;
                    byte[] pubKey = iv;
                    return new SM2Crypto(method, priKey, pubKey, coding).encrypt(content);
                }
//                case "SM4" -> {
//                    return new SM4Crypto(method, key, iv, coding).encrypt(content);
//                }
                case "RSA" -> {
                    byte[] priKey = key;
                    byte[] pubKey = iv;
                    return new RSACrypto(method, priKey, pubKey, coding).encrypt(content);
                }
                // default 包括AES、DES、SM4
                default -> {
                    SecretKeySpec keySpec = new SecretKeySpec(key, algorithm);
                    IvParameterSpec ivSpec = null;
                    if (iv.length > 0)
                        ivSpec = new IvParameterSpec(iv);
                    Cipher cipher = Cipher.getInstance(method);
                    byte[] encrypted;
                    if (ivSpec != null)
                        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
                    else
                        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
                    encrypted = cipher.doFinal(content.getBytes());
                    if ("Base64".equalsIgnoreCase(coding))
                        return Base64.getEncoder().encodeToString(encrypted);
                    else if ("hex".equalsIgnoreCase(coding))
                        return AutoCrypt.bytesToHex(encrypted);
                    else
                        return new String(encrypted);
                }
            }
        } catch (Exception e) {
            String errorStr = "\n加密出错： " + e + "\n" +
                    "参数： \n\t\t" +
                    "算法：" + algorithm + "\n\t\t模式：" + method + "\n\t\tkey：" + new String(key) +
                    "\n\t\tIV：" + new String(iv) + "\n\t\t加密内容：" + content;
            BurpExtender.callback.printError(errorStr);
            return content;
        }
    }

    public String decrypt(String content) {
        if (algorithm == null || method == null)
            return content;

        try {
            switch (algorithm) {
                case "SM2" -> {
                    byte[] priKey = key;
                    byte[] pubKey = iv;
                    return new SM2Crypto(method, priKey, pubKey, coding).decrypt(content);
                }
//                case "SM4" -> {
//                    return new SM4Crypto(method, key, iv, coding).decrypt(content);
//                }
                case "RSA" -> {
                    byte[] priKey = key;
                    byte[] pubKey = iv;
                    return new RSACrypto(method, priKey, pubKey, coding).decrypt(content);
                }
                // default 包括 AES、DES、SM4
                default -> {
                    SecretKeySpec keySpec = new SecretKeySpec(key, algorithm);
                    IvParameterSpec ivSpec = null;
                    if (iv.length > 0)
                        ivSpec = new IvParameterSpec(iv);
                    Cipher cipher = Cipher.getInstance(method);
                    byte[] encrypted;
                    if ("Base64".equalsIgnoreCase(coding))
                        encrypted = Base64.getDecoder().decode(content);
                    else
                        encrypted = AutoCrypt.hexToBytes(content);
                    if (ivSpec != null)
                        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
                    else
                        cipher.init(Cipher.DECRYPT_MODE, keySpec);
                    return new String(cipher.doFinal(encrypted));
                }
            }
        } catch (Exception e) {
            String errorStr = "\n解密出错： " + e + "\n" +
                    "参数： \n\t\t" +
                    "算法：" + algorithm + "\n\t\t模式：" + method + "\n\t\tkey：" + new String(key) +
                    "\n\t\tIV：" + new String(iv) + "\n\t\t解密内容：" + content;
            BurpExtender.callback.printError(errorStr);
            return content;
        }
    }
}
