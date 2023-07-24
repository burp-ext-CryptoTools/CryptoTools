package lib.Cryptos;

import burp.BurpExtender;
import com.tencent.kona.crypto.spec.SM2PrivateKeySpec;
import com.tencent.kona.crypto.spec.SM2PublicKeySpec;
import lib.AutoCrypt;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class SM2Crypto {
    private final String coding;
    private final Cipher cipher;
    private PublicKey pubKey = null;
    private PrivateKey priKey = null;

    public SM2Crypto(String method, byte[] priKey, byte[] pubKey, String coding) throws NoSuchAlgorithmException, NoSuchPaddingException {
        this.coding = coding;

        cipher = Cipher.getInstance("SM2");

        KeyFactory keyFactory = KeyFactory.getInstance("SM2");

        if (pubKey.length > 0) {
            try {
                this.pubKey = keyFactory.generatePublic(new SM2PublicKeySpec(pubKey));
            } catch (Exception e) {
                BurpExtender.callback.printError("SM2 公钥错误");
            }
        }

        if (priKey.length > 0) {
            try {
                this.priKey = keyFactory.generatePrivate(new SM2PrivateKeySpec(priKey));
            } catch (Exception e) {
                BurpExtender.callback.printError("SM2 私钥错误");
            }
        }
    }

    public String encrypt(String plainText) throws Exception {
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes());

        if ("Base64".equalsIgnoreCase(coding))
            return Base64.getEncoder().encodeToString(encryptedBytes);
        else if ("hex".equalsIgnoreCase(coding))
            return AutoCrypt.bytesToHex(encryptedBytes);
        else
            return new String(encryptedBytes);
    }

    public String decrypt(String encryptedText) throws Exception {
        byte[] encryptedBytes;
        if ("Base64".equalsIgnoreCase(coding))
            encryptedBytes = Base64.getDecoder().decode(encryptedText);
        else if ("hex".equalsIgnoreCase(coding))
            encryptedBytes = AutoCrypt.hexToBytes(encryptedText);
        else
            encryptedBytes = encryptedText.getBytes();

        cipher.init(Cipher.DECRYPT_MODE, priKey);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

        return new String(decryptedBytes);
    }
}