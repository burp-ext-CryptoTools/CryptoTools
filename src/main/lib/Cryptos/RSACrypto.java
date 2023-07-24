package lib.Cryptos;

import lib.AutoCrypt;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class RSACrypto {
    private final String coding;
    private final KeyFactory keyFactory;
    private final Cipher cipher;
    private final byte[] priKey;
    private final byte[] pubKey;

    public RSACrypto(String method, byte[] priKey, byte[] pubKey, String coding) throws NoSuchAlgorithmException, NoSuchPaddingException {
        this.coding = coding;
        this.priKey = priKey;
        this.pubKey = pubKey;

        keyFactory = KeyFactory.getInstance("RSA");
        cipher = Cipher.getInstance(method);
    }

    public String encrypt(String plainText) throws Exception {

        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(pubKey);
        PublicKey publicKey = keyFactory.generatePublic(keySpec);

        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes());

        if ("Base64".equalsIgnoreCase(coding))
            return Base64.getEncoder().encodeToString(encryptedBytes);
        else if ("hex".equalsIgnoreCase(coding))
            return AutoCrypt.bytesToHex(encryptedBytes);
        else
            return new String(encryptedBytes);
    }

    public String decrypt(String encryptedText) throws Exception {

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(priKey);
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        byte[] encryptedBytes;
        if ("Base64".equalsIgnoreCase(coding))
            encryptedBytes = Base64.getDecoder().decode(encryptedText);
        else if ("hex".equalsIgnoreCase(coding))
            encryptedBytes = AutoCrypt.hexToBytes(encryptedText);
        else
            encryptedBytes = encryptedText.getBytes();

        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return new String(decryptedBytes);
    }
}