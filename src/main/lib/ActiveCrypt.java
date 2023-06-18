package lib;

import burp.BurpExtender;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.Buffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ActiveCrypt {
    CurrentParameter currentParameter;

    public ActiveCrypt(CurrentParameter currentParameter) {
        this.currentParameter = currentParameter;
    }

    public String handle(String text) throws Exception {
        if ("urlEncode".equalsIgnoreCase(currentParameter.codeMethod))
            return url_encode(text, currentParameter.url_encode_all, currentParameter.charset);
        if ("urlDecode".equalsIgnoreCase(currentParameter.codeMethod))
            return url_decode(text, currentParameter.charset);
        if ("base64Encode".equalsIgnoreCase(currentParameter.codeMethod))
            return base64_encode(text);
        if ("base64Decode".equalsIgnoreCase(currentParameter.codeMethod))
            return base64_decode(text);
        if ("hexEncode".equalsIgnoreCase(currentParameter.codeMethod))
            return string2Hex(text,"","","utf-8");
        if ("hexDecode".equalsIgnoreCase(currentParameter.codeMethod))
            return hex2String(text, Charset.defaultCharset().name());
        if ("convertCharset".equalsIgnoreCase(currentParameter.codeMethod))
            return convertCharset(text, currentParameter.charset);
        if ("htmlEncode".equalsIgnoreCase(currentParameter.codeMethod))
            return html_encode(text, currentParameter.charset);
        if ("htmlDecode".equalsIgnoreCase(currentParameter.codeMethod))
            return html_decode(text, currentParameter.charset);
        if (currentParameter.isCrypt)
            if (currentParameter.isDecrypt) {
                byte[] key = ProcessData.string2byes(currentParameter.key, currentParameter.keyCode);
                byte[] IV = ProcessData.string2byes(currentParameter.IV, currentParameter.IVCode);
                String decrypted = new Crypto(currentParameter.codeMethod, currentParameter.mode, key, IV, currentParameter.inCode).decrypt(text);

                if ("hex".equalsIgnoreCase(currentParameter.outCode))
                    return ProcessData.bytesToHex(decrypted.getBytes());
                else if ("base64".equalsIgnoreCase(currentParameter.outCode))
                    return new String(Base64.getEncoder().encode(decrypted.getBytes()));
                else
                    return decrypted;
            } else {
                byte[] key = ProcessData.string2byes(currentParameter.key, currentParameter.keyCode);
                byte[] IV = ProcessData.string2byes(currentParameter.IV, currentParameter.IVCode);

                text = new String(ProcessData.string2byes(text, currentParameter.inCode));

                return new Crypto(currentParameter.codeMethod, currentParameter.mode, key, IV, currentParameter.outCode).encrypt(text);
            }
        if (currentParameter.isHash)
            return hash(currentParameter.codeMethod, text);
        else
            return text;
    }

    public String url_encode(String text, boolean all, String charset) throws UnsupportedEncodingException {
        if (all) {
            return string2Hex(text, "%", "", charset);
        } else {
            return URLEncoder.encode(text, charset);
        }
    }

    public String url_decode(String text, String charset) throws UnsupportedEncodingException {
        return URLDecoder.decode(text, charset);
    }

    public String base64_encode(String text) {
        return Base64.getEncoder().encodeToString(text.getBytes());
    }

    public String base64_decode(String text) {
        byte[] decode = Base64.getDecoder().decode(text);
        return new String(decode);
    }

    public String convertCharset(String text, String charset) throws UnsupportedEncodingException {
        return new String(text.getBytes(charset), StandardCharsets.ISO_8859_1);
    }

    public String html_encode(String text, String charset) throws UnsupportedEncodingException {
        return string2Hex(text, "&#x", ";", charset);
    }

    public String html_decode(String text, String charset) throws UnsupportedEncodingException {
        return hex2String(text, charset);
    }

    public String string2Hex(String text, String prefix, String suffix, String charset) throws UnsupportedEncodingException {
        StringBuilder result = new StringBuilder();
        byte[] bytes = text.getBytes(charset);

        for (int b : bytes) {
            result.append(prefix).append(Integer.toHexString((b + 256) % 256)).append(suffix);
        }

        return result.toString();
    }

    public String string2Hex(byte[] bytes, String prefix, String suffix, String charset) throws UnsupportedEncodingException {
        StringBuilder result = new StringBuilder();

        for (int b : bytes) {
            result.append(prefix).append(Integer.toHexString((b + 256) % 256)).append(suffix);
        }

        return result.toString();
    }

    public String hex2String(String text, String charset) throws UnsupportedEncodingException {
        ArrayList<Byte> integers = new ArrayList<>();

        Pattern compile = Pattern.compile("[0-9a-f]{2}");
        Matcher matcher = compile.matcher(text);

        while (matcher.find()) {
            String num = matcher.group();
            integers.add((byte) Integer.parseInt(num, 16));
        }

        byte[] bytes = new byte[integers.size()];
        for (int i = 0; i < integers.size(); i++) {
            bytes[i] = integers.get(i);
        }

        return new String(bytes, charset);
    }

    public String hash(String algorithm, String text) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        MessageDigest instance = MessageDigest.getInstance(algorithm);
        instance.update(text.getBytes());
        byte[] bytes = instance.digest();
        return string2Hex(bytes, "", "", "iso-8859-1");
    }

    public static class CurrentParameter {
        public String codeMethod;
        public String charset = Charset.defaultCharset().name();
        public boolean url_encode_all = false;
        public boolean isHash = false;
        public boolean isCrypt = false;
        public boolean isDecrypt = false;
        public String key;
        public String keyCode;
        public String IV;
        public String IVCode;
        public String mode;
        public String inCode;
        public String outCode;

        public CurrentParameter(String codeMethod) {
            this.codeMethod = codeMethod;
        }

        public CurrentParameter(String codeMethod, boolean isHash) {
            this.codeMethod = codeMethod;
            this.isHash = isHash;
        }

        public CurrentParameter(String codeMethod, boolean isCrypt, boolean isDecrypt, String key, String IV, String mode, String inCode, String outCode, String keyCode, String IVCode) {
            this.codeMethod = codeMethod;
            this.isCrypt = isCrypt;
            this.isDecrypt = isDecrypt;
            this.key = key;
            this.IV = IV;
            this.mode = mode;
            this.inCode = inCode;
            this.outCode = outCode;
            this.keyCode = keyCode;
            this.IVCode = IVCode;
        }

        public CurrentParameter(String codeMethod, String charset) {
            this.codeMethod = codeMethod;
            this.charset = charset;
        }

        public CurrentParameter(String codeMethod, String charset, boolean url_encode_all, boolean isHash) {
            this.codeMethod = codeMethod;
            this.charset = charset;
            this.url_encode_all = url_encode_all;
            this.isHash = isHash;
        }
    }
}
