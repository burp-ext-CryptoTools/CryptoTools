package lib;

import burp.BurpExtender;
import burp.IExtensionHelpers;
import burp.IRequestInfo;
import burp.IResponseInfo;
import config.autoCryptConfig;

import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class AutoCrypt {
    public static byte[] unpackPacket(byte[] packet, IExtensionHelpers helpers, boolean isRequest, boolean decode) {
        List<String> headers;
        String urlParameters = "";
        String body;
        String cryptoLocation;
        String cryptoReg;

        if (isRequest) {
            IRequestInfo requestInfo = helpers.analyzeRequest(packet);

            // headers
            headers = requestInfo.getHeaders();

            // url参数
            String[] split = headers.get(0).split("\\?", 2);
            urlParameters = split.length > 1 ? split[1] : "";

            // body
            int bodyOffset = requestInfo.getBodyOffset();
            body = new String(Arrays.copyOfRange(packet, bodyOffset, packet.length));

            // cryptLocation
            cryptoLocation = autoCryptConfig.requestCryptoLocation;
            // cryptReg
            cryptoReg = autoCryptConfig.requestCryptoReg;

        } else {
            IResponseInfo responseInfo = helpers.analyzeResponse(packet);

            // headers
            headers = responseInfo.getHeaders();

            // body
            int bodyOffset = responseInfo.getBodyOffset();
            body = new String(Arrays.copyOfRange(packet, bodyOffset, packet.length));

            // cryptLocation
            cryptoLocation = autoCryptConfig.responseCryptoLocation;
            // cryptoReg
            cryptoReg = autoCryptConfig.responseCryptoReg;
        }

        if (Objects.equals(cryptoLocation, "url")) {
            urlParameters = extractDataWithReg(urlParameters, cryptoReg, isRequest, decode);
            if (!"".equals(urlParameters))
                headers.set(0, headers.get(0).split("\\?", 2)[0] + urlParameters);
        } else if (Objects.equals(cryptoLocation, "headers")) {
            for (int i = 1; i < headers.size(); i++) {
                headers.set(i, extractDataWithReg(headers.get(i), cryptoReg, isRequest, decode));
            }
        } else
            body = extractDataWithReg(body, cryptoReg, isRequest, decode);

        return helpers.buildHttpMessage(headers, body.getBytes());
    }

    public static String extractDataWithReg(String data, String regStr, boolean isRequest, boolean decode) {
        if (data == null || "".equals(data) || regStr == null || "".equals(regStr))
            return data;

        CryptoChains.CryptoChain encryptChain;
        CryptoChains.CryptoChain decryptChain;
        if (isRequest) {
            encryptChain = autoCryptConfig.requestEncryptChain;
            decryptChain = autoCryptConfig.requestDecryptChain;
        }else {
            encryptChain = autoCryptConfig.responseEncryptChain;
            decryptChain = autoCryptConfig.responseDecryptChain;
        }

        Pattern pattern = Pattern.compile(regStr);
        Matcher matcher = pattern.matcher(data);

        StringBuilder buffer = new StringBuilder();

        // 循环获取多次匹配到的结果
        while (matcher.find()) {
            int start = matcher.start();
            StringBuilder replacement = new StringBuilder();

            // 每次匹配到的结果可能有多个分组（多组小括号），如果没有则进行提示
            if (matcher.groupCount() < 1)
                BurpExtender.callback.printError("Error：自动解密未匹配到任何内容，需要替换的内容请用小括号括起来");

            for (int i = 1; i <= matcher.groupCount(); i++) {
                String match = matcher.group(i);
                if ("".equals(match))
                    break;

                // 对匹配到的数据进行加解密
                String value;
                try {
                    if (decode && decryptChain != null)
                        value = decryptChain.doFinal(match);
                    else if (!decode && encryptChain != null)
                        value = encryptChain.doFinal(match);
                    else
                        value = match;
                }catch (Exception e){
                    BurpExtender.callback.printError(e.toString());
                    value = match;
                }

                replacement.append(data, start, matcher.start(i)).append(value);
                start = matcher.end(i);
            }
            replacement.append(data, start, matcher.end());
            matcher.appendReplacement(buffer, Matcher.quoteReplacement(replacement.toString()));
        }
        matcher.appendTail(buffer);
        return buffer.toString();
    }

    public static byte[] string2byes(String str, String mode) {
        if (str == null || "".equals(str))
            return new byte[]{};

        str = str.strip();
        if ("hex".equals(mode)) {
            byte[] bytes = new byte[str.length() / 2];
            for (int i = 0; i < str.length(); i += 2)
                bytes[i / 2] = (byte) ((Character.digit(str.charAt(i), 16) << 4) + Character.digit(str.charAt(i + 1), 16));
            return bytes;
        } else if ("base64".equals(mode)) {
            return Base64.getDecoder().decode(str);
        } else {
            return str.getBytes();
        }
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", (b + 256) % 256 ));
        }
        return sb.toString();
    }

    public static byte[] hexToBytes(String hexString) {
        int len = hexString.length();
        String hex;
        if (len % 2 == 1) {
            hex = "0" + hexString;
            len += 1;
        } else
            hex = hexString;

        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }
}
