package burp;

import lib.CryptoChain;

import java.util.HashMap;

public class ProcessorClass implements IIntruderPayloadProcessor {
    String name;
    CryptoChain cryptoChain;
    public static HashMap<String, ProcessorClass> registeredProcessorList = new HashMap<>();

    public ProcessorClass(String name, CryptoChain cryptoChain) {
        this.name = name;
        this.cryptoChain = cryptoChain;
    }

    @Override
    public String getProcessorName() {
        return name;
    }

    @Override
    public byte[] processPayload(byte[] currentPayload, byte[] originalPayload, byte[] baseValue) {
        try {
            String result = cryptoChain.doFinal(new String(currentPayload));

            BurpExtender.callback.printOutput(new String(originalPayload) + " => " + new String(currentPayload) + " => " + result);

            return result.getBytes();
        } catch (Exception e) {
            BurpExtender.callback.printError("processPayload error");
        }
        return currentPayload;
    }

    public String add2Processor() {
        if ("".equals(name))
            return "菜单名不能为空";

        delProcessor(name);

        registeredProcessorList.put(name, this);
        BurpExtender.callback.registerIntruderPayloadProcessor(this);

        return name + "添加成功";
    }

    public String delProcessor(String name) {
        for (String _name : registeredProcessorList.keySet()) {
            if (_name.equals(name)) {
                BurpExtender.callback.removeIntruderPayloadProcessor(registeredProcessorList.get(_name));
                registeredProcessorList.remove(_name);
                break;
            }
        }

        return name + "删除成功";
    }
}
