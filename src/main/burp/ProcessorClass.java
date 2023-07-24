package burp;

import lib.CryptoChains.CryptoChain;

import java.util.List;

public class ProcessorClass implements IIntruderPayloadProcessor {
    String name;
    CryptoChain cryptoChain;

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

    public void add2Processor() {
        delProcessor(name);
        BurpExtender.callback.registerIntruderPayloadProcessor(this);
    }

    public static String delProcessor(String name) {
        List<IIntruderPayloadProcessor> processors = BurpExtender.callback.getIntruderPayloadProcessors();
        for (IIntruderPayloadProcessor processor : processors) {
            if (name.equals(processor.getProcessorName())) {
                BurpExtender.callback.removeIntruderPayloadProcessor(processor);
                return name + "删除成功";
            }
        }
        return name + "删除失败";
    }

    public static String removeAllProcessor() {
        for (IIntruderPayloadProcessor processor : BurpExtender.callback.getIntruderPayloadProcessors()) {
            BurpExtender.callback.removeIntruderPayloadProcessor(processor);
        }

        return "清除成功";
    }
}
