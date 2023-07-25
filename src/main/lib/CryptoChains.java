package lib;

import burp.BurpExtender;
import burp.MenuFactoryClass;
import burp.ProcessorClass;
import ui.AutoCryptConfigUI;

import javax.swing.*;
import java.nio.charset.Charset;
import java.util.LinkedHashMap;

public class CryptoChains {
    public static LinkedHashMap<String, CryptoChain> cryptoChainLinkedHashMap = new LinkedHashMap<>();

    public static String addChain(String chainName, CryptoChain cryptoChain) {
        if ("".equals(chainName))
            return "菜单名不能为空";
        cryptoChain.getCryptChain();
        cryptoChainLinkedHashMap.put(chainName, cryptoChain);

        // 添加到右击菜单
        MenuFactoryClass menuFactoryClass = BurpExtender.menuFactoryClass;
        menuFactoryClass.addMenuItem(chainName, cryptoChain);

        // 添加到processor
        ProcessorClass processorClass = new ProcessorClass(chainName, cryptoChain);
        processorClass.add2Processor();

        // 添加到主动解密模块
        refreshCryptoComboBox();

        return chainName + " 添加成功";
    }

    public static void refreshCryptoComboBox() {
        AutoCryptConfigUI.requestPanel.refreshCryptoComboBox(cryptoChainLinkedHashMap.keySet().toArray(new String[0]));
        AutoCryptConfigUI.responsePanel.refreshCryptoComboBox(cryptoChainLinkedHashMap.keySet().toArray(new String[0]));
    }

    public static class CryptoChain {
        public LinkedHashMap<Integer, JPanel> cardChain = new LinkedHashMap<>();
        public LinkedHashMap<Integer, ActiveCrypt> cryptChain = new LinkedHashMap<>();

        public CryptoChain() {

        }

        private CryptoChain(CryptoChain cryptoChain) {
            this.cardChain = new LinkedHashMap<>(cryptoChain.cardChain);
            this.cryptChain = new LinkedHashMap<>(cryptoChain.cryptChain);
        }

        public void upItem(int index) {
            if (index == 1)
                return;
            JPanel temp = cardChain.get(index);

            cardChain.remove(index);
            cardChain.put(index, cardChain.get(index - 1));

            cardChain.remove(index - 1);
            cardChain.put(index - 1, temp);
        }

        public void downItem(int index) {
            if (index == cardChain.size())
                return;

            JPanel temp = cardChain.get(index);

            cardChain.remove(index);
            cardChain.put(index, cardChain.get(index + 1));

            cardChain.remove(index + 1);
            cardChain.put(index + 1, temp);
        }

        public void delItem(int index) {
            for (int i = index; i <= cardChain.size(); i++) {
                if (i != cardChain.size()) {
                    cardChain.remove(i);
                    cardChain.put(i, cardChain.get(i + 1));
                }
            }
            cardChain.remove(cardChain.size());
        }

        public void clear() {
            cardChain.clear();
        }

        public void getCryptChain() {
            cryptChain.clear();
            for (JPanel panel : cardChain.values()) {
                JPanel leftPanel = (JPanel) panel.getComponent(0);
                JPanel labelPanel = (JPanel) leftPanel.getComponent(0);
                JLabel label = (JLabel) labelPanel.getComponent(0);
                String cryptName = label.getText();


                if ("urlEncode".equalsIgnoreCase(cryptName)) {
                    JPanel dataPanel = (JPanel) leftPanel.getComponent(1);
                    JCheckBox all_encode = (JCheckBox) dataPanel.getComponent(0);
                    boolean selected = all_encode.isSelected();
                    ActiveCrypt.CurrentParameter parameter = new ActiveCrypt.CurrentParameter(cryptName, Charset.defaultCharset().name(), selected, false);
                    cryptChain.put(cryptChain.size() + 1, new ActiveCrypt(parameter));
                } else if (cryptName.contains("crypt")) {
                    JPanel dataPanel = (JPanel) leftPanel.getComponent(1);

                    JPanel jPanel1 = (JPanel) dataPanel.getComponent(0);
                    JPanel jPanel2 = (JPanel) dataPanel.getComponent(1);

                    JPanel keyPanel = (JPanel) jPanel1.getComponent(0);
                    JPanel IVPanel = (JPanel) jPanel1.getComponent(1);

                    JPanel algorithmPanel = (JPanel) jPanel2.getComponent(0);
                    JPanel inputEncodePanel = (JPanel) jPanel2.getComponent(1);
                    JPanel outputEncodePanel = (JPanel) jPanel2.getComponent(2);


                    JTextField keyTextField = (JTextField) keyPanel.getComponent(2);
                    JComboBox keyCodeComboBox = (JComboBox) keyPanel.getComponent(4);

                    String key = keyTextField.getText();
                    String keyCode = (String) keyCodeComboBox.getSelectedItem();

                    JTextField IVTextField = (JTextField) IVPanel.getComponent(2);
                    JComboBox IVCodeComboBox = (JComboBox) IVPanel.getComponent(4);

                    String IV = IVTextField.getText();
                    String IVCode = (String) IVCodeComboBox.getSelectedItem();

                    JComboBox algorithmComboBox = (JComboBox) algorithmPanel.getComponent(1);
                    String algorithm = (String) algorithmComboBox.getSelectedItem();

                    JComboBox inputCodeComboBox = (JComboBox) inputEncodePanel.getComponent(1);
                    String inputCode = (String) inputCodeComboBox.getSelectedItem();

                    JComboBox outputCodeComboBox = (JComboBox) outputEncodePanel.getComponent(1);
                    String outputCode = (String) outputCodeComboBox.getSelectedItem();

                    ActiveCrypt.CurrentParameter parameter = new ActiveCrypt.CurrentParameter(algorithm.split("/")[0], true, cryptName.contains("Decrypt"), key, IV, algorithm, inputCode, outputCode, keyCode, IVCode);
                    cryptChain.put(cryptChain.size() + 1, new ActiveCrypt(parameter));
                } else if ("convertCharset".equalsIgnoreCase(cryptName)) {
                    JPanel dataPanel = (JPanel) leftPanel.getComponent(1);

                    JComboBox charsetComboBox = (JComboBox) dataPanel.getComponent(0);
                    String charset = (String) charsetComboBox.getSelectedItem();

                    ActiveCrypt.CurrentParameter parameter = new ActiveCrypt.CurrentParameter(cryptName, charset);
                    cryptChain.put(cryptChain.size() + 1, new ActiveCrypt(parameter));
                } else if ("hash".equalsIgnoreCase(cryptName)) {
                    JPanel dataPanel = (JPanel) leftPanel.getComponent(1);

                    JComboBox hashComboBox = (JComboBox) dataPanel.getComponent(0);
                    String hash = (String) hashComboBox.getSelectedItem();

                    ActiveCrypt.CurrentParameter parameter = new ActiveCrypt.CurrentParameter(hash, true);
                    cryptChain.put(cryptChain.size() + 1, new ActiveCrypt(parameter));
                } else if ("stringReplace".equalsIgnoreCase(cryptName)) {
                    JPanel dataPanel = (JPanel) leftPanel.getComponent(1);

                    JPanel checkPanel = (JPanel) dataPanel.getComponent(0);
                    JCheckBox checkBox = (JCheckBox) checkPanel.getComponent(0);
                    boolean isReg = checkBox.isSelected();

                    JPanel inputPanel = (JPanel) dataPanel.getComponent(1);
                    JTextField findTextField = (JTextField) inputPanel.getComponent(1);
                    JTextField replaceTextField = (JTextField) inputPanel.getComponent(3);

                    String oldString = findTextField.getText();
                    String newString = replaceTextField.getText();

                    ActiveCrypt.CurrentParameter parameter = new ActiveCrypt.CurrentParameter(cryptName, isReg, oldString, newString);
                    cryptChain.put(cryptChain.size() + 1, new ActiveCrypt(parameter));
                } else {
                    ActiveCrypt.CurrentParameter parameter = new ActiveCrypt.CurrentParameter(cryptName);
                    cryptChain.put(cryptChain.size() + 1, new ActiveCrypt(parameter));
                }
            }
        }

        public String doFinal(String text) throws Exception {
            for (ActiveCrypt cryptTool : cryptChain.values()) {
                text = cryptTool.handle(text);
            }
            return text;
        }

        public CryptoChain copy() {
            return new CryptoChain(this);
        }
    }
}
