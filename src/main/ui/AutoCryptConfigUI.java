package ui;

import config.autoCryptConfig;
import lib.CryptoChains;

import javax.swing.*;
import javax.swing.border.MatteBorder;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.awt.event.FocusAdapter;
import java.awt.event.FocusEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.Enumeration;

/**
 * ITab的第一个页面，获取用户输入的配置信息
 * 加解密在这里做个中转，方便获取到的配置的传递
 */
public class AutoCryptConfigUI extends JPanel {
    public static GetContentPanel requestPanel;
    public static GetContentPanel responsePanel;
    JTextField hostTextField;
    static boolean REQUEST = true;
    static boolean RESPONSE = false;

    public AutoCryptConfigUI() {
        init();
    }

    private void init() {
        setLayout(new BorderLayout());

        JLabel hostLabel = new JLabel("host匹配（正则）: ");
        hostTextField = new JTextField(30);

        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        topPanel.add(hostLabel);
        topPanel.add(hostTextField);

        JButton saveButton = new JButton("save");
        JPanel bottomPanel = new JPanel();
        bottomPanel.add(saveButton);

        JPanel centerPanel = new JPanel();
        centerPanel.setLayout(new GridLayout(1, 2));

        requestPanel = new GetContentPanel(REQUEST);
        responsePanel = new GetContentPanel(RESPONSE);

        // 点击保存按钮，保存数据
        saveButton.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                save();
                JOptionPane.showMessageDialog(null, "保存成功", "提示", JOptionPane.INFORMATION_MESSAGE);
            }
        });

        centerPanel.add(requestPanel);
        centerPanel.add(responsePanel);

        add(topPanel, BorderLayout.NORTH);
        add(centerPanel, BorderLayout.CENTER);
        add(bottomPanel, BorderLayout.SOUTH);
    }

    private void save() {
        autoCryptConfig.hostReg = hostTextField.getText();
        autoCryptConfig.requestCryptoReg = getJComboBoxSelected(requestPanel.cryptRegComboBox);
        autoCryptConfig.responseCryptoReg = getJComboBoxSelected(responsePanel.cryptRegComboBox);
        autoCryptConfig.requestCryptoLocation = getButtonGroupSelected(requestPanel.locationButtonGroup);
        autoCryptConfig.responseCryptoLocation = getButtonGroupSelected(responsePanel.locationButtonGroup);

        autoCryptConfig.requestEncryptChain = CryptoChains.cryptoChainLinkedHashMap.get(getJComboBoxSelected(requestPanel.encryptoComboBox));
        autoCryptConfig.requestDecryptChain = CryptoChains.cryptoChainLinkedHashMap.get(getJComboBoxSelected(requestPanel.decryptoComboBox));
        autoCryptConfig.responseEncryptChain = CryptoChains.cryptoChainLinkedHashMap.get(getJComboBoxSelected(responsePanel.encryptoComboBox));
        autoCryptConfig.responseDecryptChain = CryptoChains.cryptoChainLinkedHashMap.get(getJComboBoxSelected(responsePanel.decryptoComboBox));
    }

    private String getJComboBoxSelected(JComboBox<String> jComboBox) {
        return jComboBox.getSelectedItem().toString();
    }

    private String getButtonGroupSelected(ButtonGroup buttonGroup) {
        Enumeration<AbstractButton> elements = buttonGroup.getElements();
        while (elements.hasMoreElements()) {
            AbstractButton button = elements.nextElement();
            if (button.isSelected())
                return button.getText();
        }
        return "";
    }

    public class GetContentPanel extends JPanel {
        boolean isRequest;
        JComboBox<String> encryptoComboBox;
        JComboBox<String> decryptoComboBox;
        JComboBox<String> cryptRegComboBox;
        ButtonGroup locationButtonGroup;

        public GetContentPanel(boolean isRequest) {
            this.isRequest = isRequest;
            init();
        }

        private void init() {
            setLayout(new GridLayout(10, 1, 20, 1));

            // 第一行，加密链选择
            JPanel jPanel1 = new JPanel();
            JLabel encryptoLabel = new JLabel("加密链: ");
            encryptoComboBox = getCryptoComboBox();
            encryptoComboBox.setPreferredSize(new Dimension(300, encryptoComboBox.getPreferredSize().height));
            jPanel1.add(encryptoLabel);
            jPanel1.add(encryptoComboBox);

            // 第二行，解密链选择
            JPanel jPanel2 = new JPanel();
            JLabel decryptoLabel = new JLabel("解密链: ");
            decryptoComboBox = getCryptoComboBox();
            decryptoComboBox.setPreferredSize(new Dimension(300, decryptoComboBox.getPreferredSize().height));
            jPanel2.add(decryptoLabel);
            jPanel2.add(decryptoComboBox);

            // 第三行，密文位置
            JPanel jPanel3 = new JPanel();
            JLabel cryptLocationLabel = new JLabel("密文位置: ");
            jPanel3.add(cryptLocationLabel);


            JRadioButton urlRadio = new JRadioButton("url");
            JRadioButton headerRadio = new JRadioButton("header");
            JRadioButton bodyRadio = new JRadioButton("body");

            toSilky(new JRadioButton[]{urlRadio, headerRadio, bodyRadio});

            locationButtonGroup = new ButtonGroup();
            if (isRequest) {
                locationButtonGroup.add(urlRadio);
                jPanel3.add(urlRadio);
            }
            jPanel3.add(headerRadio);
            jPanel3.add(bodyRadio);
            locationButtonGroup.add(headerRadio);
            locationButtonGroup.add(bodyRadio);
            bodyRadio.setSelected(true);

            // 第四行，密文正则
            JPanel jPanel4 = new JPanel();
            JLabel cryptLabel = new JLabel("密文匹配（正则）: ");

            cryptRegComboBox = new JComboBox<>();
            cryptRegComboBox.setEditable(true);
            cryptRegComboBox.setPreferredSize(new Dimension(300, cryptRegComboBox.getPreferredSize().height));

            cryptRegComboBox.addItem(":.?\"([^,}]*)\"");
            cryptRegComboBox.addItem("=([^&]*)");
            cryptRegComboBox.setRenderer(new DefaultListCellRenderer() {
                @Override
                public Component getListCellRendererComponent(JList list, Object value, int index, boolean isSelected, boolean cellHasFocus) {
                    super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
                    if (value != null)
                        if (":.?\"([^,}]*)\"".equals(value))
                            setToolTipText("匹配json格式的所有值");
                        else if ("=([^&]*)".equals(value))
                            setToolTipText("匹配url传参的所有值");
                        else
                            setToolTipText("");
                    return this;
                }
            });

            jPanel4.add(cryptLabel);
            jPanel4.add(cryptRegComboBox);

            // 让panel1不顶格
            // 添加不上 Bounds，就加一个20像素的透明边框吧
            jPanel1.setBorder(BorderFactory.createMatteBorder(20, 0, 1, 0, new Color(0, 0, 0, 0)));

            if (isRequest) {
                MatteBorder border = BorderFactory.createMatteBorder(1, 0, 0, 1, new Color(64, 64, 64, 64));
                setBorder(new TitledBorder(border, "request", TitledBorder.CENTER, TitledBorder.TOP, new Font(null, Font.PLAIN, 18)));
            } else {
                MatteBorder border = BorderFactory.createMatteBorder(1, 0, 0, 0, new Color(64, 64, 64, 64));
                setBorder(new TitledBorder(border, "response", TitledBorder.CENTER, TitledBorder.TOP, new Font(null, Font.PLAIN, 18)));
            }

            add(jPanel1);
            add(jPanel2);
            add(jPanel3);
            add(jPanel4);
        }

        private JComboBox<String> getCryptoComboBox() {
            JComboBox<String> jComboBox = new JComboBox<>();
            jComboBox.addItem("暂无选择, 请添加");

            return jComboBox;
        }

        /**
         * 让JRadioButton失去焦点，使体验更丝滑
         */
        private void toSilky(JRadioButton[] radioArray) {
            for (JRadioButton radio : radioArray) {
                radio.addFocusListener(new FocusAdapter() {
                    @Override
                    public void focusGained(FocusEvent e) {
                        radio.setFocusable(false);
                    }
                });
            }
        }

        /**
         * 更新加解密链的JComboBox
         * @param items JComboBox展示的内容
         */
        public void refreshCryptoComboBox(String[] items){
            encryptoComboBox.removeAllItems();
            decryptoComboBox.removeAllItems();

            if (items.length > 0) {
                encryptoComboBox.addItem("---请下拉选择---");
                decryptoComboBox.addItem("---请下拉选择---");

                for (String item : items) {
                    encryptoComboBox.addItem(item);
                    decryptoComboBox.addItem(item);
                }
            }else {
                encryptoComboBox.addItem("暂无选择, 请添加");
                decryptoComboBox.addItem("暂无选择, 请添加");
            }
        }
    }

}
