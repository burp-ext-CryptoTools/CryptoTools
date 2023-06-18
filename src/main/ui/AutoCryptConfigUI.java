package ui;

import config.allCryptoConfig;
import config.autoCryptConfig;

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
    GetContentPanel requestPanel;
    GetContentPanel responsePanel;

    public AutoCryptConfigUI() {
//        super(BoxLayout.Y_AXIS);
        init();
    }

    private void init() {
        setLayout(new BorderLayout());

        JButton saveButton = new JButton("save");
        JPanel bottomPanel = new JPanel();
        bottomPanel.add(saveButton);

        JPanel centerPanel = new JPanel();
        centerPanel.setLayout(new GridLayout(1, 2));

        requestPanel = new GetContentPanel(GetContentPanel.REQUEST);
        responsePanel = new GetContentPanel(GetContentPanel.RESPONSE);

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

        add(centerPanel, BorderLayout.CENTER);
        add(bottomPanel, BorderLayout.SOUTH);
    }

    public class GetContentPanel extends JPanel {
        int type;
        static int REQUEST = 1;
        static int RESPONSE = 2;

        JTextField hostTextField;
        JComboBox<String> algorithmComboBox;
        JComboBox<String> methodComboBox;
        JTextField keyTextField;
        ButtonGroup keyButtonGroup;
        JTextField IVTextField;
        ButtonGroup IVButtonGroup;
        ButtonGroup cryptLocationButtonGroup;
        ButtonGroup cryptEncodeButtonGroup;
        JComboBox<String> cryptRegComboBox;
        Color lineColor = new Color(64, 64, 64, 64);

        JPanel line1;
        JPanel line2;
        JLabel keyLabel;
        JLabel IVLabel;

        /**
         * 创建左右两个 JPanel，分别获取处理 request 与 response 的参数
         *
         * @param type {@code GetContentPanel.REQUEST} or {@code GetContentPanel.RESPONSE}
         */
        public GetContentPanel(int type) {
            this.type = type;
            initUI();

            /**
             * 添加监听事件
             * 根据当前选择的加密算法，修改加密模式的可选项。
             * 如果选择公钥加密，则修改密钥和IV分别为私钥、公钥
             */
            algorithmComboBox.addItemListener(e -> {
                String item = (String) e.getItem();
                replaceItemList(allCryptoConfig.cryptoMap.get(item));

                if ("RSA".equalsIgnoreCase(item) || "SM2".equalsIgnoreCase(item)) {
                    keyLabel.setText("私钥(解密)");
                    IVLabel.setText("公钥(加密)");
                    keyTextField.setColumns(20);
                } else {
                    keyLabel.setText("密钥");
                    IVLabel.setText("IV");
                    keyTextField.setColumns(19);
                }
            });
        }

        public void initUI() {
            setLayout(new GridLayout(10, 1, 20, 1));

            JPanel panel1 = getJPanel();
            JPanel panel2 = getJPanel();
            JPanel panel3 = getJPanel();
            JPanel panel4 = getJPanel();
            JPanel panel5 = getJPanel();
            JPanel panel6 = getJPanel();
            Enumeration<AbstractButton> tmpElements;

            // 第一行，host
            if (type == REQUEST) {
                JLabel hostLabel = new JLabel("host匹配（正则）");
                hostTextField = new JTextField(30);

                panel1.setLayout(new FlowLayout(FlowLayout.CENTER));

                panel1.add(hostLabel);
                panel1.add(hostTextField);
            }

            // 第二行，加密方式选择
            JLabel algorithmLabel = new JLabel("加密算法");
            algorithmComboBox = new JComboBox<>(allCryptoConfig.cryptoMap.keySet().toArray(new String[0]));
            JLabel methodJLabel = new JLabel("           加密方式");
            methodComboBox = new JComboBox<>();
            methodComboBox.setPreferredSize(new Dimension(260, methodComboBox.getPreferredSize().height));
            methodComboBox.setEditable(true);

            panel2.add(algorithmLabel);
            panel2.add(algorithmComboBox);
            panel2.add(methodJLabel);
            panel2.add(methodComboBox);

            // 第三行，密钥
            keyLabel = new JLabel("密钥");

            keyTextField = new JTextField(19);

            panel3.add(keyLabel);
            panel3.add(keyTextField);

            keyButtonGroup = getRadioButtonList(allCryptoConfig.titles4encode);
            tmpElements = keyButtonGroup.getElements();

            while (tmpElements.hasMoreElements()) {
                JRadioButton button = (JRadioButton) tmpElements.nextElement();
                panel3.add(button);
            }

            // 第四行，IV
            IVLabel = new JLabel("IV");

            IVTextField = new JTextField(20);

            panel4.add(IVLabel);
            panel4.add(IVTextField);

            IVButtonGroup = getRadioButtonList(allCryptoConfig.titles4encode);
            tmpElements = IVButtonGroup.getElements();

            while (tmpElements.hasMoreElements()) {
                JRadioButton button = (JRadioButton) tmpElements.nextElement();
                panel4.add(button);
            }

            // 第五行，密文位置
            JLabel cryptLocationLabel = new JLabel("密文位置");
            panel5.add(cryptLocationLabel);

            cryptLocationButtonGroup = getRadioButtonList(allCryptoConfig.titles4location);
            tmpElements = cryptLocationButtonGroup.getElements();

            /*
             *  将 url、headers、body 三个单选框加入布局
             *  如果 type==RESPONSE，隐藏 url
             *  默认选中 body
             */
            boolean first = true;
            while (tmpElements.hasMoreElements()) {
                JRadioButton button = (JRadioButton) tmpElements.nextElement();

                if (type == RESPONSE && first) {
                    button.setVisible(false);
                    first = false;
                }

                button.setSelected(!tmpElements.hasMoreElements());

                panel5.add(button);
            }

            JLabel cryptEncodeLabel = new JLabel("               编码方式");
            panel5.add(cryptEncodeLabel);

            cryptEncodeButtonGroup = getRadioButtonList(allCryptoConfig.titles4encode);
            tmpElements = cryptEncodeButtonGroup.getElements();

            while (tmpElements.hasMoreElements()) {
                JRadioButton button = (JRadioButton) tmpElements.nextElement();
                panel5.add(button);
            }

            // 第六行，密文匹配正则
            JLabel cryptLabel = new JLabel("密文匹配（正则）");

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

            panel6.add(cryptLabel);
            panel6.add(cryptRegComboBox);

            // 让panel1不顶格
            // 添加不上 Bounds，就加一个20像素的透明边框吧
            panel1.setBorder(BorderFactory.createMatteBorder(20, 0, 1, 0, new Color(0, 0, 0, 0)));

            if (type == REQUEST) {
                panel2.setBorder(BorderFactory.createMatteBorder(0, 0, 0, 1, lineColor));
                panel3.setBorder(BorderFactory.createMatteBorder(0, 0, 0, 1, lineColor));
                panel4.setBorder(BorderFactory.createMatteBorder(0, 0, 0, 1, lineColor));
                panel5.setBorder(BorderFactory.createMatteBorder(0, 0, 0, 1, lineColor));
                panel6.setBorder(BorderFactory.createMatteBorder(0, 0, 0, 1, lineColor));
            }

            line1 = getLine(true, type == REQUEST ? "request" : "response");
            line2 = getLine();

            add(panel1);
            add(line1);
            add(panel2);
            add(panel3);
            add(panel4);
            add(line2);
            add(panel5);
            add(panel6);
        }

        public JPanel getJPanel() {
            JPanel panel = new JPanel();
            panel.setLayout(new FlowLayout(FlowLayout.LEFT, 5, 5));

            return panel;
        }

        public JPanel getLine() {
            return getLine(false, null);
        }

        public JPanel getLine(Boolean addTitle, String title) {
            JPanel panel = new JPanel();

            MatteBorder border;
            if (addTitle)
                border = BorderFactory.createMatteBorder(1, 0, 0, 0, new Color(64, 64, 64, 64));
            else
                border = BorderFactory.createMatteBorder(1, 0, 0, 1, new Color(64, 64, 64, 64));

            if (addTitle) {
                panel.setBorder(new TitledBorder(border, title, TitledBorder.CENTER, TitledBorder.TOP, new Font(null, Font.PLAIN, 18)));
            } else {
                panel.setBorder(border);
            }

            return panel;
        }

        private void replaceItemList(String[] items) {
            methodComboBox.removeAllItems();
            for (String item : items) {
                methodComboBox.addItem(item);
            }
        }

        private ButtonGroup getRadioButtonList(String[] titles) {
            ButtonGroup buttonGroup = new ButtonGroup();

            boolean first = true;
            for (String title : titles) {
                JRadioButton button = new JRadioButton(title);
                button.setSelected(first);
                first = false;

                buttonGroup.add(button);

                // 让 JRadioButton 失去焦点，获取丝滑体验
                button.addFocusListener(new FocusAdapter() {
                    @Override
                    public void focusGained(FocusEvent e) {
                        button.setFocusable(false);
                    }
                });
            }
            return buttonGroup;
        }
    }

    /**
     * 将用户输入的配置信息保存到全局变量中
     */
    public void save() {
        autoCryptConfig.hostReg = requestPanel.hostTextField.getText();

        autoCryptConfig.requestAlgorithm = (String) requestPanel.algorithmComboBox.getSelectedItem();
        autoCryptConfig.responseAlgorithm = (String) responsePanel.algorithmComboBox.getSelectedItem();
        autoCryptConfig.requestMethod = (String) requestPanel.methodComboBox.getSelectedItem();
        autoCryptConfig.responseMethod = (String) responsePanel.methodComboBox.getSelectedItem();

        autoCryptConfig.requestKey = requestPanel.keyTextField.getText();
        autoCryptConfig.responseKey = responsePanel.keyTextField.getText();
        autoCryptConfig.requestKeyEncode = getJRadioButtonValue(requestPanel.keyButtonGroup);
        autoCryptConfig.responseKeyEncode = getJRadioButtonValue(responsePanel.keyButtonGroup);

        autoCryptConfig.requestIV = requestPanel.IVTextField.getText();
        autoCryptConfig.responseIV = responsePanel.IVTextField.getText();
        autoCryptConfig.requestIVEncode = getJRadioButtonValue(requestPanel.IVButtonGroup);
        autoCryptConfig.responseIVEncode = getJRadioButtonValue(responsePanel.IVButtonGroup);

        autoCryptConfig.requestCryptoLocation = getJRadioButtonValue(requestPanel.cryptLocationButtonGroup);
        autoCryptConfig.responseCryptoLocation = getJRadioButtonValue(responsePanel.cryptLocationButtonGroup);
        autoCryptConfig.requestCryptoEncode = getJRadioButtonValue(requestPanel.cryptEncodeButtonGroup);
        autoCryptConfig.responseCryptoEncode = getJRadioButtonValue(responsePanel.cryptEncodeButtonGroup);
        autoCryptConfig.requestCryptoReg = (String) requestPanel.cryptRegComboBox.getSelectedItem();
        autoCryptConfig.responseCryptoReg = (String) responsePanel.cryptRegComboBox.getSelectedItem();


        // 如果后面需要添加保存配置功能，打算放在这里
    }

    /**
     * 获取单选框组中被选中的单选框的值
     *
     * @param group ButtonGroup，单选框组
     * @return 返回被选中的单选框的值，如 "base64"
     */
    public String getJRadioButtonValue(ButtonGroup group) {
        Enumeration<AbstractButton> elements = group.getElements();

        while (elements.hasMoreElements()) {
            JRadioButton button = (JRadioButton) elements.nextElement();
            if (button.isSelected()) {
                return button.getText();
            }
        }
        return null;
    }
}
