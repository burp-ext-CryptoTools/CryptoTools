package ui;

import burp.MenuFactoryClass;
import burp.ProcessorClass;
import config.activeCryptConfig;
import config.allCryptoConfig;
import lib.CryptoChains;
import lib.CryptoChains.CryptoChain;

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.lang.reflect.Method;
import java.nio.charset.Charset;
import java.security.Security;

/**
 * 添加加解密链的UI，包括左侧选择列表和右侧已选择的加解密算法的卡片
 */
public class ActiveCryptConfigUI extends JPanel {
    public CryptoChain cryptoChain = new CryptoChain();
    public JPanel selectedPanel;

    public ActiveCryptConfigUI() {
        init();
    }

    public void init() {
        setLayout(new BorderLayout());

        // 上方，接收添加的菜单的命名
        JPanel topPanel = new JPanel();

        JLabel nameLabel = new JLabel("命名： ");
        JTextField nameTextField = new JTextField(30);

        topPanel.add(nameLabel);
        topPanel.add(nameTextField);

        // 中部，主题窗口
        JPanel centerPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.BOTH;

        // 中左部分，可选择的加解密和编码列表
        gbc.gridx = 0;
        gbc.weightx = gbc.weighty = 20;

        centerPanel.add(optionListJPanel(), gbc);

        // 中中部分，已选择的列表
        gbc.gridx = 20;
        gbc.weightx = 80;

        selectedPanel = new JPanel(new GridLayout(0, 1, 0, 0));
        JScrollPane selectedScrollPanel = new JScrollPane(selectedPanel);
        selectedScrollPanel.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);


        centerPanel.add(selectedScrollPanel, gbc);

        // 中右部分，输入输出窗口(暂时去掉)
//        gbc.gridx = 2;
//        gbc.weightx = 60;
//
//        JPanel IOPanel = new JPanel();
//        IOPanel.setBackground(new Color(2000000000));
//
//        centerPanel.add(IOPanel, gbc);

        // 底部，保存按钮
        JPanel bottomPanel = new JPanel();

        JButton addChainjButton = new JButton("添加到加解密链");
        JButton manageButton = new JButton("管理加解密链");
        JButton clearMenuButton = new JButton("清除所有加解密链");

        bottomPanel.add(addChainjButton);
        bottomPanel.add(manageButton);
        bottomPanel.add(clearMenuButton);

        add(topPanel, BorderLayout.NORTH);
        add(centerPanel, BorderLayout.CENTER);
        add(bottomPanel, BorderLayout.SOUTH);

        // 管理所有菜单
        manageButton.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                JDialog jDialog = new JDialog();
                jDialog.setSize(400, 300);
                jDialog.setPreferredSize(new Dimension(400, 300));

                JPanel leftElements = new JPanel(new GridLayout(0, 1, 0, 5));
                for (String cryptoName : CryptoChains.cryptoChainLinkedHashMap.keySet()) {
                    JLabel label = new JLabel(cryptoName);
                    JButton delButton = new JButton("×");
                    JPanel element = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
                    element.add(label);
                    element.add(delButton);
                    leftElements.add(element);

                    delButton.addMouseListener(new MouseAdapter() {
                        @Override
                        public void mouseClicked(MouseEvent e) {
                            // 删除右击菜单
                            MenuFactoryClass.delMenuItem(cryptoName);

                            // 删除Processor
                            ProcessorClass.delProcessor(cryptoName);

                            // 删除自动加解密选择项
                            CryptoChains.cryptoChainLinkedHashMap.remove(cryptoName);
                            CryptoChains.refreshCryptoComboBox();

                            // 更新管理框的条目
                            leftElements.remove(element);
                            leftElements.repaint();
                        }
                    });
                }

                JScrollPane leftScrollPane = new JScrollPane(leftElements);
                leftScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
                jDialog.add(leftScrollPane, BorderLayout.CENTER);

                jDialog.setVisible(true);
            }
        });

        // 添加到加解密链
        addChainjButton.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                String itemName = nameTextField.getText();

                if ("".equals(itemName)) {
                    itemName = JOptionPane.showInputDialog("请输入菜单名");
                    nameTextField.setText(itemName);
                }

                String msg = CryptoChains.addChain(itemName, cryptoChain);
                JOptionPane.showMessageDialog(null, msg, "提示", JOptionPane.INFORMATION_MESSAGE);
            }
        });

        // 清除所有加解密链
        clearMenuButton.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                int option = JOptionPane.showConfirmDialog(centerPanel, "是否清除所有加解密链", "清除所有", JOptionPane.YES_NO_OPTION, JOptionPane.QUESTION_MESSAGE);
                if (option == JOptionPane.YES_OPTION) {

                    // 删除所有 右击菜单
                    MenuFactoryClass.delAllMenuItem();

                    // 删除所有 processor
                    ProcessorClass.removeAllProcessor();

                    // 删除所有自动加解密选择项
                    CryptoChains.cryptoChainLinkedHashMap.clear();
                    CryptoChains.refreshCryptoComboBox();
                }
            }
        });
    }

    /**
     * 左侧选择列表，所有可用的加解密方式
     */
    public JScrollPane optionListJPanel() {
        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));

        for (String option : activeCryptConfig.optionList) {
            JPanel singlePanel = new JPanel();

            JLabel nameLabel = new JLabel(option);
            JButton addButton = new JButton("+");

            addButton.addMouseListener(new MouseAdapter() {
                @Override
                public void mouseClicked(MouseEvent e) {
                    int index = cryptoChain.cardChain.size() + 1;

                    try {
                        Method getCard = CryptoCards.class.getMethod(option + "Card");
                        JPanel card = (JPanel) getCard.invoke(new CryptoCards());

                        cryptoChain.cardChain.put(index, card);

                        // 刷新已选择的列表
                        refreshSelectedPanel();

                    } catch (Exception ex) {
                        throw new RuntimeException(ex);
                    }
                }
            });

            singlePanel.add(nameLabel);
            singlePanel.add(addButton);

            mainPanel.add(singlePanel);
        }

        JScrollPane listScrollPane = new JScrollPane(mainPanel);
        listScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        return listScrollPane;
    }

    /**
     * 上移、下移、删除卡片后更新UI
     */
    public void refreshSelectedPanel() {
        int size = cryptoChain.cardChain.size();
        selectedPanel.removeAll();

        for (int i = 1; i <= size; i++) {
            JPanel card = cryptoChain.cardChain.get(i);
            selectedPanel.add(card);
        }

        for (int i = 0; i < 10; i++) {
            selectedPanel.add(new JPanel());
        }

        selectedPanel.requestFocus();
    }

    /**
     * 创建加解密卡片，通过反射调用
     */
    public class CryptoCards {
        public JPanel urlDecodeCard() {
            return baseCard("urlDecode", null, ActiveCryptConfigUI.this);
        }

        public JPanel urlEncodeCard() {
            JCheckBox checkBox = new JCheckBox("all encode");
            JPanel jPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
            jPanel.add(checkBox);

            return baseCard("urlEncode", jPanel, ActiveCryptConfigUI.this);
        }

        public JPanel base64DecodeCard() {
            return baseCard("base64Decode", null, ActiveCryptConfigUI.this);
        }

        public JPanel base64EncodeCard() {
            return baseCard("base64Encode", null, ActiveCryptConfigUI.this);
        }

        public JPanel hexDecodeCard() {
            return baseCard("hexDecode", null, ActiveCryptConfigUI.this);
        }

        public JPanel hexEncodeCard() {
            return baseCard("hexEncode", null, ActiveCryptConfigUI.this);
        }

        public JPanel htmlDecodeCard() {
            return baseCard("htmlDecode", null, ActiveCryptConfigUI.this);
        }

        public JPanel htmlEncodeCard() {
            return baseCard("htmlEncode", null, ActiveCryptConfigUI.this);
        }

        public JPanel convertCharsetCard() {
            JPanel jPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));

            String[] values = Charset.availableCharsets().keySet().toArray(new String[0]);

            JComboBox<String> box = new JComboBox<>(values);
            jPanel.add(box);

            return baseCard("convertCharset", jPanel, ActiveCryptConfigUI.this);
        }

        public JPanel hashCard() {
            JPanel jPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
            String[] values = Security.getAlgorithms("MessageDigest").toArray(new String[0]);
            JComboBox<String> box = new JComboBox<>(values);
            jPanel.add(box);

            return baseCard("hash", jPanel, ActiveCryptConfigUI.this);
        }

        public JPanel stringReplaceCard() {
            JPanel jPanel = new JPanel();
            jPanel.setLayout(new BoxLayout(jPanel, BoxLayout.PAGE_AXIS));

            JPanel checkPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
            JCheckBox regCheckBox = new JCheckBox("使用正则");

            checkPanel.add(regCheckBox);

            JPanel inputPanel = new JPanel();
            inputPanel.setLayout(new BoxLayout(inputPanel, BoxLayout.LINE_AXIS));

            JLabel findLabel = new JLabel("查找内容: ");
            JTextField findTextField = new JTextField();
            findTextField.setPreferredSize(new Dimension(findTextField.getPreferredSize().width, 5));

            JLabel replaceLabel = new JLabel("替换为: ");
            JTextField replaceTextField = new JTextField();
            replaceTextField.setPreferredSize(new Dimension(replaceTextField.getPreferredSize().width, 5));

            inputPanel.add(findLabel);
            inputPanel.add(findTextField);
            inputPanel.add(replaceLabel);
            inputPanel.add(replaceTextField);

            jPanel.add(checkPanel);
            jPanel.add(inputPanel);

            return baseCard("stringReplace", jPanel, ActiveCryptConfigUI.this);
        }

        public JPanel AESDecryptCard() {
            return cryptoCard("AES", "AESDecrypt", ActiveCryptConfigUI.this);
        }

        public JPanel AESEncryptCard() {
            return cryptoCard("AES", "AESEncrypt", ActiveCryptConfigUI.this);
        }

        public JPanel DESDecryptCard() {
            return cryptoCard("DES", "DESDecrypt", ActiveCryptConfigUI.this);
        }

        public JPanel DESEncryptCard() {
            return cryptoCard("DES", "DESEncrypt", ActiveCryptConfigUI.this);
        }

        public JPanel SM4DecryptCard() {
            return cryptoCard("SM4", "SM4Decrypt", ActiveCryptConfigUI.this);
        }

        public JPanel SM4EncryptCard() {
            return cryptoCard("SM4", "SM4Encrypt", ActiveCryptConfigUI.this);
        }

        public JPanel RSADecryptCard() {
            return cryptoCard("RSA", "RSADecrypt", ActiveCryptConfigUI.this);
        }

        public JPanel RSAEncryptCard() {
            return cryptoCard("RSA", "RSAEncrypt", ActiveCryptConfigUI.this);
        }

        public JPanel SM2DecryptCard() {
            return cryptoCard("SM2", "SM2Decrypt", ActiveCryptConfigUI.this);
        }

        public JPanel SM2EncryptCard() {
            return cryptoCard("SM2", "SM2Encrypt", ActiveCryptConfigUI.this);
        }

        public static JPanel baseCard(String title, JPanel panel, ActiveCryptConfigUI activeCryptConfigUI) {
            // 新建JPanel，作为整体框架
            JPanel basePanel = new JPanel(new GridBagLayout());
            basePanel.setBorder(BorderFactory.createMatteBorder(2, 2, 2, 2, new Color(0, 0, 0)));
            basePanel.setPreferredSize(new Dimension(0, 120));

            // 页面标签
            JPanel labelPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
            JLabel label = new JLabel(title);
            label.setBorder(BorderFactory.createEmptyBorder(5, 5, 20, 0));
            labelPanel.add(label);

            // 新建功能区，包括上移、下移、删除
            JPanel funcPanel = new JPanel();
            funcPanel.setLayout(new GridLayout());
            funcPanel.setBackground(new Color(230, 230, 230));

            JButton upButton = getButton("↑");
            JButton downButton = getButton("↓");
            JButton delButton = getButton("×");

            // 功能区按钮事件
            upButton.addMouseListener(new MouseAdapter() {
                @Override
                public void mouseClicked(MouseEvent e) {
                    for (int i = 1; i <= activeCryptConfigUI.cryptoChain.cardChain.size(); i++) {
                        if (basePanel.equals(activeCryptConfigUI.cryptoChain.cardChain.get(i))) {
                            activeCryptConfigUI.cryptoChain.upItem(i);
                            activeCryptConfigUI.refreshSelectedPanel();
                            return;
                        }
                    }
                }
            });

            downButton.addMouseListener(new MouseAdapter() {
                @Override
                public void mouseClicked(MouseEvent e) {
                    for (int i = 1; i <= activeCryptConfigUI.cryptoChain.cardChain.size(); i++) {
                        if (basePanel.equals(activeCryptConfigUI.cryptoChain.cardChain.get(i))) {
                            activeCryptConfigUI.cryptoChain.downItem(i);
                            activeCryptConfigUI.refreshSelectedPanel();
                            return;
                        }
                    }
                }
            });

            delButton.addMouseListener(new MouseAdapter() {
                @Override
                public void mouseClicked(MouseEvent e) {
                    for (int i = 1; i <= activeCryptConfigUI.cryptoChain.cardChain.size(); i++) {
                        if (basePanel.equals(activeCryptConfigUI.cryptoChain.cardChain.get(i))) {
                            activeCryptConfigUI.cryptoChain.delItem(i);
                            activeCryptConfigUI.selectedPanel.remove(i - 1);
                            activeCryptConfigUI.refreshSelectedPanel();
                            return;
                        }
                    }
                }
            });

            funcPanel.add(upButton);
            funcPanel.add(downButton);
            funcPanel.add(delButton);

            // 组装左边区域，如果有传入panel，将其放入左下方
            JPanel leftPanel = new JPanel();
            leftPanel.setLayout(new BoxLayout(leftPanel, BoxLayout.PAGE_AXIS));

            leftPanel.add(labelPanel);

            if (panel != null) {
                leftPanel.add(panel);
            }

            GridBagConstraints gbc = new GridBagConstraints();
            gbc.fill = GridBagConstraints.BOTH;

            gbc.weightx = gbc.weighty = 999;
            gbc.gridx = gbc.gridy = 0;

            basePanel.add(leftPanel, gbc);

            gbc.gridx = 1;
            gbc.weightx = 1;
            basePanel.add(funcPanel, gbc);

            return basePanel;
        }

        public JPanel cryptoCard(String cipherName, String title, ActiveCryptConfigUI activeCryptConfigUI) {
            JPanel jPanel = new JPanel();
            jPanel.setLayout(new BoxLayout(jPanel, BoxLayout.PAGE_AXIS));

            // 密钥组
            JPanel keyPanel = new JPanel();
            keyPanel.setLayout(new BoxLayout(keyPanel, BoxLayout.LINE_AXIS));

            JLabel keyLabel;
            if ("RSA".equalsIgnoreCase(cipherName) || "SM2".equalsIgnoreCase(cipherName))
                keyLabel = new JLabel("私钥");
            else
                keyLabel = new JLabel("密钥");
            JTextField keyTextField = new JTextField(15);
            JComboBox<String> keyEncodeComboBox = new JComboBox<>(allCryptoConfig.titles4encode);

            keyPanel.add(keyLabel);
            keyPanel.add(Box.createHorizontalStrut(0));
            keyPanel.add(keyTextField);
            keyPanel.add(Box.createHorizontalStrut(0));
            keyPanel.add(keyEncodeComboBox);
            keyPanel.add(Box.createHorizontalStrut(0));

            int height = Math.max(keyTextField.getPreferredSize().height, keyEncodeComboBox.getPreferredSize().height);
            keyTextField.setPreferredSize(new Dimension(keyTextField.getPreferredSize().width, height));
            keyEncodeComboBox.setPreferredSize(new Dimension(keyEncodeComboBox.getPreferredSize().width, height));

            // IV组
            JPanel IVPanel = new JPanel();
            IVPanel.setLayout(new BoxLayout(IVPanel, BoxLayout.LINE_AXIS));

            JLabel IVLabel;
            if ("RSA".equalsIgnoreCase(cipherName) || "SM2".equalsIgnoreCase(cipherName))
                IVLabel = new JLabel("公钥");
            else
                IVLabel = new JLabel("IV");
            JTextField IVTextField = new JTextField(15);
            JComboBox<String> IVEncodeComboBox = new JComboBox<>(allCryptoConfig.titles4encode);

            IVPanel.add(IVLabel);
            IVPanel.add(Box.createHorizontalStrut(0));
            IVPanel.add(IVTextField);
            IVPanel.add(Box.createHorizontalStrut(0));
            IVPanel.add(IVEncodeComboBox);
            IVPanel.add(Box.createHorizontalStrut(0));

            IVTextField.setPreferredSize(new Dimension(IVTextField.getPreferredSize().width, height));
            IVEncodeComboBox.setPreferredSize(new Dimension(IVEncodeComboBox.getPreferredSize().width, height));

            // 算法选择
            JPanel algorithmPanel = new JPanel();
            JLabel algorithmLabel = new JLabel("加密方式");
            JComboBox<String> algorithmComboBox = new JComboBox<>(allCryptoConfig.cryptoMap.get(cipherName));
            algorithmComboBox.setEditable(true);
            algorithmPanel.add(algorithmLabel);
            algorithmPanel.add(algorithmComboBox);

            // 输入格式
            JPanel inputEncodePanel = new JPanel();
            JLabel inputEncodeLabel = new JLabel("输入格式");
            JComboBox<String> inputEncodeComboBox = new JComboBox<>(allCryptoConfig.titles4encode);
            inputEncodePanel.add(inputEncodeLabel);
            inputEncodePanel.add(inputEncodeComboBox);

            // 输出格式
            JPanel outputEncodePanel = new JPanel();
            JLabel outputEncodeLabel = new JLabel("输出格式");
            JComboBox<String> outputEncodeComboBox = new JComboBox<>(allCryptoConfig.titles4encode);
            outputEncodePanel.add(outputEncodeLabel);
            outputEncodePanel.add(outputEncodeComboBox);

            JPanel jPanel1 = new JPanel();
            jPanel1.setLayout(new BoxLayout(jPanel1, BoxLayout.LINE_AXIS));
            JPanel jPanel2 = new JPanel();
            jPanel2.setLayout(new BoxLayout(jPanel2, BoxLayout.LINE_AXIS));

            jPanel1.add(keyPanel);
            jPanel1.add(IVPanel);

            jPanel2.add(algorithmPanel);
            jPanel2.add(inputEncodePanel);
            jPanel2.add(outputEncodePanel);

            jPanel.add(jPanel1);
            jPanel.add(jPanel2);

            return baseCard(title, jPanel, activeCryptConfigUI);
        }

        private static JButton getButton(String text) {
            JButton jButton = new JButton(text);
            jButton.setContentAreaFilled(false);
            jButton.setBorderPainted(false);
            jButton.setMargin(new Insets(0, 2, 0, 2));
            jButton.setFont(new Font("Arial", Font.BOLD, 13));

            return jButton;
        }
    }

}
