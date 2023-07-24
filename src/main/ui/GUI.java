package ui;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;

public class GUI extends JFrame {
    JTabbedPane tabbedPane;
    int newIndex = 0;
    public AutoCryptConfigUI autoCryptConfigUI;

    public GUI() {
        init();

        setContentPane(tabbedPane);
        pack();
    }

    /**
     * 初始化整个配置页面（ITab）的基本框架
     */
    public void init() {
        tabbedPane = new JTabbedPane(SwingConstants.TOP, JTabbedPane.SCROLL_TAB_LAYOUT);

        autoCryptConfigUI = new AutoCryptConfigUI();
        tabbedPane.addTab("自动解密配置", autoCryptConfigUI);
        tabbedPane.add("+", null);

        /*
        鼠标事件，点击+添加新标签、双击改名等
         */
        tabbedPane.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                if (e.getSource() instanceof JTabbedPane) {
                    int tabCount = tabbedPane.getTabCount();
                    int selectedIndex = tabbedPane.getSelectedIndex();

                    // 如果选中的是最后的选项（即+），则添加新tab
                    if (selectedIndex == tabCount - 1) {
                        addNewTable(tabCount);
                    }
                    // 双击鼠标，改名
                    else if (e.getClickCount() == 2 && selectedIndex != 0) {
                        JTabbedPane pane = (JTabbedPane) e.getSource();
                        int doubleClickIndex = pane.getSelectedIndex();
                        NewComponent doubleClickComponent = (NewComponent) tabbedPane.getTabComponentAt(doubleClickIndex);

                        JLabel titleLabel = doubleClickComponent.titleLabel;
                        JTextField titleTextField = doubleClickComponent.titleTextField;

                        titleLabel.setVisible(false);
                        titleTextField.setVisible(true);

                        titleTextField.setText(titleLabel.getText());
                        titleTextField.requestFocusInWindow();
                        titleTextField.setCaretPosition(titleTextField.getText().length());
                    } else {
                        ((JTabbedPane) e.getSource()).requestFocusInWindow();
                    }
                }
            }

            @Override
            // 鼠标拖动，准备实现个拖动改变标签位置的功能
            public void mouseDragged(MouseEvent e) {
                super.mouseDragged(e);
            }
        });
    }

    /**
     * 添加新tab，配置多个右击菜单
     * @param count 计数器，表示新增tab的个数
     */
    public void addNewTable(int count) {
        newIndex += 1;
        String title = "加解密链配置" + newIndex;

        tabbedPane.insertTab(title, null, new ActiveCryptConfigUI(), null, count - 1);

        NewComponent newComponent = new NewComponent(title);

        tabbedPane.setTabComponentAt(count - 1, newComponent);
        tabbedPane.setSelectedIndex(count - 1);
    }

    /**
     * 用于新建Tab，在顶部菜单栏展示的Component
     */
    private class NewComponent extends JPanel {
        String title;
        JButton closeButton;
        JLabel titleLabel;
        JTextField titleTextField;

        public NewComponent(String title) {
            this.title = title;
            init();
        }

        private void init() {
            closeButton = new JButton();
            closeButton.setText("×");
            closeButton.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 0));
            closeButton.setBorderPainted(false);
            closeButton.setContentAreaFilled(false);
            closeButton.setFocusable(false);

            closeButton.addMouseListener(new MouseAdapter() {
                @Override
                public void mouseEntered(MouseEvent e) {
                    closeButton.setForeground(Color.red);
                }

                @Override
                public void mouseExited(MouseEvent e) {
                    closeButton.setForeground(Color.black);
                }
            });

            closeButton.addActionListener(e -> {
                JButton button = (JButton) e.getSource();
                NewComponent component = (NewComponent) SwingUtilities.getAncestorOfClass(NewComponent.class, button);

                int index = tabbedPane.indexOfTabComponent(component);
                if (index == tabbedPane.getTabCount() - 2) {
                    tabbedPane.setSelectedIndex(tabbedPane.getTabCount() - 3);
                }

                tabbedPane.remove(index);
            });

            titleLabel = new JLabel(title);
            titleTextField = new JTextField();

            titleTextField.setBackground(new Color(0, 0, 0, 0));
            titleTextField.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 0));
            titleTextField.setOpaque(false);

            titleTextField.addFocusListener(new FocusAdapter() {
                @Override
                public void focusLost(FocusEvent e) {
                    saveTitle();
                }
            });
            titleTextField.addKeyListener(new KeyAdapter() {
                @Override
                public void keyPressed(KeyEvent e) {
                    if (e.getKeyCode() == KeyEvent.VK_ENTER)
                        saveTitle();
                }
            });

            add(titleLabel);
            add(titleTextField);
            add(closeButton);
        }

        public String getTitle() {
            return title;
        }

        public void saveTitle() {
            titleLabel.setText(titleTextField.getText());

            titleLabel.setVisible(true);
            titleTextField.setVisible(false);
        }
    }
}
