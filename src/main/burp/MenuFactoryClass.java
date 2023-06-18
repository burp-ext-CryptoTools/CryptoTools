package burp;

import lib.CryptoChain;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.util.ArrayList;
import java.util.List;

public class MenuFactoryClass implements IContextMenuFactory {
    public static ArrayList<JMenuItem> menu_item_list = new ArrayList<>();

    private IContextMenuInvocation invocation;

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        this.invocation = invocation;
        // 返回菜单列表
        return menu_item_list;
    }

    public String addMenuItem(String itemName, CryptoChain cryptoChain) {
        if ("".equals(itemName))
            return "菜单名不能为空";

        delMenuItem(itemName);

        JMenuItem menuItem = new JMenuItem(itemName);
        menuItem.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // 获取选中的内容
                IHttpRequestResponse[] selectedMessages = invocation.getSelectedMessages();
                boolean isRequest = invocation.getInvocationContext() % 2 == 0;

                if (selectedMessages.length > 0) {
                    IHttpRequestResponse selectedMessage = selectedMessages[0];
                    byte[] packetBytes;
                    if (isRequest)
                        packetBytes = selectedMessage.getRequest();
                    else
                        packetBytes = selectedMessage.getResponse();

                    int[] selectedIndexRange = invocation.getSelectionBounds();

                    String selectedText = "";
                    boolean isStr;
                    try {
                        selectedText = new String(packetBytes).substring(selectedIndexRange[0], selectedIndexRange[1]);
                        isStr = true;
                    } catch (Exception ignored) {
                        byte[] bytes = new byte[selectedIndexRange[1] - selectedIndexRange[0]];
                        System.arraycopy(packetBytes, selectedIndexRange[0], bytes, 0, selectedIndexRange[1] - selectedIndexRange[0]);
                        selectedText = new String(bytes);
                        isStr = false;
                    }

                    try {
                        String result = cryptoChain.doFinal(selectedText);
                        byte[] newPacket;

                        if (isStr) {
                            String s = new String(packetBytes).substring(0, selectedIndexRange[0]) + result + new String(packetBytes).substring(selectedIndexRange[1]);
                            newPacket = s.getBytes();
                        } else {
                            byte[] bytes = new byte[packetBytes.length + result.getBytes().length - selectedText.getBytes().length];
                            System.arraycopy(packetBytes, 0, bytes, 0, selectedIndexRange[0]);
                            System.arraycopy(result.getBytes(), 0, bytes, selectedIndexRange[0], result.getBytes().length);
                            System.arraycopy(packetBytes, selectedIndexRange[1], bytes, selectedIndexRange[0] + result.getBytes().length, selectedIndexRange[1] - selectedIndexRange[0]);
                            newPacket = bytes;
                        }

                        try {
                            if (isRequest)
                                selectedMessage.setRequest(newPacket);
                            else
                                selectedMessage.setResponse(newPacket);
                        } catch (UnsupportedOperationException err) {
                            /*
                            创建文本域显示加解密结果，不知道怎么调用burp自带的 Converted text 框框，暂时使用该方式代替
                             */
                            // 创建一个JTextArea并设置文本
                            JTextArea textArea = new JTextArea();
                            textArea.setText(result);
                            textArea.setPreferredSize(new Dimension(500, 300));
                            textArea.setEditable(false); // 不可编辑
                            textArea.setLineWrap(true); //自动换行
                            textArea.setWrapStyleWord(true); // 换行时保持单词完整

                            // 将JTextArea添加到JScrollPane中
                            JScrollPane scrollPane = new JScrollPane(textArea);

                            // 显示JOptionPane并将JScrollPane添加到其中
                            JOptionPane jOptionPane = new JOptionPane(scrollPane, JOptionPane.PLAIN_MESSAGE);
                            JDialog dialog = jOptionPane.createDialog(null, "结果");
                            dialog.setResizable(true);
                            dialog.setVisible(true);
                        }

                    } catch (Exception ex) {
                        BurpExtender.callback.printError(ex.toString());
                    }
                }

            }
        });

        menu_item_list.add(menuItem);
        refresh();

        return itemName + " 添加成功";
    }

    public String delMenuItem(String itemName) {
        int index = 0;
        for (JMenuItem menu_item : menu_item_list) {
            if (itemName.equals(menu_item.getText())) {
                menu_item_list.remove(index);
                refresh();
                return itemName + " 已删除";
            }
            index += 1;
        }
        return itemName + " 删除失败";
    }

    public static String delAllMenuItem() {
        menu_item_list.clear();

        for (IContextMenuFactory menuFactory : BurpExtender.callback.getContextMenuFactories()) {
            BurpExtender.callback.removeContextMenuFactory(menuFactory);
        }

        return "已全部删除";
    }

    public void refresh() {
        BurpExtender.callback.registerContextMenuFactory(this);
    }
}
