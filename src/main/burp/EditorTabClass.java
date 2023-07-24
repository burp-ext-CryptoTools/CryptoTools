package burp;

import config.autoCryptConfig;
import lib.AutoCrypt;
import ui.AutoCryptConfigUI;
import ui.MessageEditorUI;

import java.awt.*;

public class EditorTabClass implements IMessageEditorTabFactory {
    IExtensionHelpers helpers;
    IBurpExtenderCallbacks callback;
    AutoCryptConfigUI editorTabUI;

    public EditorTabClass() {
        this.helpers = BurpExtender.helpers;
        this.callback = BurpExtender.callback;
    }

    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
        return new PacketCryptTab(controller, editable);
    }

    class PacketCryptTab implements IMessageEditorTab {

        boolean editable;
        boolean isRequest;
        byte[] currentMessage;
        IMessageEditor view;
        IMessageEditorController controller;

        public PacketCryptTab(IMessageEditorController _controller, boolean _editable) {
            editable = _editable;
            controller = _controller;

            view = callback.createMessageEditor(new MessageEditorUI(), true);
        }

        @Override
        public String getTabCaption() {
            return "Crypto tools";
        }

        @Override
        public Component getUiComponent() {
            return view.getComponent();
        }

        @Override
        // 是否在页面中展示 IMessageEditorTab
        public boolean isEnabled(byte[] content, boolean isRequest) {

            try {
                IHttpService httpService = controller.getHttpService();

                // 内层的数据包不显示该插件
                // MessageEditorUI 返回的 httpService host 为 none，port 为 1
                // 应该不会真的有 host 为 none 且 port 为 1 的服务吧，暂无更好的处理方式了
                if (httpService == null || "none".equals(httpService.getHost()) && httpService.getPort() == 1)
                    return false;

                String hostReg = autoCryptConfig.hostReg;

                String host = httpService.getHost();

                return "".equals(hostReg) || hostReg == null || host != null && host.matches(hostReg);
            } catch (Exception e) {
                return true;
            }

        }

        @Override
        // 设置 IMessageEditorTab 中的值
        public void setMessage(byte[] content, boolean isRequest) {
            this.isRequest = isRequest;
            this.currentMessage = content;

            if (content == null || content.length == 0) {
                view.setMessage(new byte[]{}, isRequest);
            } else {
                byte[] newContent = AutoCrypt.unpackPacket(content, helpers, isRequest, true);

                view.setMessage(newContent, isRequest);
            }
        }

        @Override
        // 该方法的返回值将替换原始数据包
        public byte[] getMessage() {
            if (view.isMessageModified()) {
                return AutoCrypt.unpackPacket(view.getMessage(), helpers, isRequest, false);
            } else {
                return currentMessage;
            }
        }

        @Override
        public boolean isModified() {
            return view.isMessageModified();
        }

        @Override
        public byte[] getSelectedData() {
            return view.getSelectedData();
        }
    }
}
