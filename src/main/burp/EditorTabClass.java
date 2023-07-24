package burp;

import config.autoCryptConfig;
import lib.AutoCrypt;
import ui.AutoCryptConfigUI;
import ui.MessageEditorUI;

import java.awt.*;
import java.lang.reflect.Field;
import java.util.Arrays;

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

            view = callback.createMessageEditor(new MessageEditorUI(_controller.getHttpService()), true);
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
            IHttpService httpService = controller.getHttpService();

            if (httpService == null)
                return false;

            /*
            真想不出怎么解决让插件在内层不显示的问题，待添加
             */

            String hostReg = autoCryptConfig.hostReg;
            String host = httpService.getHost();

            return "".equals(hostReg) || host != null && host.matches(hostReg);
        }

        @Override
        // 设置 IMessageEditorTab 中的值
        public void setMessage(byte[] content, boolean isRequest) {
            this.isRequest = isRequest;
            this.currentMessage = content;

            if (content != null || content.length != 0) {
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
