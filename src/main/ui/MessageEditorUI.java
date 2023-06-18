package ui;

import burp.IHttpService;
import burp.IMessageEditorController;

import javax.swing.*;


public class MessageEditorUI extends JPanel implements IMessageEditorController {
    @Override
    public IHttpService getHttpService() {
        return new IHttpService() {
            @Override
            public String getHost() {
                return "none";
            }

            @Override
            public int getPort() {
                return 1;
            }

            @Override
            public String getProtocol() {
                return "http";
            }
        };
    }

    @Override
    public byte[] getRequest() {
        return null;
    }

    @Override
    public byte[] getResponse() {
        return null;
    }
}
