package ui;

import burp.IHttpService;
import burp.IMessageEditorController;

import javax.swing.*;
import java.awt.*;


public class MessageEditorUI extends JPanel implements IMessageEditorController {
    IHttpService iHttpService;
    public MessageEditorUI(IHttpService _iHttpService) {
        iHttpService = _iHttpService;
    }

    @Override
    public IHttpService getHttpService() {
        return iHttpService;
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
