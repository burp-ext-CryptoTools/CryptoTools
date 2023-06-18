package burp;

import ui.GUI;

import java.awt.*;

public class ITabClass implements ITab{
    GUI gui;
//    public AutoCryptConfigUI editorTabUI;

    public ITabClass() {
        gui = new GUI();
//        editorTabUI = gui.editorTabUI;
    }

    @Override
    public String getTabCaption() {
        return "Crypto tools";
    }

    @Override
    public Component getUiComponent() {
        return gui.getComponent(0);
    }

}
