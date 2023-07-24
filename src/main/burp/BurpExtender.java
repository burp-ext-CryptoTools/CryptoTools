package burp;

public class BurpExtender implements IBurpExtender {
    public static IBurpExtenderCallbacks callback;
    public static IExtensionHelpers helpers;

    ITabClass iTabClass;
    EditorTabClass editorTabClass;
    MenuFactoryClass menuFactoryClass;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {

        callback = callbacks;
        helpers = callbacks.getHelpers();
        callbacks.setExtensionName("Crypto tools");  // 设置插件名称

        iTabClass = new ITabClass();
        menuFactoryClass = new MenuFactoryClass();
        editorTabClass = new EditorTabClass();

        callbacks.addSuiteTab(iTabClass);  // 添加tab
        callbacks.registerMessageEditorTabFactory(editorTabClass);  // 添加数据包编辑tab
        callbacks.registerContextMenuFactory(menuFactoryClass);     // 添加右击菜单
    }

}