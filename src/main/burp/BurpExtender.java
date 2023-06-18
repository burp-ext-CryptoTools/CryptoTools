package burp;

public class BurpExtender implements IBurpExtender {
    public static IBurpExtenderCallbacks callback;
    public static IExtensionHelpers helpers;

    ITabClass iTabClass;
    EditorTabClass editorTabClass;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {

        callback = callbacks;
        helpers = callbacks.getHelpers();
        iTabClass = new ITabClass();
//        menuFactoryClass = new MenuFactoryClass();
//        ProcessorClass processorClass = new ProcessorClass("test");
        editorTabClass = new EditorTabClass();

        callbacks.setExtensionName("Crypto tools");  // 设置插件名称

        callbacks.addSuiteTab(iTabClass);  // 添加tab
        callbacks.registerMessageEditorTabFactory(editorTabClass);  // 添加数据包编辑tab
//        callbacks.registerIntruderPayloadProcessor(processorClass);
    }

}