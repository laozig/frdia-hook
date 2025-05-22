// Hook WebView 的 addJavascriptInterface，监控 JS 注入接口
Java.perform(function () {
    var WebView = Java.use("android.webkit.WebView");
    WebView.addJavascriptInterface.implementation = function (obj, name) {
        console.log("[*] WebView.addJavascriptInterface called, name: " + name + ", obj: " + obj);
        return this.addJavascriptInterface(obj, name);
    };
}); 