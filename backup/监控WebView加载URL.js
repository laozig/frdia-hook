// Hook WebView 的 loadUrl 方法，监控所有网页加载
Java.perform(function () {
    var WebView = Java.use("android.webkit.WebView");
    WebView.loadUrl.overload('java.lang.String').implementation = function (url) {
        console.log("[*] WebView.loadUrl called, url: " + url);
        return this.loadUrl(url);
    };
}); 