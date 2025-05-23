// 监控WebView加载本地文件
Java.perform(function () {
    var WebView = Java.use('android.webkit.WebView');
    WebView.loadUrl.overload('java.lang.String').implementation = function (url) {
        if (url && url.startsWith('file://')) {
            console.log('[*] WebView 加载本地文件: ' + url);
        }
        return this.loadUrl(url);
    };
}); 