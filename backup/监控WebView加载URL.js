/*
 * 脚本名称：监控WebView加载URL.js
 * 功能描述：监控应用WebView加载的所有URL
 * 
 * 适用场景：
 *   - 分析应用内嵌网页的加载行为
 *   - 发现应用使用的隐藏Web接口
 *   - 追踪混合开发应用的页面跳转逻辑
 *   - 检测潜在的不安全URL加载
 *   - 分析基于WebView的广告加载
 *
 * 使用方法：
 *   1. frida -U -f 目标应用包名 -l 监控WebView加载URL.js --no-pause
 *   2. 或者 frida -U --attach-pid 目标进程PID -l 监控WebView加载URL.js
 *   3. 操作应用中的WebView相关功能，观察控制台输出的URL信息
 *
 * 启动方式说明：
 *   - -U: 使用USB连接的设备
 *   - -f: 指定以spawn方式启动的应用包名
 *   - --attach-pid: 附加到已运行的进程
 *   - --no-pause: 注入后不暂停应用执行
 *
 * 工作原理：
 *   Hook android.webkit.WebView类的loadUrl方法，该方法是WebView加载网页的主要入口点。
 *   当应用使用WebView加载任何URL时，脚本会拦截这些调用并记录URL地址，
 *   从而揭示应用加载的所有网页内容和可能的Web接口调用。
 *
 * 注意事项：
 *   - 可以扩展脚本监控其他WebView加载方法，如loadData、loadDataWithBaseURL等
 *   - 对于使用自定义WebView或其他浏览器组件的应用，可能需要调整Hook点
 *   - 某些应用可能使用加密或混淆的URL参数
 *   - 建议配合网络监控工具分析WebView的网络请求
 *   - 可以结合JavaScript注入分析WebView中的JavaScript执行
 */

// Hook WebView 的 loadUrl 方法，监控所有网页加载
Java.perform(function () {
    var WebView = Java.use("android.webkit.WebView");
    WebView.loadUrl.overload('java.lang.String').implementation = function (url) {
        console.log("[*] WebView.loadUrl called, url: " + url);
        return this.loadUrl(url);
    };
}); 