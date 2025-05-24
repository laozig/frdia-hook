/*
 * 脚本名称：监控WebView_JS注入接口.js
 * 功能描述：监控Android WebView中JavaScript接口的注入，用于分析混合应用安全
 * 
 * 适用场景：
 *   - 混合应用(Hybrid App)安全分析
 *   - 检测潜在的JavaScript注入漏洞
 *   - 分析WebView与原生代码间的交互机制
 *   - 逆向分析H5与Native交互的API设计
 *   - 寻找Web与Native桥接层的安全缺陷
 *
 * 使用方法：
 *   1. frida -U -f 目标应用包名 -l 监控WebView_JS注入接口.js --no-pause
 *   2. 或者 frida -U --attach-pid 目标进程PID -l 监控WebView_JS注入接口.js
 *   3. 操作应用中的WebView页面，观察控制台输出的JavaScript接口注入信息
 *
 * 启动方式说明：
 *   - -U: 使用USB连接的设备
 *   - -f: 指定以spawn方式启动的应用包名
 *   - --attach-pid: 附加到已运行的进程
 *   - --no-pause: 注入后不暂停应用执行
 *
 * 工作原理：
 *   Hook android.webkit.WebView类的addJavascriptInterface方法，这是Android应用
 *   向WebView中注入可被JavaScript调用的Java对象的标准API。通过监控这个方法，可以
 *   发现应用暴露给网页JavaScript的所有本地接口，有助于分析潜在的安全风险。
 *
 * 安全风险：
 *   - Android 4.2以下版本使用addJavascriptInterface存在远程代码执行漏洞
 *   - 过度暴露的JavaScript接口可能导致敏感数据泄露或权限提升
 *   - 不安全的接口实现可能被恶意网页利用
 *   - 某些应用可能通过此接口实现应用完整性检测绕过
 */

// Hook WebView 的 addJavascriptInterface，监控 JS 注入接口
Java.perform(function () {
    var WebView = Java.use("android.webkit.WebView");
    
    WebView.addJavascriptInterface.implementation = function (obj, name) {
        console.log("[*] WebView注入JavaScript接口:");
        console.log("    接口名称: " + name);
        console.log("    接口对象: " + obj.getClass().getName());
        
        // 分析接口中的方法
        try {
            var methods = obj.getClass().getDeclaredMethods();
            if (methods.length > 0) {
                console.log("    暴露的方法:");
                for (var i = 0; i < methods.length; i++) {
                    var method = methods[i];
                    // 检查是否有@JavascriptInterface注解
                    var annotations = method.getAnnotations();
                    var hasJsInterface = false;
                    for (var j = 0; j < annotations.length; j++) {
                        if (annotations[j].toString().indexOf("JavascriptInterface") !== -1) {
                            hasJsInterface = true;
                            break;
                        }
                    }
                    // 只打印有@JavascriptInterface注解的方法(Android 4.2+安全机制)
                    if (hasJsInterface || methods.length < 5) { // 如果方法少，也全部打印
                        console.log("      - " + method.getName() + 
                                   (hasJsInterface ? " [@JavascriptInterface]" : " [无注解]"));
                    }
                }
            }
        } catch (e) {
            console.log("    无法分析接口方法: " + e);
        }
        
        // 打印调用堆栈
        console.log("    调用堆栈: \n    " + 
            Java.use("android.util.Log").getStackTraceString(
            Java.use("java.lang.Exception").$new()).split('\n').slice(1, 4).join('\n    '));
            
        // 调用原始方法
        return this.addJavascriptInterface(obj, name);
    };
    
    console.log("[*] WebView JavaScript接口监控已启动");
}); 