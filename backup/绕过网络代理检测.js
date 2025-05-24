/*
 * 脚本名称：绕过网络代理检测.js
 * 功能描述：绕过应用对网络代理的检测，使应用在使用代理的环境中正常运行
 * 
 * 适用场景：
 *   - 使用Charles、Fiddler等代理工具分析应用网络流量
 *   - 绕过应用的代理检测保护机制
 *   - 在模拟器或代理环境中测试应用
 *   - 分析具有网络安全保护的应用
 *   - 调试应用的网络通信问题
 *
 * 使用方法：
 *   1. 设置好网络代理（如Charles、Fiddler等）
 *   2. frida -U -f 目标应用包名 -l 绕过网络代理检测.js --no-pause
 *   3. 或者 frida -U --attach-pid 目标进程PID -l 绕过网络代理检测.js
 *   4. 应用将无法检测到当前网络使用了代理
 *
 * 启动方式说明：
 *   - -U: 使用USB连接的设备
 *   - -f: 指定以spawn方式启动的应用包名
 *   - --attach-pid: 附加到已运行的进程
 *   - --no-pause: 注入后不暂停应用执行
 *
 * 工作原理：
 *   Hook java.lang.System类的getProperty方法，该方法可以获取系统属性，包括代理相关的设置。
 *   当应用尝试检查http.proxyHost、http.proxyPort等代理相关的系统属性时，
 *   脚本会拦截这些调用并返回null，使应用认为当前没有设置网络代理，
 *   从而绕过应用可能实施的代理检测保护措施。
 *
 * 注意事项：
 *   - 应用可能使用多种方式检测代理，如NetworkInfo、Proxy类等
 *   - 某些应用可能在Native层检测代理设置
 *   - 对于使用SSL Pinning的应用，需要配合绕过SSL证书校验.js使用
 *   - 部分应用可能检测设备IP、网络接口等信息判断代理
 *   - 此脚本主要处理通过System.getProperty检测代理的情况
 */

// Hook 网络代理检测，绕过代理检测
Java.perform(function () {
    var System = Java.use('java.lang.System');
    System.getProperty.overload('java.lang.String').implementation = function (key) {
        if (key === 'http.proxyHost' || key === 'http.proxyPort' || key === 'https.proxyHost' || key === 'https.proxyPort') {
            console.log("[*] System.getProperty called for proxy check: " + key + " (return null)");
            return null;
        }
        return this.getProperty(key);
    };
}); 