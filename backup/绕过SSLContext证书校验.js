/*
 * 脚本名称：绕过SSLContext证书校验.js
 * 功能描述：绕过应用对SSL证书的校验，便于HTTPS流量抓包分析
 * 
 * 适用场景：
 *   - 使用Charles、Fiddler等工具抓包HTTPS流量
 *   - 分析应用的网络通信内容
 *   - 测试应用的安全性和漏洞
 *   - 调试应用的网络相关功能
 *   - 分析使用证书固定(SSL Pinning)的应用
 *
 * 使用方法：
 *   1. 配置好抓包工具和证书
 *   2. frida -U -f 目标应用包名 -l 绕过SSLContext证书校验.js --no-pause
 *   3. 或者 frida -U --attach-pid 目标进程PID -l 绕过SSLContext证书校验.js
 *   4. 应用将不再验证SSL证书，可以使用抓包工具查看HTTPS流量
 *
 * 启动方式说明：
 *   - -U: 使用USB连接的设备
 *   - -f: 指定以spawn方式启动的应用包名
 *   - --attach-pid: 附加到已运行的进程
 *   - --no-pause: 注入后不暂停应用执行
 *
 * 工作原理：
 *   Hook javax.net.ssl.SSLContext类的init方法，该方法用于初始化SSL上下文，
 *   并接收KeyManager、TrustManager和SecureRandom参数。TrustManager负责验证服务器证书。
 *   许多应用通过自定义TrustManager实现证书固定(SSL Pinning)，拒绝接受代理证书。
 *   脚本通过将TrustManager参数设置为null，使应用使用默认的信任管理器，
 *   从而接受所有证书（包括代理工具的证书），便于HTTPS流量分析。
 *
 * 注意事项：
 *   - 应用可能使用多种SSL Pinning实现，此脚本仅处理基于SSLContext的检测
 *   - 建议与绕过X509TrustManager.js等脚本配合使用
 *   - 某些应用可能在Native层实现证书校验，此脚本对此无效
 *   - 可以作为通杀绕过SSL Pinning.js的补充使用
 *   - 仅用于应用分析和安全测试，不应用于非法目的
 */

// Hook SSLContext.init，绕过 SSL 抓包检测
Java.perform(function () {
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').implementation = function (km, tm, sr) {
        console.log("[*] SSLContext.init called, bypassing custom TrustManager");
        // 直接传入空 TrustManager，绕过证书校验
        this.init(km, null, sr);
    };
}); 