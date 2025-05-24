/*
 * 脚本名称：通杀绕过SSL Pinning.js
 * 功能描述：绕过应用对SSL证书的固定验证，便于HTTPS流量抓包分析
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
 *   2. frida -U -f 目标应用包名 -l 通杀绕过SSL Pinning.js --no-pause
 *   3. 或者 frida -U --attach-pid 目标进程PID -l 通杀绕过SSL Pinning.js
 *   4. 应用将不再验证SSL证书，可以使用抓包工具查看HTTPS流量
 *
 * 启动方式说明：
 *   - -U: 使用USB连接的设备
 *   - -f: 指定以spawn方式启动的应用包名
 *   - --attach-pid: 附加到已运行的进程
 *   - --no-pause: 注入后不暂停应用执行
 *
 * 工作原理：
 *   1. 创建自定义TrustManager实现：
 *      - 实现X509TrustManager接口的所有方法
 *      - 这些方法不执行任何验证，直接返回成功
 *      - getAcceptedIssuers返回空数组，表示接受任何证书
 *   
 *   2. 拦截SSLContext.init方法：
 *      - 此方法用于初始化SSL上下文，接收KeyManager、TrustManager和SecureRandom参数
 *      - 用自定义的信任所有证书的TrustManager替换原有TrustManager
 *      - 绕过应用的证书验证机制，使应用接受任何证书（包括抓包工具的证书）
 *
 *   这种方式可以有效绕过大多数应用实现的SSL证书固定，使HTTPS流量可被抓包分析。
 *
 * 注意事项：
 *   - 应用可能使用多种方式实现SSL Pinning，如Certificate Transparency、公钥固定等
 *   - 高度安全的应用可能在Native层实现证书验证，此脚本可能无效
 *   - 建议与绕过SSLContext证书校验.js、绕过X509TrustManager.js等配合使用
 *   - 对于OkHttp、Retrofit等框架固定证书的实现，可能需要额外处理
 *   - 此方法仅用于应用分析和安全测试，不应用于非法目的
 */
// 通杀绕过SSL Pinning
Java.perform(function () {
    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    var TrustManager = Java.registerClass({
        name: 'com.frida.TrustManager',
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function (chain, authType) {},
            checkServerTrusted: function (chain, authType) {},
            getAcceptedIssuers: function () { return []; }
        }
    });
    SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').implementation = function (km, tm, sr) {
        console.log('[*] SSL Pinning检测拦截: 注入信任管理器');
        this.init(km, [TrustManager.$new()], sr);
    };
}); 