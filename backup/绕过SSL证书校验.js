/*
 * 脚本名称：绕过SSL证书校验.js
 * 功能描述：绕过Android应用对SSL/TLS证书的验证，实现中间人攻击流量分析
 * 
 * 适用场景：
 *   - 分析使用HTTPS协议的网络流量
 *   - 对接口加密数据进行解密和分析
 *   - 绕过SSL证书固定(SSL Pinning)机制
 *   - 配合抓包工具进行API调试
 *   - 分析应用与服务器通信机制
 *
 * 使用方法：
 *   1. frida -U -f 目标应用包名 -l 绕过SSL证书校验.js --no-pause
 *   2. 或者 frida -U --attach-pid 目标进程PID -l 绕过SSL证书校验.js
 *   3. 配合Charles、Burp Suite等代理工具使用
 *   4. 确保设备已安装并信任抓包工具的CA证书
 *
 * 启动方式说明：
 *   - -U: 使用USB连接的设备
 *   - -f: 指定以spawn方式启动的应用包名
 *   - --attach-pid: 附加到已运行的进程
 *   - --no-pause: 注入后不暂停应用执行
 *
 * 工作原理：
 *   Hook多个常用的SSL/TLS证书校验相关类和方法，使它们始终返回有效结果，
 *   无论证书是否真实有效。这样应用在遇到代理服务器提供的自签名证书时，
 *   也会误认为证书有效，从而允许中间人获取加密流量。
 *
 * 安全风险：
 *   - 此脚本仅供安全研究和合法测试使用
 *   - 在生产环境中禁用SSL验证会导致严重的安全风险
 *   - 对他人应用使用此脚本可能违反法律法规
 *   - 某些应用可能实施多层防护，仍能检测到SSL拦截
 */

// Hook SSL证书校验相关类和方法，实现绕过证书检查
Java.perform(function() {
    console.log("[*] SSL证书验证绕过脚本已加载");

    // 方法1: Hook SSLContext的TrustManager
    var TrustManager = Java.registerClass({
        name: 'com.frida.TrustManager',
        implements: [Java.use('javax.net.ssl.X509TrustManager')],
        methods: {
            checkClientTrusted: function(chain, authType) {
                console.log("[*] 绕过客户端证书校验");
            },
            checkServerTrusted: function(chain, authType) {
                console.log("[*] 绕过服务器证书校验");
            },
            getAcceptedIssuers: function() {
                console.log("[*] 绕过可接受证书颁发者验证");
                return [];
            }
        }
    });

    // 创建空的HostnameVerifier
    var HostnameVerifier = Java.registerClass({
        name: 'com.frida.HostnameVerifier',
        implements: [Java.use('javax.net.ssl.HostnameVerifier')],
        methods: {
            verify: function(hostname, session) {
                console.log("[*] 绕过主机名验证: " + hostname);
                return true;
            }
        }
    });

    // 方法2: Hook OkHttp的证书固定机制
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, list) {
            console.log("[*] 绕过OkHttp证书固定: " + hostname);
            return;
        };
    } catch(e) {
        console.log("未检测到OkHttp证书固定机制");
    }

    // 替换SSLContext的默认TrustManager
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    SSLContext.init.implementation = function(keyManager, trustManager, secureRandom) {
        console.log("[*] 替换SSLContext的TrustManager");
        var trustManagers = Java.array('javax.net.ssl.TrustManager', [TrustManager.$new()]);
        this.init(keyManager, trustManagers, secureRandom);
    };

    // 设置默认的HostnameVerifier为空实现
    var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
    HttpsURLConnection.setDefaultHostnameVerifier.implementation = function(hostnameVerifier) {
        console.log("[*] 设置默认HostnameVerifier");
        this.setDefaultHostnameVerifier(HostnameVerifier.$new());
    };

    // 设置自定义HostnameVerifier
    HttpsURLConnection.setHostnameVerifier.implementation = function(hostnameVerifier) {
        console.log("[*] 设置实例HostnameVerifier");
        this.setHostnameVerifier(HostnameVerifier.$new());
    };

    console.log("[*] SSL证书验证绕过设置完成");
    console.log("[*] 现在可以使用Charles/Burp等工具抓包分析HTTPS流量");
}); 