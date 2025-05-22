// 绕过 Android SSL Pinning
// 作用：通过替换 SSL 证书校验逻辑，绕过应用的 SSL 证书固定，便于抓包分析 HTTPS 流量。
Java.perform(function () {
    try {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var SSLContext = Java.use('javax.net.ssl.SSLContext');

        // 创建自定义的 TrustManager，接受所有证书
        var TrustManager = Java.registerClass({
            name: 'com.sensepost.test.TrustManager',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function (chain, authType) {},
                checkServerTrusted: function (chain, authType) {},
                getAcceptedIssuers: function () { return []; }
            }
        });

        // 替换 SSLContext 的 init 方法
        SSLContext.init.overload(
            '[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom'
        ).implementation = function (keyManager, trustManager, secureRandom) {
            console.log('[*] Bypassing SSL Pinning');
            // 注入自定义 TrustManager
            this.init(keyManager, [TrustManager.$new()], secureRandom);
        };
    } catch (e) {
        console.log('[!] bypass_ssl_pinning error:', e);
    }
}); 