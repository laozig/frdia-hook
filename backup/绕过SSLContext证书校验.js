// Hook SSLContext.init，绕过 SSL 抓包检测
Java.perform(function () {
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').implementation = function (km, tm, sr) {
        console.log("[*] SSLContext.init called, bypassing custom TrustManager");
        // 直接传入空 TrustManager，绕过证书校验
        this.init(km, null, sr);
    };
}); 