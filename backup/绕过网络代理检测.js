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