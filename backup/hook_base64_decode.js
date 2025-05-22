// Hook Base64 解码，监控敏感数据解密
Java.perform(function () {
    var Base64 = Java.use("android.util.Base64");
    Base64.decode.overload('java.lang.String', 'int').implementation = function (str, flags) {
        console.log("[*] Base64.decode called, input: " + str);
        var result = this.decode(str, flags);
        console.log("[*] Base64.decode result (bytes): " + result);
        return result;
    };
}); 