// Hook DNS 解析，监控所有域名解析请求
Java.perform(function () {
    var InetAddress = Java.use('java.net.InetAddress');
    InetAddress.getByName.implementation = function (host) {
        console.log("[*] DNS getByName: " + host);
        return this.getByName(host);
    };
}); 