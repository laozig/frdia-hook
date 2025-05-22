// Hook 检查 Frida Server 端口，绕过端口检测
Java.perform(function () {
    var Socket = Java.use('java.net.Socket');
    Socket.connect.overload('java.net.SocketAddress', 'int').implementation = function (endpoint, timeout) {
        var host = endpoint.toString();
        if (host.indexOf('27042') !== -1 || host.indexOf('27043') !== -1) {
            console.log("[*] Socket.connect called for Frida port: " + host + " (block)");
            throw Java.use('java.io.IOException').$new('Connection refused');
        }
        return this.connect(endpoint, timeout);
    };
}); 