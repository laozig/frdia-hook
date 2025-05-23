// 通杀绕过端口进程检测
Java.perform(function () {
    var Socket = Java.use('java.net.Socket');
    Socket.connect.overload('java.net.SocketAddress', 'int').implementation = function (endpoint, timeout) {
        var host = endpoint.toString();
        if (host.indexOf('27042') !== -1 || host.indexOf('27043') !== -1) {
            console.log('[*] Frida端口检测拦截: ' + host + ' (阻断)');
            throw Java.use('java.io.IOException').$new('Connection refused');
        }
        return this.connect(endpoint, timeout);
    };
    var Process = Java.use('java.lang.ProcessBuilder');
    Process.command.overload().implementation = function () {
        var cmd = this.command();
        if (cmd && cmd.toString().indexOf('frida') !== -1) {
            console.log('[*] Frida进程检测拦截: ' + cmd + ' (阻断)');
            return Java.use('java.util.ArrayList').$new();
        }
        return cmd;
    };
}); 