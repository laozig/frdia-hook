/*
 * 脚本名称：绕过Frida端口检测.js
 * 功能描述：绕过应用对Frida服务器端口的检测，防止应用发现分析环境
 * 
 * 适用场景：
 *   - 分析具有反Frida检测的应用程序
 *   - 绕过应用的网络端口检测机制
 *   - 对抗基于网络连接的反调试技术
 *   - 配合其他反检测脚本使用
 *   - 分析金融、支付等具有高安全性要求的应用
 *
 * 使用方法：
 *   1. 将此脚本与其他分析脚本一起加载
 *   2. frida -U -f 目标应用包名 -l 绕过Frida端口检测.js --no-pause
 *   3. 或者 frida -U --attach-pid 目标进程PID -l 绕过Frida端口检测.js
 *
 * 启动方式说明：
 *   - -U: 使用USB连接的设备
 *   - -f: 指定以spawn方式启动的应用包名
 *   - --attach-pid: 附加到已运行的进程
 *   - --no-pause: 注入后不暂停应用执行
 *
 * 工作原理：
 *   Hook java.net.Socket类的connect方法，当应用尝试连接到Frida服务器的默认端口
 *   (27042或27043)时，抛出异常使连接失败，从而使应用无法检测到Frida服务器的存在。
 *   许多应用通过尝试连接这些端口来检测设备上是否运行了Frida服务器。
 *
 * 注意事项：
 *   - 此脚本只覆盖了Java层的Socket连接检测
 *   - 某些应用可能使用Native层代码进行端口检测
 *   - 高级应用可能检测其他Frida特征，如进程名、线程名等
 *   - 建议与"绕过Frida检测.js"和"通杀绕过Frida检测.js"配合使用
 *   - 也可以通过修改Frida服务器默认端口来规避检测
 */

// Hook 检查 Frida Server 端口，绕过端口检测
Java.perform(function () {
    var Socket = Java.use('java.net.Socket');
    
    // 拦截Socket连接方法
    Socket.connect.overload('java.net.SocketAddress', 'int').implementation = function (endpoint, timeout) {
        var host = endpoint.toString();
        
        // 检查是否尝试连接Frida服务器端口
        if (host.indexOf('27042') !== -1 || host.indexOf('27043') !== -1) {
            console.log("[*] Frida端口检测拦截: " + host);
            console.log("    模拟连接失败，抛出IOException");
            
            // 抛出连接异常，模拟端口未开放
            throw Java.use('java.io.IOException').$new('Connection refused');
        }
        
        // 对于非Frida端口的连接，保持原始行为
        return this.connect(endpoint, timeout);
    };
    
    // 可选：拦截其他可能用于端口检测的方法
    /*
    // 拦截InetAddress.isReachable方法
    var InetAddress = Java.use('java.net.InetAddress');
    InetAddress.isReachable.overload('int').implementation = function(timeout) {
        var host = this.getHostAddress();
        if (host === '127.0.0.1') {
            console.log("[*] 本地回环地址检测拦截");
            return false;
        }
        return this.isReachable(timeout);
    };
    */
    
    console.log("[*] Frida端口检测绕过已启用");
    console.log("[*] 监控端口: 27042, 27043");
}); 