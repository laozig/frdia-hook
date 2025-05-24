/*
 * 脚本名称：通杀绕过端口进程检测.js
 * 功能描述：绕过应用对Frida端口和进程的检测，防止应用识别分析环境
 * 
 * 适用场景：
 *   - 分析具有反Frida保护的应用
 *   - 绕过金融、支付等安全敏感应用的完整性检测
 *   - 调试带有自我保护机制的应用
 *   - 逆向分析高度加固的应用
 *   - 对抗应用的安全防护机制
 *
 * 使用方法：
 *   1. frida -U -f 目标应用包名 -l 通杀绕过端口进程检测.js --no-pause
 *   2. 或者 frida -U --attach-pid 目标进程PID -l 通杀绕过端口进程检测.js
 *   3. 应用将无法检测到Frida的端口(27042/27043)和相关进程
 *
 * 启动方式说明：
 *   - -U: 使用USB连接的设备
 *   - -f: 指定以spawn方式启动的应用包名
 *   - --attach-pid: 附加到已运行的进程
 *   - --no-pause: 注入后不暂停应用执行
 *
 * 工作原理：
 *   1. 拦截Socket连接操作：
 *      Hook java.net.Socket.connect方法，检测目标是否为Frida端口(27042/27043)，
 *      如果是则阻断连接并抛出IOException异常，欺骗应用认为连接被拒绝。
 *   
 *   2. 拦截进程检测操作：
 *      Hook java.lang.ProcessBuilder.command方法，检测命令是否包含"frida"关键词，
 *      如果包含则返回空列表，使应用无法获取Frida相关进程信息。
 *      
 *   这种方式可以有效防止应用通过连接测试或进程列表检测来识别Frida注入行为。
 *
 * 注意事项：
 *   - 高度加固的应用可能使用多种检测方法，可能需要配合其他绕过脚本使用
 *   - 部分应用可能在Native层实现Frida检测，此脚本可能不完全有效
 *   - 建议与绕过Frida检测.js和绕过Frida端口检测.js配合使用
 *   - 某些应用可能使用/proc目录检测，需要额外处理
 *   - 如需更全面的保护，可与反调试和反注入相关脚本组合使用
 */
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