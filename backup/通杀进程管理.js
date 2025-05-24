/*
 * 脚本名称：通杀进程管理.js
 * 功能描述：监控和拦截进程相关系统调用函数，便于分析应用的进程操作行为
 * 
 * 适用场景：
 *   - 分析应用对进程的管理和监控行为
 *   - 调试子进程创建和通信问题
 *   - 分析应用的反调试和自我保护机制
 *   - 监控应用尝试杀死其他进程的行为
 *   - 安全性测试和漏洞分析
 *   - 分析检测多开或注入的机制
 *
 * 使用方法：
 *   1. frida -U -f 目标应用包名 -l 通杀进程管理.js --no-pause
 *   2. 或者 frida -U --attach-pid 目标进程PID -l 通杀进程管理.js
 *   3. 操作应用，查看控制台输出的进程相关系统调用信息
 *
 * 启动方式说明：
 *   - -U: 使用USB连接的设备
 *   - -f: 指定以spawn方式启动的应用包名
 *   - --attach-pid: 附加到已运行的进程
 *   - --no-pause: 注入后不暂停应用执行
 *
 * 工作原理：
 *   Hook libc.so库中四个与进程管理相关的关键系统调用函数：
 *   1. ps: 列出系统中的进程
 *   2. kill: 向指定进程发送信号
 *   3. getpid: 获取当前进程ID
 *   4. getppid: 获取父进程ID
 *
 *   对每个函数调用进行监控，记录调用参数和返回值，
 *   便于分析应用如何检测和管理进程，以及实现反调试保护。
 *
 * 注意事项：
 *   - 有些应用可能使用其他方法如exec、fork等创建进程，可能需要额外监控
 *   - 该脚本以监控为主，不修改调用结果，若需要绕过检测需要修改返回值
 *   - 可与通杀绕过端口进程检测.js配合使用，全面监控进程相关保护
 *   - 在高度加固的应用中，可能需要与反调试脚本配合使用
 *   - 如需监控进程创建，建议与监控fork进程创建.js和监控execve进程执行.js配合使用
 */
// 通杀进程管理
['ps', 'kill', 'getpid', 'getppid'].forEach(function (func) {
    try {
        var addr = Module.findExportByName('libc.so', func);
        if (addr) {
            Interceptor.attach(addr, {
                onEnter: function (args) {
                    console.log('[*] ' + func + ' 调用, 参数: ' + args[0]);
                },
                onLeave: function (retval) {
                    console.log('[*] ' + func + ' 返回: ' + retval);
                }
            });
        }
    } catch (e) {}
}); 