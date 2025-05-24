/*
 * 脚本名称：通杀绕过调试检测.js
 * 功能描述：全面绕过Android应用的调试检测机制，同时处理Java层和Native层的检测方法
 * 
 * 适用场景：
 *   - 分析具有反调试保护的Android应用
 *   - 辅助动态分析、插桩和调试加固应用
 *   - 绕过应用程序的安全检测机制
 *   - 配合其他分析工具使用，如Frida、IDA Pro等
 *
 * 使用方法：
 *   1. frida -U -f 目标应用包名 -l 通杀绕过调试检测.js --no-pause
 *   2. 或者 frida -U --attach-pid 目标进程PID -l 通杀绕过调试检测.js
 *
 * 启动方式说明：
 *   - -U: 使用USB连接的设备
 *   - -f: 指定以spawn方式启动的应用包名
 *   - --attach-pid: 附加到已运行的进程
 *   - --no-pause: 注入后不暂停应用执行
 *
 * 工作原理：
 *   1. Java层：Hook android.os.Debug类的关键方法
 *      - isDebuggerConnected: 检测Java调试器连接状态
 *      - getFlags: 获取调试标志位
 *   2. Native层：Hook ptrace系统调用
 *      - 许多应用使用ptrace(PTRACE_TRACEME, 0)来实现自保护
 *      - 应用通过检测能否被ptrace追踪来判断是否被调试
 *
 * 注意事项：
 *   - 部分应用可能采用多种反调试技术组合，可能需要增加其他绕过方法
 *   - 某些高级保护可能检测内存中的Frida本身，可配合其他反检测脚本使用
 *   - 对于高度定制的反调试方案，可能需要针对性开发绕过方法
 */

// 通杀绕过调试检测
Java.perform(function () {
    // 绕过Java层调试检测
    var Debug = Java.use('android.os.Debug');
    
    // 绕过debugger连接检测
    Debug.isDebuggerConnected.implementation = function () {
        console.log('[*] 调试检测拦截: isDebuggerConnected (返回false)');
        return false;
    };
    
    // 绕过调试标志检测
    Debug.getFlags.implementation = function () {
        console.log('[*] 调试检测拦截: getFlags (返回0)');
        return 0;
    };
});

// 绕过Native层ptrace反调试
Interceptor.attach(Module.findExportByName('libc.so', 'ptrace'), {
    onEnter: function (args) {
        console.log('[*] 调试检测拦截: ptrace (失效)');
        args[0] = ptr(-1);  // 修改ptrace的request参数使其失效
    },
    onLeave: function (retval) {
        retval.replace(0);  // 确保ptrace返回成功，避免触发检测
    }
}); 