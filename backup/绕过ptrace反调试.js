/*
 * 脚本名称：绕过ptrace反调试.js
 * 功能描述：绕过应用通过ptrace系统调用实现的反调试保护机制
 * 
 * 适用场景：
 *   - 绕过应用的反调试保护
 *   - 分析具有自我保护机制的应用
 *   - 调试受保护的Android应用
 *   - 逆向分析带有安全防护的应用
 *   - 分析应用的反调试实现方式
 *
 * 使用方法：
 *   1. frida -U -f 目标应用包名 -l 绕过ptrace反调试.js --no-pause
 *   2. 或者 frida -U --attach-pid 目标进程PID -l 绕过ptrace反调试.js
 *   3. 应用将无法通过ptrace系统调用实现反调试保护
 *
 * 启动方式说明：
 *   - -U: 使用USB连接的设备
 *   - -f: 指定以spawn方式启动的应用包名
 *   - --attach-pid: 附加到已运行的进程
 *   - --no-pause: 注入后不暂停应用执行
 *
 * 工作原理：
 *   Hook libc.so库中的ptrace系统调用函数，该函数是Linux系统中进程跟踪和调试的核心API。
 *   许多应用利用"一个进程只能被一个调试器附加"的特性，通过在启动时自己调用ptrace(PTRACE_TRACEME,...)
 *   或尝试附加到自身，来阻止外部调试器的附加。
 *   脚本通过修改ptrace调用的请求参数为无效值（-1），并强制返回成功值（0），
 *   使应用的反调试保护机制失效，从而允许调试器正常附加和调试。
 *
 * 注意事项：
 *   - 应用可能使用多种反调试技术，此脚本仅处理基于ptrace的检测
 *   - 建议与其他反调试绕过脚本配合使用，如绕过isDebuggerConnected检测.js
 *   - 某些应用可能使用JNI层的其他方法进行反调试
 *   - 可以扩展脚本以处理不同类型的ptrace请求
 *   - 此脚本与阻止自身ptrace调试.js的功能有所不同，后者专注于特定场景
 */

// Hook ptrace，绕过 native 反调试
Interceptor.attach(Module.findExportByName("libc.so", "ptrace"), {
    onEnter: function (args) {
        console.log("[*] ptrace called, bypassing anti-debug");
        args[0] = ptr(-1); // 让 ptrace 失效
    },
    onLeave: function (retval) {
        retval.replace(0);
    }
}); 