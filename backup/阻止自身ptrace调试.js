/*
 * 脚本名称：阻止自身ptrace调试.js
 * 功能描述：绕过应用通过ptrace系统调用实现的反调试保护机制
 * 
 * 适用场景：
 *   - 绕过应用的反调试保护
 *   - 分析具有自我保护机制的应用
 *   - 调试受保护的Android应用
 *   - 逆向分析带有安全保护的应用
 *   - 配合其他调试工具分析应用
 *
 * 使用方法：
 *   1. frida -U -f 目标应用包名 -l 阻止自身ptrace调试.js --no-pause
 *   2. 或者 frida -U --attach-pid 目标进程PID -l 阻止自身ptrace调试.js
 *   3. 应用将无法通过ptrace检测到被调试状态
 *
 * 启动方式说明：
 *   - -U: 使用USB连接的设备
 *   - -f: 指定以spawn方式启动的应用包名
 *   - --attach-pid: 附加到已运行的进程
 *   - --no-pause: 注入后不暂停应用执行
 *
 * 工作原理：
 *   Hook libc.so库中的ptrace系统调用函数，该函数是Linux系统中进程跟踪和调试的核心API。
 *   许多应用使用ptrace(PTRACE_ATTACH, getpid(), ...)尝试附加到自身进程，
 *   如果成功则表明没有调试器，如果失败则可能存在调试器。
 *   脚本检测到应用尝试使用PTRACE_ATTACH附加到自身进程时，会拦截调用并返回-1，
 *   模拟已被调试的状态，从而绕过应用可能采取的保护措施。
 *
 * 注意事项：
 *   - 应用可能使用多种反调试技术，建议与其他反调试绕过脚本配合使用
 *   - 某些应用可能使用其他系统调用或检测方法
 *   - 部分应用可能在检测到调试状态后采取加密或混淆措施
 *   - 此脚本专门处理ptrace自我附加的检测方法
 *   - 对于复杂的保护机制，可能需要多种绕过技术组合使用
 */

// Hook ptrace(PTRACE_ATTACH, getpid, ...) 反调试，阻止自身被调试
// 作用：阻止调试器通过 ptrace attach 当前进程，实现反调试保护。
try {
    Interceptor.attach(Module.findExportByName("libc.so", "ptrace"), {
        onEnter: function (args) {
            var request = args[0].toInt32();
            var pid = args[1].toInt32();
            // 检查是否为 attach 当前进程
            if (request === 16 /* PTRACE_ATTACH */ && pid === Process.id) {
                console.log("[*] ptrace(PTRACE_ATTACH, self) called (bypass)");
                this.bypass = true;
            }
        },
        onLeave: function (retval) {
            if (this.bypass) {
                retval.replace(-1); // 阻止 attach
            }
        }
    });
} catch (e) {
    console.log('[!] hook_native_ptrace_self error:', e);
} 