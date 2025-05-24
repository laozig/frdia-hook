/*
 * 脚本名称：通杀绕过反反调试.js
 * 功能描述：绕过应用对调试器检测的保护机制，允许成功调试受保护的应用
 * 
 * 适用场景：
 *   - 调试具有反调试保护的Android应用
 *   - 逆向分析带有自我保护的应用
 *   - 对抗各类应用的安全防护机制
 *   - 与其他反调试绕过脚本配合使用
 *   - 分析应用的反调试实现机制
 *
 * 使用方法：
 *   1. frida -U -f 目标应用包名 -l 通杀绕过反反调试.js --no-pause
 *   2. 或者 frida -U --attach-pid 目标进程PID -l 通杀绕过反反调试.js
 *   3. 应用将无法通过getppid和prctl系统调用检测调试状态
 *
 * 启动方式说明：
 *   - -U: 使用USB连接的设备
 *   - -f: 指定以spawn方式启动的应用包名
 *   - --attach-pid: 附加到已运行的进程
 *   - --no-pause: 注入后不暂停应用执行
 *
 * 工作原理：
 *   1. 拦截getppid系统调用：
 *      在Linux系统中，被调试进程的父进程通常是调试器，应用可通过getppid检测。
 *      此脚本拦截getppid调用并返回0，欺骗应用认为自己没有父进程。
 *   
 *   2. 拦截prctl系统调用：
 *      prctl是进程控制函数，常用于设置/获取进程状态，包括反调试保护。
 *      例如prctl(PR_SET_DUMPABLE, 0)可阻止进程被调试，
 *      此脚本拦截prctl调用但不修改结果，主要用于监控应用的反调试行为。
 *
 * 注意事项：
 *   - 应用可能使用多种反调试技术，此脚本仅处理常见的两种检测方法
 *   - 建议与绕过ptrace反调试.js配合使用，处理基于ptrace的检测
 *   - 某些应用可能在Java层使用Debug.isDebuggerConnected()，需要额外处理
 *   - 对于高度加固的应用，可能需要多个反调试脚本同时使用
 *   - 可与通杀绕过调试检测.js配合使用，提高绕过成功率
 */
// 通杀绕过反反调试
Interceptor.attach(Module.findExportByName('libc.so', 'getppid'), {
    onEnter: function (args) {
        console.log('[*] 反反调试检测拦截: getppid (返回0)');
    },
    onLeave: function (retval) {
        retval.replace(0);
    }
});
Interceptor.attach(Module.findExportByName('libc.so', 'prctl'), {
    onEnter: function (args) {
        console.log('[*] 反反调试检测拦截: prctl');
    },
    onLeave: function (retval) {}
}); 