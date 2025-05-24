/*
 * 脚本名称：绕过isDebuggerConnected检测.js
 * 功能描述：绕过应用通过检测调试器连接状态实现的反调试保护机制
 * 
 * 适用场景：
 *   - 绕过应用的反调试保护
 *   - 分析拒绝在调试模式下运行的应用
 *   - 调试具有自我保护机制的应用
 *   - 逆向分析具有安全防护的应用
 *   - 绕过应用在调试状态下的特殊行为
 *
 * 使用方法：
 *   1. frida -U -f 目标应用包名 -l 绕过isDebuggerConnected检测.js --no-pause
 *   2. 或者 frida -U --attach-pid 目标进程PID -l 绕过isDebuggerConnected检测.js
 *   3. 应用将无法通过isDebuggerConnected方法检测到调试器
 *
 * 启动方式说明：
 *   - -U: 使用USB连接的设备
 *   - -f: 指定以spawn方式启动的应用包名
 *   - --attach-pid: 附加到已运行的进程
 *   - --no-pause: 注入后不暂停应用执行
 *
 * 工作原理：
 *   Hook android.os.Debug类的isDebuggerConnected方法，该方法用于检测当前进程是否连接了调试器。
 *   许多应用通过调用此方法来识别是否处于被调试状态，并可能在检测到调试器时采取防护措施，
 *   如终止进程、修改程序流程或混淆关键数据。
 *   脚本通过替换该方法的实现，使其始终返回false，从而欺骗应用认为当前没有调试器连接，
 *   绕过可能的保护措施，使应用正常运行。
 *
 * 注意事项：
 *   - 应用可能使用多种调试检测方法，此脚本仅处理isDebuggerConnected检测
 *   - 建议与绕过FLAG_DEBUGGABLE检测.js等脚本配合使用
 *   - 部分应用可能通过Native层检测调试状态，此脚本对此无效
 *   - 可以作为通杀绕过调试检测.js的补充使用
 *   - 某些应用可能会多次或在关键路径上调用此方法进行检测
 */

// Hook 反调试检测，绕过 isDebuggerConnected 检查
Java.perform(function () {
    var Debug = Java.use('android.os.Debug');
    Debug.isDebuggerConnected.implementation = function () {
        console.log("[*] Debug.isDebuggerConnected called, return false");
        return false;
    };
}); 