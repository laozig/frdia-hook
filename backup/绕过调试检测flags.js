/*
 * 脚本名称：绕过调试检测flags.js
 * 功能描述：绕过应用通过Debug.getFlags()检测调试状态的保护机制
 * 
 * 适用场景：
 *   - 绕过应用的反调试保护
 *   - 分析具有调试检测机制的应用
 *   - 调试受保护的应用功能
 *   - 逆向分析带有安全保护的应用
 *   - 绕过应用在调试状态下的功能限制
 *
 * 使用方法：
 *   1. frida -U -f 目标应用包名 -l 绕过调试检测flags.js --no-pause
 *   2. 或者 frida -U --attach-pid 目标进程PID -l 绕过调试检测flags.js
 *   3. 应用将无法检测到当前处于调试状态
 *
 * 启动方式说明：
 *   - -U: 使用USB连接的设备
 *   - -f: 指定以spawn方式启动的应用包名
 *   - --attach-pid: 附加到已运行的进程
 *   - --no-pause: 注入后不暂停应用执行
 *
 * 工作原理：
 *   Hook android.os.Debug类的getFlags方法，该方法可以返回当前进程的调试标志。
 *   当应用调用此方法检测是否处于调试状态时，脚本会拦截调用并始终返回0（表示无调试标志），
 *   从而欺骗应用认为当前环境是正常的非调试环境，绕过可能的保护措施。
 *
 * 注意事项：
 *   - 应用可能使用多种调试检测方法，建议与其他反调试绕过脚本配合使用
 *   - 某些应用可能使用Native层的调试检测，此脚本对此无效
 *   - 可以配合"通杀绕过调试检测.js"等脚本一起使用
 *   - 部分高级保护可能会检测Frida本身，需要配合反Frida检测脚本
 *   - 此脚本仅处理Java层的Debug.getFlags检测
 */

// Hook getFlags，绕过调试检测
Java.perform(function () {
    var Debug = Java.use('android.os.Debug');
    Debug.getFlags.implementation = function () {
        console.log("[*] Debug.getFlags called (return 0)");
        return 0;
    };
}); 