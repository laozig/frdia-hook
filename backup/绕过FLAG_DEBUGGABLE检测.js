/*
 * 脚本名称：绕过FLAG_DEBUGGABLE检测.js
 * 功能描述：绕过应用通过检测ApplicationInfo.FLAG_DEBUGGABLE标志来识别调试状态的保护机制
 * 
 * 适用场景：
 *   - 绕过应用的反调试保护
 *   - 分析拒绝在调试模式下运行的应用
 *   - 调试具有自我保护机制的应用
 *   - 在非调试环境下模拟调试状态
 *   - 逆向分析具有安全防护的应用
 *
 * 使用方法：
 *   1. frida -U -f 目标应用包名 -l 绕过FLAG_DEBUGGABLE检测.js --no-pause
 *   2. 或者 frida -U --attach-pid 目标进程PID -l 绕过FLAG_DEBUGGABLE检测.js
 *   3. 应用将无法通过FLAG_DEBUGGABLE标志检测到调试状态
 *
 * 启动方式说明：
 *   - -U: 使用USB连接的设备
 *   - -f: 指定以spawn方式启动的应用包名
 *   - --attach-pid: 附加到已运行的进程
 *   - --no-pause: 注入后不暂停应用执行
 *
 * 工作原理：
 *   Hook android.content.pm.ApplicationInfo类的FLAG_DEBUGGABLE静态字段，该字段是一个常量，
 *   用于标识应用是否处于可调试状态。当应用在AndroidManifest.xml中设置了android:debuggable="true"
 *   或者通过其他方式标记为可调试时，ApplicationInfo.flags & ApplicationInfo.FLAG_DEBUGGABLE
 *   的结果将不为零。许多应用通过检查此标志来识别调试状态，并可能采取相应的保护措施。
 *   脚本使用Object.defineProperty重新定义了该常量的getter方法，使其返回0，
 *   从而使所有涉及此常量的比较操作结果为否定，让应用误认为自己不处于调试状态。
 *
 * 注意事项：
 *   - 此脚本仅修改常量值，但应用可能仍通过其他方法检测flags字段
 *   - 某些应用可能使用多种调试检测方法，需要配合其他脚本一起使用
 *   - 建议与绕过isDebuggerConnected检测.js等脚本配合使用
 *   - 部分应用可能使用Native层检测，此脚本对此无效
 *   - 可以作为通杀绕过调试检测.js的补充使用
 */

// Hook ApplicationInfo.FLAG_DEBUGGABLE，绕过调试检测
Java.perform(function () {
    var ApplicationInfo = Java.use('android.content.pm.ApplicationInfo');
    Object.defineProperty(ApplicationInfo, 'FLAG_DEBUGGABLE', {
        get: function () {
            console.log("[*] ApplicationInfo.FLAG_DEBUGGABLE get (return 0)");
            return 0;
        }
    });
}); 