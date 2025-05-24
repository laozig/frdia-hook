/*
 * 脚本名称：绕过Build_MANUFACTURER检测.js
 * 功能描述：绕过应用通过检测设备制造商识别模拟器或非标准设备的保护机制
 * 
 * 适用场景：
 *   - 在模拟器上测试拒绝在非真机上运行的应用
 *   - 绕过应用对特定制造商设备的限制
 *   - 分析具有设备制造商检测的应用
 *   - 测试应用在不同厂商设备上的行为
 *   - 规避针对特定厂商设备的限制功能
 *
 * 使用方法：
 *   1. frida -U -f 目标应用包名 -l 绕过Build_MANUFACTURER检测.js --no-pause
 *   2. 或者 frida -U --attach-pid 目标进程PID -l 绕过Build_MANUFACTURER检测.js
 *   3. 应用将读取到伪造的设备制造商信息
 *
 * 启动方式说明：
 *   - -U: 使用USB连接的设备
 *   - -f: 指定以spawn方式启动的应用包名
 *   - --attach-pid: 附加到已运行的进程
 *   - --no-pause: 注入后不暂停应用执行
 *
 * 工作原理：
 *   Hook android.os.Build类的MANUFACTURER静态字段，该字段包含设备的制造商信息。
 *   模拟器通常使用特定的制造商名称（如"Google"、"unknown"等），许多应用通过检查此值
 *   来识别模拟器或非标准设备。脚本使用Object.defineProperty重新定义了该属性的
 *   getter方法，使其始终返回一个真实设备制造商的名称，从而欺骗应用认为当前运行
 *   在真实设备上。
 *
 * 注意事项：
 *   - 可以根据需要修改脚本中的制造商值，以模拟不同厂商的设备
 *   - 某些应用可能同时检查多个Build属性，需要配合其他脚本一起使用
 *   - 建议与绕过Build_MODEL检测.js和绕过Build_FINGERPRINT检测.js一起使用
 *   - 部分应用可能使用JNI层检测，此脚本对此无效
 *   - 可以作为通杀绕过模拟器检测.js的补充使用
 */

// Hook Build.MANUFACTURER，绕过模拟器检测
Java.perform(function () {
    var Build = Java.use('android.os.Build');
    Object.defineProperty(Build, 'MANUFACTURER', {
        get: function () {
            console.log("[*] Build.MANUFACTURER get (return real device)");
            return "Google"; // 可自定义
        }
    });
}); 