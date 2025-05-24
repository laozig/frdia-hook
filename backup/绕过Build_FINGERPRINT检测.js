/*
 * 脚本名称：绕过Build_FINGERPRINT检测.js
 * 功能描述：绕过应用通过检测系统指纹信息识别模拟器或非标准设备的保护机制
 * 
 * 适用场景：
 *   - 在模拟器上测试拒绝在非真机上运行的应用
 *   - 绕过应用对设备真实性的验证
 *   - 分析具有设备指纹检测的应用
 *   - 测试应用在不同设备环境下的行为
 *   - 规避针对特定设备型号的限制
 *
 * 使用方法：
 *   1. frida -U -f 目标应用包名 -l 绕过Build_FINGERPRINT检测.js --no-pause
 *   2. 或者 frida -U --attach-pid 目标进程PID -l 绕过Build_FINGERPRINT检测.js
 *   3. 应用将读取到伪造的设备指纹信息
 *
 * 启动方式说明：
 *   - -U: 使用USB连接的设备
 *   - -f: 指定以spawn方式启动的应用包名
 *   - --attach-pid: 附加到已运行的进程
 *   - --no-pause: 注入后不暂停应用执行
 *
 * 工作原理：
 *   Hook android.os.Build类的FINGERPRINT静态字段，该字段包含设备的指纹信息，
 *   格式通常为"品牌/产品/设备:Android版本/构建ID/变体:类型/标签"。
 *   许多应用通过检查此值来识别模拟器或非标准设备，脚本使用Object.defineProperty
 *   重新定义了该属性的getter方法，使其始终返回一个模拟真实设备的指纹信息，
 *   从而欺骗应用认为当前运行在真实设备上。
 *
 * 注意事项：
 *   - 可以根据需要修改脚本中的指纹值，以模拟不同的设备
 *   - 某些应用可能同时检查多个Build属性，需要配合其他脚本一起使用
 *   - 建议与绕过Build_MODEL检测.js和绕过Build_MANUFACTURER检测.js一起使用
 *   - 部分应用可能使用JNI层检测，此脚本对此无效
 *   - 可以作为通杀绕过模拟器检测.js的补充使用
 */

// Hook Build.FINGERPRINT，绕过模拟器检测
Java.perform(function () {
    var Build = Java.use('android.os.Build');
    Object.defineProperty(Build, 'FINGERPRINT', {
        get: function () {
            console.log("[*] Build.FINGERPRINT get (return real device)");
            return "google/sdk_gphone_x86/generic_x86:11/RSR1.201013.001/6903274:user/release-keys"; // 可自定义
        }
    });
}); 