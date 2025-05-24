/*
 * 脚本名称：绕过沙箱检测.js
 * 功能描述：绕过Android应用对虚拟环境、模拟器和沙箱环境的检测机制
 * 
 * 适用场景：
 *   - 在模拟器/虚拟机中运行检测沙箱环境的应用
 *   - 绕过应用的安全防护机制
 *   - 在安全分析环境中分析应用行为
 *   - 自动化测试需要在虚拟环境中运行的应用
 *   - 绕过针对安全研究环境的检测逻辑
 *
 * 使用方法：
 *   1. frida -U -f 目标应用包名 -l 绕过沙箱检测.js --no-pause
 *   2. 或者 frida -U --attach-pid 目标进程PID -l 绕过沙箱检测.js
 *   3. 应用将会无法识别当前环境为沙箱/模拟器
 *
 * 启动方式说明：
 *   - -U: 使用USB连接的设备
 *   - -f: 指定以spawn方式启动的应用包名
 *   - --attach-pid: 附加到已运行的进程
 *   - --no-pause: 注入后不暂停应用执行
 *
 * 工作原理：
 *   Hook java.lang.System.getProperty方法，这是应用检测虚拟环境的常用方法之一。
 *   当应用尝试读取可能暴露模拟器/虚拟机特征的系统属性时（如包含vbox、virtualbox或qemu
 *   的属性），返回空字符串，从而隐藏虚拟环境的特征。
 *
 * 常见的沙箱检测方式：
 *   1. 系统属性检测：检查模拟器相关的系统属性
 *   2. 硬件特征检测：检查模拟器特有的硬件信息
 *   3. 传感器检测：检查加速度传感器、陀螺仪等物理传感器数据
 *   4. 电话相关检测：检查IMEI、电话号码等
 *   5. 进程/文件检测：检查模拟器特有的文件或进程
 *
 * 注意事项：
 *   - 此脚本仅涵盖了基于系统属性的检测方法
 *   - 完整的沙箱检测绕过可能还需要处理其他检测方式
 *   - 建议与"通杀绕过沙箱检测.js"配合使用以获得更全面的绕过效果
 */

// Hook 沙箱检测常用方法，绕过沙箱检测
Java.perform(function () {
    var System = Java.use('java.lang.System');
    
    // 拦截系统属性读取方法
    System.getProperty.overload('java.lang.String').implementation = function (key) {
        // 检查是否在查询与模拟器/虚拟机相关的属性
        if (key.indexOf('vbox') !== -1 || 
            key.indexOf('virtualbox') !== -1 || 
            key.indexOf('qemu') !== -1 ||
            key.indexOf('sdk') !== -1 ||
            key.indexOf('emulator') !== -1 ||
            key.indexOf('genymotion') !== -1) {
            
            console.log("[*] 沙箱检测拦截: " + key + " (返回空值)");
            return "";  // 返回空字符串而非实际值
        }
        
        // 特别处理一些常见的检测属性
        if (key === "ro.product.cpu.abi" && this.getProperty(key).indexOf("x86") >= 0) {
            console.log("[*] CPU架构检测拦截 (伪装为ARM)");
            return "armeabi-v7a";  // 伪装为真实设备
        }
        
        // 对于非沙箱检测的属性读取，保持原始行为
        return this.getProperty(key);
    };
    
    // 可选：也可以Hook其他可能用于检测的方法
    /*
    // 拦截Build类字段，避免暴露模拟器信息
    var Build = Java.use('android.os.Build');
    Build.FINGERPRINT.value = "google/walleye/walleye:8.1.0/OPM1.171019.011/4448085:user/release-keys";
    Build.MODEL.value = "Pixel 2";
    Build.MANUFACTURER.value = "Google";
    */
    
    console.log("[*] 沙箱/模拟器环境检测绕过已启用");
    console.log("[*] 监控的关键词: vbox, virtualbox, qemu, sdk, emulator, genymotion");
}); 