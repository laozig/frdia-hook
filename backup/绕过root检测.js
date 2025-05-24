/*
 * 脚本名称：绕过root检测.js
 * 功能描述：绕过Android应用对设备root状态的检测，使应用无法识别设备是否已root
 * 
 * 适用场景：
 *   - 在已root设备上运行限制root用户使用的应用
 *   - 绕过金融、支付类应用的安全检测
 *   - 分析应用在已root设备上的行为
 *   - 测试应用的root检测能力和安全防护
 *   - 解除应用功能限制
 *
 * 使用方法：
 *   1. frida -U -f 目标应用包名 -l 绕过root检测.js --no-pause
 *   2. 或者 frida -U --attach-pid 目标进程PID -l 绕过root检测.js
 *
 * 启动方式说明：
 *   - -U: 使用USB连接的设备
 *   - -f: 指定以spawn方式启动的应用包名
 *   - --attach-pid: 附加到已运行的进程
 *   - --no-pause: 注入后不暂停应用执行
 *
 * 工作原理：
 *   Hook java.io.File.exists方法，当应用尝试检查su二进制文件或busybox等root相关
 *   文件是否存在时，返回false，让应用误以为设备未root。这是应用检测root最常用的
 *   方法之一。
 *
 * 注意事项：
 *   - 此脚本只涵盖了文件检测这一种root检测方法
 *   - 完整的root检测绕过可能还需要处理以下方面：
 *     1. 检查常见root应用包名
 *     2. 检查系统属性(build.prop)
 *     3. 检查系统分区挂载状态
 *     4. 检查root权限(Runtime.exec "su")
 *     5. Native层检测
 *   - 建议与"通杀绕过Root检测.js"配合使用以获得更全面的绕过效果
 */

// Hook 检查 root 的常用方法，绕过 root 检测
Java.perform(function () {
    var File = Java.use('java.io.File');
    
    // 拦截File.exists方法，用于检测文件是否存在
    File.exists.implementation = function () {
        var path = this.getAbsolutePath();
        
        // 检查路径是否包含root相关关键词
        if (path.indexOf("su") !== -1 || path.indexOf("busybox") !== -1 || 
            path.indexOf("supersu") !== -1 || path.indexOf("magisk") !== -1 ||
            path.indexOf("/sbin/") !== -1 && path.indexOf("su") !== -1) {
            
            console.log("[*] Root检测拦截: " + path + " (返回false)");
            return false;  // 返回false表示文件不存在
        }
        
        // 对于非root检测的文件调用，保持原始行为
        return this.exists();
    };
    
    console.log("[*] 简单root检测绕过已安装");
    console.log("[*] 注意：复杂应用可能需要更全面的root检测绕过");
}); 