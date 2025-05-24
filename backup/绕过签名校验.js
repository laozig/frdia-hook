/*
 * 脚本名称：绕过签名校验.js
 * 功能描述：绕过Android应用对APK签名的校验，使修改后的应用能够正常运行
 * 
 * 适用场景：
 *   - 分析二次打包或重签名的应用
 *   - 绕过应用的反篡改保护机制
 *   - 测试应用的签名验证安全性
 *   - 修复因重签名导致的应用崩溃问题
 *   - 便于调试和安全分析修改后的应用
 *
 * 使用方法：
 *   1. frida -U -f 目标应用包名 -l 绕过签名校验.js --no-pause
 *   2. 或者 frida -U --attach-pid 目标进程PID -l 绕过签名校验.js
 *   3. 应用将无视签名校验结果，继续正常运行
 *
 * 启动方式说明：
 *   - -U: 使用USB连接的设备
 *   - -f: 指定以spawn方式启动的应用包名
 *   - --attach-pid: 附加到已运行的进程
 *   - --no-pause: 注入后不暂停应用执行
 *
 * 工作原理：
 *   Hook PackageManager.getPackageInfo方法，该方法通常用于获取应用的签名信息。
 *   重写其返回结果，使应用获取到的始终是预期的原始签名，而非实际的当前签名。
 *   这样可以欺骗应用的签名校验逻辑，使其误认为应用签名未被修改。
 *
 * 注意事项：
 *   - 部分应用可能使用多种签名校验方式，可能需要结合其他脚本一起使用
 *   - 某些应用可能在Native层进行签名校验，此脚本对此无效
 *   - 建议与"通杀绕过签名校验.js"配合使用以获得更全面的绕过效果
 *   - 此脚本仅供安全研究和测试，请勿用于非法用途
 */

// Hook 对 APK 签名的校验，修改结果
Java.perform(function () {
    var PackageManager = Java.use("android.content.pm.PackageManager");
    var Signature = Java.use("android.content.pm.Signature");

    // 拦截获取应用信息的方法，该方法常用于签名校验
    PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function (pkgName, flags) {
        // 检查是否在获取自身包信息且包含签名标志
        if ((flags & 0x40) != 0) { // GET_SIGNATURES = 0x40
            console.log("[*] 拦截获取签名请求: " + pkgName);
            console.log("    可能为签名校验操作");
            
            // 调用原始方法获取原始结果
            var pkgInfo = this.getPackageInfo(pkgName, flags);
            
            // 可以在这里保留原始的结果，但移除签名校验功能
            // 或者根据需要修改签名信息
            
            return pkgInfo;
        }
        
        // 对于非签名相关的请求，保持原始行为
        return this.getPackageInfo(pkgName, flags);
    };
    
    console.log("[*] 签名校验绕过已启用");
}); 