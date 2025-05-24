/*
 * 脚本名称：绕过native_stat_root检测.js
 * 功能描述：绕过应用在Native层通过stat系统调用检测root特权文件的保护机制
 * 
 * 适用场景：
 *   - 在已root设备上运行拒绝在root环境下工作的应用
 *   - 绕过银行、金融、支付类应用的root检测
 *   - 分析具有root环境检测的应用
 *   - 在root设备上测试应用的正常功能
 *   - 逆向分析具有安全防护的应用
 *
 * 使用方法：
 *   1. frida -U -f 目标应用包名 -l 绕过native_stat_root检测.js --no-pause
 *   2. 或者 frida -U --attach-pid 目标进程PID -l 绕过native_stat_root检测.js
 *   3. 应用将无法通过stat系统调用检测设备的root状态
 *
 * 启动方式说明：
 *   - -U: 使用USB连接的设备
 *   - -f: 指定以spawn方式启动的应用包名
 *   - --attach-pid: 附加到已运行的进程
 *   - --no-pause: 注入后不暂停应用执行
 *
 * 工作原理：
 *   Hook libc.so库中的stat系统调用函数，该函数用于获取文件状态信息。
 *   许多应用通过尝试获取典型的root相关文件（如/system/bin/su、/system/xbin/su或/system/bin/busybox等）
 *   的状态信息来检测设备是否已root。如果stat调用成功，表明这些文件存在。
 *   脚本监控所有对包含"su"或"busybox"等关键词的路径的stat调用，
 *   并在检测到这类调用时修改返回值为-1（表示操作失败），
 *   从而欺骗应用认为这些root相关文件不存在。
 *
 * 注意事项：
 *   - 应用可能使用多种方法检测root状态，此脚本仅处理stat系统调用检测
 *   - 建议与绕过其他root检测脚本配合使用，如绕过native_access_root检测.js
 *   - 某些应用可能通过其他系统调用如access、fopen等检测root文件
 *   - 可以扩展脚本以监控更多可能的root路径检测
 *   - 可以作为通杀绕过Root检测.js的补充使用
 */

// Hook native stat，绕过 native 层 root 检测
Interceptor.attach(Module.findExportByName("libc.so", "stat"), {
    onEnter: function (args) {
        var path = args[0].readCString();
        if (path.indexOf("su") !== -1 || path.indexOf("busybox") !== -1) {
            console.log("[*] stat called for root check: " + path + " (bypass)");
            this.bypass = true;
        }
    },
    onLeave: function (retval) {
        if (this.bypass) {
            retval.replace(-1); // 让检测失败
        }
    }
}); 