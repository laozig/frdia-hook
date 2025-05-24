/*
 * 脚本名称：绕过Frida检测.js
 * 功能描述：绕过Android应用中针对Frida工具的检测机制，实现隐蔽分析
 * 
 * 适用场景：
 *   - 分析具有反Frida检测的应用程序
 *   - 绕过应用的安全防护机制
 *   - 对抗应用的完整性校验
 *   - 分析具有自保护能力的应用
 *   - 辅助其他Frida脚本正常运行
 *
 * 使用方法：
 *   1. 将此脚本与其他分析脚本一起加载
 *   2. frida -U -f 目标应用包名 -l 绕过Frida检测.js --no-pause
 *   3. 或者 frida -U --attach-pid 目标进程PID -l 绕过Frida检测.js
 *
 * 启动方式说明：
 *   - -U: 使用USB连接的设备
 *   - -f: 指定以spawn方式启动的应用包名
 *   - --attach-pid: 附加到已运行的进程
 *   - --no-pause: 注入后不暂停应用执行
 *
 * 工作原理：
 *   Hook java.lang.String.contains方法，当应用尝试检测字符串中是否包含"frida"
 *   或其他Frida相关特征时，返回false，从而绕过基于字符串匹配的检测机制。
 *   这是应用检测Frida最常见的方法之一，通常通过检查进程名、maps文件等实现。
 *
 * 注意事项：
 *   - 此脚本只覆盖了基于String.contains的检测方法
 *   - 完整的反检测可能还需要处理以下方面：
 *     1. 进程列表检测(ps命令)
 *     2. 端口检测(27042端口)
 *     3. /proc/self/maps文件检测
 *     4. Native层检测
 *     5. 线程名称检测
 *   - 建议与"通杀绕过Frida检测.js"配合使用以获得更全面的绕过效果
 */

// Hook 反Frida检测，绕过常见 Frida 检测方法
Java.perform(function () {
    var String = Java.use('java.lang.String');
    
    // 拦截String.contains方法，用于检测字符串中是否包含特定内容
    String.contains.implementation = function (str) {
        // 检查是否在查找Frida相关特征
        if (str && (
            str.indexOf('frida') !== -1 || 
            str.indexOf('gum-js-loop') !== -1 ||
            str.indexOf('gmain') !== -1 ||
            str.indexOf('linjector') !== -1
        )) {
            console.log("[*] Frida检测拦截: " + str + " (返回false)");
            return false;  // 返回false表示未检测到
        }
        
        // 对于非Frida检测的字符串调用，保持原始行为
        return this.contains(str);
    };
    
    // 可选：也可以Hook其他可能用于检测的方法
    /*
    // 拦截文件读取，防止读取/proc/self/maps等文件检测Frida
    var FileInputStream = Java.use('java.io.FileInputStream');
    FileInputStream.$init.overload('java.lang.String').implementation = function(path) {
        if (path.indexOf('/proc/') !== -1 && (path.indexOf('/maps') !== -1 || path.indexOf('/cmdline') !== -1)) {
            console.log("[*] 拦截读取敏感文件: " + path);
            path = "/dev/null"; // 替换为无害文件
        }
        return this.$init(path);
    };
    */
    
    console.log("[*] 基本Frida检测绕过已启用");
    console.log("[*] 注意：复杂应用可能需要更全面的反检测措施");
}); 