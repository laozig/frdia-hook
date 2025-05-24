/*
 * 脚本名称：绕过注入检测.js
 * 功能描述：绕过应用对Xposed、Frida等注入框架的检测机制
 * 
 * 适用场景：
 *   - 绕过应用的反注入保护
 *   - 分析具有安全保护机制的应用
 *   - 使用Frida工具分析受保护的应用
 *   - 配合其他Hook脚本分析应用
 *   - 调试具有反逆向保护的应用
 *
 * 使用方法：
 *   1. frida -U -f 目标应用包名 -l 绕过注入检测.js --no-pause
 *   2. 或者 frida -U --attach-pid 目标进程PID -l 绕过注入检测.js
 *   3. 应用将无法通过字符串检测发现注入框架的存在
 *
 * 启动方式说明：
 *   - -U: 使用USB连接的设备
 *   - -f: 指定以spawn方式启动的应用包名
 *   - --attach-pid: 附加到已运行的进程
 *   - --no-pause: 注入后不暂停应用执行
 *
 * 工作原理：
 *   Hook java.lang.String类的indexOf方法，该方法常被应用用来检测敏感字符串。
 *   当应用尝试检测字符串中是否包含"xposed"、"substrate"、"frida"等注入框架关键词时，
 *   脚本会拦截这些调用并返回-1（表示未找到），从而欺骗应用认为当前环境中不存在注入框架，
 *   绕过可能的保护措施。
 *
 * 注意事项：
 *   - 应用可能使用多种方式检测注入，如文件检测、内存特征检测等
 *   - 建议与阻止maps内存检测.js等脚本配合使用
 *   - 某些应用可能在Native层进行检测，此脚本对此无效
 *   - 高级保护可能使用多层检测，需要综合多个绕过脚本
 *   - 此脚本主要处理基于字符串查找的简单检测
 */

// Hook 反注入检测，绕过常见注入检测方法
// 作用：拦截字符串查找，绕过对 xposed、substrate、frida 等注入框架的检测。
Java.perform(function () {
    try {
        var StringCls = Java.use('java.lang.String');
        StringCls.indexOf.overload('java.lang.String').implementation = function (str) {
            // 检查是否为注入检测关键字
            if (str && (str.indexOf('xposed') !== -1 || str.indexOf('substrate') !== -1 || str.indexOf('frida') !== -1)) {
                console.log("[*] String.indexOf called for inject detection: " + str + " (return -1)");
                return -1;
            }
            return this.indexOf(str);
        };
    } catch (e) {
        console.log('[!] hook_inject_detection error:', e);
    }
}); 