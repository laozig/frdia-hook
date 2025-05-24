/*
 * 脚本名称：阻止maps内存检测.js
 * 功能描述：阻止应用读取/proc/self/maps文件检测内存中的注入工具
 * 
 * 适用场景：
 *   - 绕过应用对Frida、Xposed等工具的内存检测
 *   - 分析具有反注入保护的应用
 *   - 使用Hook工具时避免被应用检测
 *   - 逆向分析带有安全保护的应用
 *   - 配合其他绕过脚本分析受保护应用
 *
 * 使用方法：
 *   1. frida -U -f 目标应用包名 -l 阻止maps内存检测.js --no-pause
 *   2. 或者 frida -U --attach-pid 目标进程PID -l 阻止maps内存检测.js
 *   3. 应用将无法通过读取内存映射文件检测到注入工具
 *
 * 启动方式说明：
 *   - -U: 使用USB连接的设备
 *   - -f: 指定以spawn方式启动的应用包名
 *   - --attach-pid: 附加到已运行的进程
 *   - --no-pause: 注入后不暂停应用执行
 *
 * 工作原理：
 *   Hook libc.so库中的fopen函数，该函数用于打开文件。
 *   许多应用通过读取/proc/self/maps文件来检查进程的内存映射情况，
 *   从而发现Frida、Xposed等工具的特征字符串或内存区域。
 *   脚本检测到应用尝试打开maps文件时，会拦截调用并返回null（打开失败），
 *   使应用无法获取内存映射信息，从而绕过这类检测。
 *
 * 注意事项：
 *   - 应用可能使用其他方式读取maps文件，如open、read等系统调用
 *   - 建议与绕过注入检测.js等脚本配合使用
 *   - 某些应用可能使用Native层的其他检测方法
 *   - 高级保护可能使用多层检测，需要综合多个绕过脚本
 *   - 此脚本主要处理通过fopen读取maps文件的检测方式
 */

// Hook 读取 /proc/self/maps，绕过内存注入、Frida 检测等
// 作用：阻止应用检测自身内存映射，防止通过 maps 检测 Frida、Xposed、动态注入等。
try {
    Interceptor.attach(Module.findExportByName("libc.so", "fopen"), {
        onEnter: function (args) {
            var path = args[0].readCString();
            // 检查是否读取 maps 文件
            if (path.indexOf("/proc/self/maps") !== -1) {
                console.log("[*] fopen called for /proc/self/maps (bypass)");
                this.bypass = true;
            }
        },
        onLeave: function (retval) {
            if (this.bypass) {
                retval.replace(ptr(0)); // 阻止读取
            }
        }
    });
} catch (e) {
    console.log('[!] hook_native_maps error:', e);
} 