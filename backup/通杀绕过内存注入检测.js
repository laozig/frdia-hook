/*
 * 脚本名称：通杀绕过内存注入检测.js
 * 功能描述：绕过应用对内存映射和进程内存的检测，防止被识别为注入环境
 * 
 * 适用场景：
 *   - 分析具有内存自检机制的应用
 *   - 绕过金融、支付等安全敏感应用的完整性检测
 *   - 逆向高度加固的应用
 *   - 配合Frida/Xposed等注入工具使用
 *   - 对抗应用的反调试和反注入保护
 *
 * 使用方法：
 *   1. frida -U -f 目标应用包名 -l 通杀绕过内存注入检测.js --no-pause
 *   2. 或者 frida -U --attach-pid 目标进程PID -l 通杀绕过内存注入检测.js
 *   3. 应用将无法通过读取内存映射文件检测到注入
 *
 * 启动方式说明：
 *   - -U: 使用USB连接的设备
 *   - -f: 指定以spawn方式启动的应用包名
 *   - --attach-pid: 附加到已运行的进程
 *   - --no-pause: 注入后不暂停应用执行
 *
 * 工作原理：
 *   拦截libc.so库中的fopen系统调用，该函数用于打开文件：
 *   1. 检测目标路径是否为/proc/self/maps或/proc/self/mem
 *      - /proc/self/maps包含进程的内存映射信息，可用于检测注入库
 *      - /proc/self/mem是进程内存的直接映射，可用于检测代码修改
 *   2. 如果检测到这些路径，在onLeave回调中将返回值替换为0(NULL)
 *      表示文件打开失败，从而防止应用读取内存信息检测注入特征
 *
 * 注意事项：
 *   - 应用可能使用其他方法检测内存，如procfs的其他文件或系统API
 *   - 对于使用内联汇编或直接系统调用的应用，此方法可能不完全有效
 *   - 建议与通杀绕过Frida检测.js、通杀绕过反注入检测.js等配合使用
 *   - 某些加固可能使用多种方法检测，需要组合多个绕过脚本
 *   - 适用于大多数常规应用，但对特殊定制的反注入检测可能需要定制方案
 */
// 通杀绕过内存注入检测
Interceptor.attach(Module.findExportByName('libc.so', 'fopen'), {
    onEnter: function (args) {
        var path = args[0].readCString();
        if (path.indexOf('/proc/self/maps') !== -1 || path.indexOf('/proc/self/mem') !== -1) {
            console.log('[*] 内存注入检测拦截: ' + path + ' (阻断)');
            this.bypass = true;
        }
    },
    onLeave: function (retval) {
        if (this.bypass) {
            retval.replace(ptr(0));
        }
    }
}); 