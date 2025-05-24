/*
 * 脚本名称：通杀绕过反反注入.js
 * 功能描述：绕过应用对Frida等注入工具的检测机制，实现稳定注入和分析
 * 
 * 适用场景：
 *   - 分析具有反注入保护的应用
 *   - 绕过金融、支付等高安全性应用的保护机制
 *   - 调试带有完整性检测的应用
 *   - 逆向分析加固应用的内部逻辑
 *   - 对抗应用的安全自我保护措施
 *
 * 使用方法：
 *   1. frida -U -f 目标应用包名 -l 通杀绕过反反注入.js --no-pause
 *   2. 或者 frida -U --attach-pid 目标进程PID -l 通杀绕过反反注入.js
 *   3. 应用将无法通过dlopen检测到Frida或Substrate等注入框架
 *
 * 启动方式说明：
 *   - -U: 使用USB连接的设备
 *   - -f: 指定以spawn方式启动的应用包名
 *   - --attach-pid: 附加到已运行的进程
 *   - --no-pause: 注入后不暂停应用执行
 *
 * 工作原理：
 *   拦截dlopen系统调用，该函数用于动态加载共享库：
 *   1. 在onEnter回调中检查要加载的库名是否包含"frida"或"substrate"关键词
 *   2. 如果检测到这些关键词，标记该调用需要被绕过
 *   3. 在onLeave回调中，对标记的调用返回空指针(ptr(0))
 *   
 *   这种方式可以防止应用通过尝试加载注入框架相关的库来检测注入环境，
 *   因为返回的空指针表示库加载失败，从而欺骗应用认为这些注入框架不存在。
 *
 * 注意事项：
 *   - 应用可能使用多种方法检测注入，此脚本仅处理基于dlopen的检测
 *   - 建议与通杀绕过反注入检测.js配合使用，增强绕过效果
 *   - 某些应用可能通过检查/proc/maps或/proc/self/maps文件检测，需要额外处理
 *   - 对于高度加固的应用，可能需要与内存隐藏脚本配合使用
 *   - 此脚本需在应用启动前注入才能有最佳效果
 */
// 通杀绕过反反注入
Interceptor.attach(Module.findExportByName('libc.so', 'dlopen'), {
    onEnter: function (args) {
        var soName = args[0].readCString();
        if (soName && (soName.indexOf('frida') !== -1 || soName.indexOf('substrate') !== -1)) {
            console.log('[*] 反反注入检测拦截: ' + soName + ' (阻断)');
            this.bypass = true;
        }
    },
    onLeave: function (retval) {
        if (this.bypass) {
            retval.replace(ptr(0));
        }
    }
}); 