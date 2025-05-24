/*
 * 脚本名称：通杀绕过Frida检测.js
 * 功能描述：绕过应用对Frida注入框架的检测，使用Frida分析具有自我保护的应用
 * 
 * 适用场景：
 *   - 使用Frida分析具有反Frida保护的应用
 *   - 绕过应用的安全防护机制
 *   - 调试金融、支付等高安全性应用
 *   - 分析具有自我保护能力的应用
 *   - 逆向分析具有反调试特性的应用
 *
 * 使用方法：
 *   1. frida -U -f 目标应用包名 -l 通杀绕过Frida检测.js --no-pause
 *   2. 或者 frida -U --attach-pid 目标进程PID -l 通杀绕过Frida检测.js
 *   3. 应用将无法通过字符串匹配检测到Frida的存在
 *
 * 启动方式说明：
 *   - -U: 使用USB连接的设备
 *   - -f: 指定以spawn方式启动的应用包名
 *   - --attach-pid: 附加到已运行的进程
 *   - --no-pause: 注入后不暂停应用执行
 *
 * 工作原理：
 *   Hook java.lang.String类的两个关键方法，用于绕过基于字符串的Frida检测：
 *   
 *   1. 拦截String.contains方法：
 *      - 检查参数是否包含"frida"或"gum-js-loop"等Frida特征关键词
 *      - 如检测到这些关键词，返回false表示不包含，绕过检测
 *   
 *   2. 拦截String.indexOf方法：
 *      - 同样检查参数是否包含Frida相关特征
 *      - 如检测到，返回-1表示未找到，绕过基于索引的检测
 *
 *   许多应用通过搜索内存或字符串匹配来检测Frida，通过拦截这些基础方法，
 *   可以有效防止应用发现Frida注入环境的特征字符串。
 *
 * 注意事项：
 *   - 应用可能使用多种方法检测Frida，如端口扫描、进程名检测等
 *   - 建议与通杀绕过端口进程检测.js和通杀绕过内存注入检测.js配合使用
 *   - 对于Native层的Frida检测，此脚本可能不完全有效
 *   - 可能需要扩展关键词列表以应对更多的检测模式
 *   - 对于高度防护的应用，可能需要结合多个绕过脚本使用
 */
// 通杀绕过Frida检测
Java.perform(function () {
    var StringCls = Java.use('java.lang.String');
    StringCls.contains.implementation = function (str) {
        if (str && (str.indexOf('frida') !== -1 || str.indexOf('gum-js-loop') !== -1)) {
            console.log('[*] Frida检测拦截: ' + str + ' (返回false)');
            return false;
        }
        return this.contains(str);
    };
    StringCls.indexOf.overload('java.lang.String').implementation = function (str) {
        if (str && (str.indexOf('frida') !== -1 || str.indexOf('gum-js-loop') !== -1)) {
            console.log('[*] Frida检测拦截: ' + str + ' (返回-1)');
            return -1;
        }
        return this.indexOf(str);
    };
}); 