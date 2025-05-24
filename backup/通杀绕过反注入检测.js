/*
 * 脚本名称：通杀绕过反注入检测.js
 * 功能描述：在Java层绕过应用对Substrate等注入框架的检测，配合反反注入脚本使用
 * 
 * 适用场景：
 *   - 分析具有多层注入检测的应用
 *   - 绕过应用在Java层实现的注入检测
 *   - 作为Native层反注入绕过的补充
 *   - 调试带有安全防护的金融、支付类应用
 *   - 逆向分析带有加固保护的应用
 *
 * 使用方法：
 *   1. frida -U -f 目标应用包名 -l 通杀绕过反注入检测.js --no-pause
 *   2. 或者 frida -U --attach-pid 目标进程PID -l 通杀绕过反注入检测.js
 *   3. 应用将无法在Java层通过字符串检测识别出注入环境
 *
 * 启动方式说明：
 *   - -U: 使用USB连接的设备
 *   - -f: 指定以spawn方式启动的应用包名
 *   - --attach-pid: 附加到已运行的进程
 *   - --no-pause: 注入后不暂停应用执行
 *
 * 工作原理：
 *   Hook java.lang.String类的indexOf方法：
 *   1. 检测传入的参数是否包含"substrate"或"inject"等与注入相关的关键词
 *   2. 如果检测到这些关键词，返回-1表示未找到，欺骗应用认为不存在注入
 *   
 *   许多应用在Java层通过检查字符串中是否包含敏感关键词来检测注入，
 *   这种检测通常在加载过程、内存遍历或运行时检查中执行。
 *   通过修改indexOf方法的返回值，可以有效防止这类基于字符串的检测。
 *
 * 注意事项：
 *   - 此脚本专注于Java层检测，应与通杀绕过反反注入.js配合使用
 *   - 应用可能使用其他字符串相关方法如contains、startsWith等检测，需视情况扩展
 *   - 某些应用可能使用字节级别比较或哈希检测，此脚本可能不完全有效
 *   - 可扩展关键词列表以涵盖更多注入框架名称
 *   - 建议在应用启动前注入此脚本以获得最佳效果
 */
// 通杀绕过反注入检测
Java.perform(function () {
    var StringCls = Java.use('java.lang.String');
    StringCls.indexOf.overload('java.lang.String').implementation = function (str) {
        if (str && (str.indexOf('substrate') !== -1 || str.indexOf('inject') !== -1)) {
            console.log('[*] 反注入检测拦截: ' + str + ' (返回-1)');
            return -1;
        }
        return this.indexOf(str);
    };
}); 