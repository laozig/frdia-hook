/*
 * 脚本名称：通杀绕过Xposed检测.js
 * 功能描述：绕过应用对Xposed框架的检测，在使用Xposed框架的设备上正常运行应用
 * 
 * 适用场景：
 *   - 在安装了Xposed/EdXposed等框架的设备上运行防御性应用
 *   - 使用Xposed模块分析拒绝在hook环境中运行的应用
 *   - 针对具有Xposed检测的金融、支付类应用进行测试
 *   - 逆向分析带有安全保护的应用
 *   - 对抗应用的环境检测机制
 *
 * 使用方法：
 *   1. frida -U -f 目标应用包名 -l 通杀绕过Xposed检测.js --no-pause
 *   2. 或者 frida -U --attach-pid 目标进程PID -l 通杀绕过Xposed检测.js
 *   3. 应用将无法通过字符串匹配检测到Xposed框架的存在
 *
 * 启动方式说明：
 *   - -U: 使用USB连接的设备
 *   - -f: 指定以spawn方式启动的应用包名
 *   - --attach-pid: 附加到已运行的进程
 *   - --no-pause: 注入后不暂停应用执行
 *
 * 工作原理：
 *   Hook java.lang.String类的两个关键方法，用于绕过基于字符串的Xposed检测：
 *   
 *   1. 拦截String.contains方法：
 *      - 检查参数是否包含"xposed"或"de.robv.android.xposed"等Xposed特征关键词
 *      - 如检测到这些关键词，返回false表示不包含，绕过检测
 *   
 *   2. 拦截String.indexOf方法：
 *      - 同样检查参数是否包含Xposed相关特征
 *      - 如检测到，返回-1表示未找到，绕过基于索引的检测
 *
 *   许多应用通过搜索内存或字符串匹配来检测Xposed，通过拦截这些基础方法，
 *   可以有效防止应用发现Xposed框架的特征字符串。
 *
 * 注意事项：
 *   - 应用可能使用多种方法检测Xposed，如ClassLoader路径、堆栈检测等
 *   - 对于检查特定Xposed文件或目录的应用，此脚本可能不完全有效
 *   - 建议与绕过反注入检测.js和通杀绕过内存注入检测.js配合使用
 *   - 可能需要扩展关键词列表以应对更多的Xposed特征检测
 *   - 对于高度防护的应用，可能需要结合多个绕过脚本使用
 */
// 通杀绕过Xposed检测
Java.perform(function () {
    var StringCls = Java.use('java.lang.String');
    StringCls.contains.implementation = function (str) {
        if (str && (str.indexOf('xposed') !== -1 || str.indexOf('de.robv.android.xposed') !== -1)) {
            console.log('[*] Xposed检测拦截: ' + str + ' (返回false)');
            return false;
        }
        return this.contains(str);
    };
    StringCls.indexOf.overload('java.lang.String').implementation = function (str) {
        if (str && (str.indexOf('xposed') !== -1 || str.indexOf('de.robv.android.xposed') !== -1)) {
            console.log('[*] Xposed检测拦截: ' + str + ' (返回-1)');
            return -1;
        }
        return this.indexOf(str);
    };
}); 