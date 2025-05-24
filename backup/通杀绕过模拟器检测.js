/*
 * 脚本名称：通杀绕过模拟器检测.js
 * 功能描述：绕过应用对模拟器环境的检测，使应用在模拟器上正常运行
 * 
 * 适用场景：
 *   - 在Android模拟器上运行拒绝在模拟器上启动的应用
 *   - 使用模拟器进行应用自动化测试
 *   - 在虚拟环境中进行应用安全分析
 *   - 使用Android Studio或其他模拟器进行开发测试
 *   - 绕过游戏、金融、支付等应用的环境检测
 *
 * 使用方法：
 *   1. frida -U -f 目标应用包名 -l 通杀绕过模拟器检测.js --no-pause
 *   2. 或者 frida -U --attach-pid 目标进程PID -l 通杀绕过模拟器检测.js
 *   3. 应用将无法检测到运行环境为模拟器
 *
 * 启动方式说明：
 *   - -U: 使用USB连接的设备
 *   - -f: 指定以spawn方式启动的应用包名
 *   - --attach-pid: 附加到已运行的进程
 *   - --no-pause: 注入后不暂停应用执行
 *
 * 工作原理：
 *   Hook java.lang.System类的getProperty方法：
 *   1. 检测请求的系统属性key是否包含模拟器特征关键词，如"vbox"(VirtualBox)、
 *      "qemu"(QEMU)、"genymotion"或"ro.product"(产品信息)
 *   2. 如果检测到这些关键词，返回空字符串，欺骗应用无法获取模拟器特征信息
 *   
 *   Android应用通常通过检查系统属性来判断运行环境，
 *   例如ro.product.model、ro.hardware、ro.bootloader等。
 *   通过拦截这些属性的获取并返回空值，可以有效规避模拟器检测。
 *
 * 注意事项：
 *   - 应用可能使用多种方法检测模拟器，此脚本仅处理系统属性检测
 *   - 某些应用可能通过/proc/cpuinfo、Build类、电话相关API等检测，需要额外处理
 *   - 可与绕过Build_MODEL检测.js、绕过Build_MANUFACTURER检测.js等配合使用
 *   - 对于高度加固的应用，可能需要组合多个绕过脚本
 *   - 可扩展关键词列表以涵盖更多模拟器特征
 */
// 通杀绕过模拟器检测
Java.perform(function () {
    var System = Java.use('java.lang.System');
    System.getProperty.overload('java.lang.String').implementation = function (key) {
        if (key && (key.indexOf('vbox') !== -1 || key.indexOf('qemu') !== -1 || key.indexOf('genymotion') !== -1 || key.indexOf('ro.product') !== -1)) {
            console.log('[*] 模拟器检测拦截: ' + key + ' (返回空)');
            return '';
        }
        return this.getProperty(key);
    };
}); 