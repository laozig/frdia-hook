/*
 * 脚本名称：通杀绕过沙箱检测.js
 * 功能描述：绕过应用对沙箱环境的检测，使应用在虚拟应用容器中正常运行
 * 
 * 适用场景：
 *   - 在VirtualApp等虚拟应用环境中运行应用
 *   - 使用应用多开工具运行拒绝在沙箱中运行的应用
 *   - 在隔离环境中分析应用行为
 *   - 突破应用的环境限制，进行自动化测试
 *   - 对抗应用的环境检测机制
 *
 * 使用方法：
 *   1. frida -U -f 目标应用包名 -l 通杀绕过沙箱检测.js --no-pause
 *   2. 或者 frida -U --attach-pid 目标进程PID -l 通杀绕过沙箱检测.js
 *   3. 应用将无法检测到运行环境为沙箱环境
 *
 * 启动方式说明：
 *   - -U: 使用USB连接的设备
 *   - -f: 指定以spawn方式启动的应用包名
 *   - --attach-pid: 附加到已运行的进程
 *   - --no-pause: 注入后不暂停应用执行
 *
 * 工作原理：
 *   Hook java.lang.System类的getProperty方法：
 *   1. 拦截对系统属性的请求，检查key是否包含沙箱特征关键词
 *   2. 监控"virtualapp"(VirtualApp)、"sandbox"(沙箱)、"isolate"(隔离)等关键词
 *   3. 如果检测到这些关键词，返回空字符串，欺骗应用无法获取沙箱特征信息
 *
 *   Android应用通常通过检查系统属性或包名特征来判断运行环境是否为沙箱，
 *   通过拦截这些属性的获取并返回空值，可以有效规避沙箱检测。
 *
 * 注意事项：
 *   - 应用可能使用多种方法检测沙箱，如文件路径特征、包名前缀等
 *   - 某些应用可能在Native层实现沙箱检测，此脚本可能不完全有效
 *   - 可与通杀绕过多开检测.js配合使用，增强绕过效果
 *   - 可能需要扩展关键词列表以应对不同的沙箱技术
 *   - 对于高度定制的检测逻辑，可能需要更专门的绕过方案
 */
// 通杀绕过沙箱检测
Java.perform(function () {
    var System = Java.use('java.lang.System');
    System.getProperty.overload('java.lang.String').implementation = function (key) {
        if (key && (key.indexOf('virtualapp') !== -1 || key.indexOf('sandbox') !== -1 || key.indexOf('isolate') !== -1)) {
            console.log('[*] 沙箱检测拦截: ' + key + ' (返回空)');
            return '';
        }
        return this.getProperty(key);
    };
}); 