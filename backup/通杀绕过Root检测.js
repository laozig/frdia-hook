/*
 * 脚本名称：通杀绕过Root检测.js
 * 功能描述：绕过应用对设备Root状态的检测，使应用在已Root设备上正常运行
 * 
 * 适用场景：
 *   - 在已Root设备上运行拒绝在Root环境下工作的应用
 *   - 绕过银行、金融、支付类应用的Root检测
 *   - 分析具有Root检测机制的应用
 *   - 在Root设备上测试应用的正常功能
 *   - 逆向分析具有安全防护的应用
 *
 * 使用方法：
 *   1. frida -U -f 目标应用包名 -l 通杀绕过Root检测.js --no-pause
 *   2. 或者 frida -U --attach-pid 目标进程PID -l 通杀绕过Root检测.js
 *   3. 应用将无法检测到设备的Root状态
 *
 * 启动方式说明：
 *   - -U: 使用USB连接的设备
 *   - -f: 指定以spawn方式启动的应用包名
 *   - --attach-pid: 附加到已运行的进程
 *   - --no-pause: 注入后不暂停应用执行
 *
 * 工作原理：
 *   Hook java.io.File类的exists方法，这是检测Root的最常用方法之一：
 *   
 *   1. 应用通常通过检查常见的Root相关文件路径是否存在来判断设备是否Root：
 *      - /system/bin/su: 超级用户二进制文件
 *      - /system/xbin/su: 另一个常见的su位置
 *      - /sbin/su: 某些自定义ROM中的su位置
 *      - /system/bin/busybox: busybox工具常见于Root设备
 *      - /data/local/tmp/su: 临时su位置
 *      - /data/local/supersu: SuperSU应用目录
 *      - /system/app/Superuser.apk: 超级用户应用
 *      - /data/app/eu.chainfire.supersu: SuperSU包名
 *      - /data/app/com.topjohnwu.magisk: Magisk管理器包名
 *   
 *   2. 脚本检测文件路径是否包含关键词"su"、"busybox"、"magisk"或"root"
 *      如果包含，返回false表示文件不存在，从而欺骗应用认为未检测到Root特征
 *
 * 注意事项：
 *   - 应用可能使用多种方法检测Root，此脚本仅处理基于文件存在的检测
 *   - 建议与绕过native_fopen_root检测.js、绕过native_stat_root检测.js等配合使用
 *   - 某些应用可能通过运行命令或检查系统属性等其他方式检测Root
 *   - 可以扩展脚本以监控更多可能的Root文件路径检测
 *   - 对于高度防护的应用，可能需要更全面的Root隐藏方案
 */
// 通杀绕过Root检测
Java.perform(function () {
    var File = Java.use('java.io.File');
    File.exists.implementation = function () {
        var path = this.getAbsolutePath();
        if (path.indexOf('su') !== -1 || path.indexOf('busybox') !== -1 || path.indexOf('magisk') !== -1 || path.indexOf('root') !== -1) {
            console.log('[*] Root检测拦截: ' + path + ' (返回false)');
            return false;
        }
        return this.exists();
    };
}); 