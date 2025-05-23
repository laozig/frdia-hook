/*
 * 脚本名称：通杀日志输出.js
 * 功能：自动监控所有日志输出相关API，辅助分析日志泄露、调试信息
 * 适用场景：日志分析、调试信息收集、反检测
 * 使用方法：
 *   1. frida -U -f 包名 -l 通杀日志输出.js --no-pause
 *   2. 查看控制台输出，获取日志输出信息
 * 启动方式说明：
 *   - -U 代表USB设备
 *   - -f 代表spawn启动（推荐）
 *   - --no-pause 保证App正常运行
 * 注意事项：
 *   - 某些壳需配合反检测脚本
 */
// 通杀日志输出
Java.perform(function () {
    var Log = Java.use('android.util.Log');
    ['d', 'e', 'i', 'w', 'v'].forEach(function (level) {
        Log[level].overloads.forEach(function (overload) {
            overload.implementation = function () {
                var args = Array.prototype.slice.call(arguments);
                console.log('[*] Log.' + level + ' 输出: ' + JSON.stringify(args));
                return overload.apply(this, arguments);
            };
        });
    });
    var SystemOut = Java.use('java.lang.System').out.value;
    SystemOut.println.overload('java.lang.String').implementation = function (str) {
        console.log('[*] System.out 输出: ' + str);
        return this.println(str);
    };
    var SystemErr = Java.use('java.lang.System').err.value;
    SystemErr.println.overload('java.lang.String').implementation = function (str) {
        console.log('[*] System.err 输出: ' + str);
        return this.println(str);
    };
}); 