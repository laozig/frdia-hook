/*
 * 脚本名称：通杀Java反射调用.js
 * 功能：自动监控所有Java反射相关API调用，辅助分析动态调用、反射还原
 * 适用场景：反射壳、动态加载、协议分析、数据还原
 * 使用方法：
 *   1. frida -U -f 包名 -l 通杀Java反射调用.js --no-pause
 *   2. 查看控制台输出，获取反射调用信息
 * 启动方式说明：
 *   - -U 代表USB设备
 *   - -f 代表spawn启动（推荐）
 *   - --no-pause 保证App正常运行
 * 注意事项：
 *   - 某些壳需配合反检测脚本
 */
// 通杀Java反射调用
Java.perform(function () {
    var Method = Java.use('java.lang.reflect.Method');
    Method.invoke.implementation = function (obj, args) {
        console.log('[*] 反射调用: ' + this.getName());
        return this.invoke(obj, args);
    };
    var Constructor = Java.use('java.lang.reflect.Constructor');
    Constructor.newInstance.overload('[Ljava.lang.Object;').implementation = function (args) {
        console.log('[*] 反射构造实例: ' + this.getName());
        return this.newInstance(args);
    };
}); 