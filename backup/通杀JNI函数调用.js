/*
 * 脚本名称：通杀JNI函数调用.js
 * 功能：自动监控所有JNI RegisterNatives注册的函数调用，辅助分析Java与Native交互
 * 适用场景：so逆向、动态注册native分析、协议分析
 * 使用方法：
 *   1. frida -U -f 包名 -l 通杀JNI函数调用.js --no-pause
 *   2. 查看控制台输出，获取JNI注册信息
 * 启动方式说明：
 *   - -U 代表USB设备
 *   - -f 代表spawn启动（推荐）
 *   - --no-pause 保证App正常运行
 * 注意事项：
 *   - 某些so需配合反检测脚本
 */
// 通杀JNI函数调用
Interceptor.attach(Module.findExportByName(null, 'RegisterNatives'), {
    onEnter: function (args) {
        var env = args[0];
        var clazz = args[1];
        var methods = args[2];
        var count = args[3].toInt32();
        console.log('[*] RegisterNatives 注册JNI函数, 数量: ' + count);
    }
}); 