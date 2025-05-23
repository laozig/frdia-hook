/*
 * 脚本名称：自动dump动态注册native表.js
 * 功能：Hook RegisterNatives，输出所有动态注册的native方法表信息
 * 适用场景：so逆向、动态注册native分析、配合IDA分析
 * 使用方法：
 *   1. frida -U -f 包名 -l 自动dump动态注册native表.js --no-pause
 *   2. 查看控制台输出，配合自动化工具dump
 * 启动方式说明：
 *   - -U 代表USB设备
 *   - -f 代表spawn启动（推荐）
 *   - --no-pause 保证App正常运行
 * 注意事项：
 *   - 需root或frida-server有权限
 *   - 某些so需配合反检测脚本
 */
// 自动dump动态注册native表.js
Interceptor.attach(Module.findExportByName(null, 'RegisterNatives'), {
    onEnter: function (args) {
        var env = args[0];
        var clazz = args[1];
        var methods = args[2];
        var count = args[3].toInt32();
        console.log('[*] RegisterNatives 动态注册native方法, 数量: ' + count);
        // 可进一步dump methods结构体内容
    }
}); 