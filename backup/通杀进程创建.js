/*
 * 脚本名称：通杀进程创建.js
 * 功能：自动监控fork/execve/system等进程创建相关系统调用，辅助分析子进程、命令执行
 * 适用场景：反检测、进程注入、命令执行分析、so逆向
 * 使用方法：
 *   1. frida -U -f 包名 -l 通杀进程创建.js --no-pause
 *   2. 查看控制台输出，获取进程创建信息
 * 启动方式说明：
 *   - -U 代表USB设备
 *   - -f 代表spawn启动（推荐）
 *   - --no-pause 保证App正常运行
 * 注意事项：
 *   - 某些so需配合反检测脚本
 */
// 通杀进程创建
['fork', 'execve', 'system'].forEach(function (func) {
    try {
        var addr = Module.findExportByName('libc.so', func);
        if (addr) {
            Interceptor.attach(addr, {
                onEnter: function (args) {
                    console.log('[*] ' + func + ' 调用, 参数: ' + args[0]);
                },
                onLeave: function (retval) {
                    console.log('[*] ' + func + ' 返回: ' + retval);
                }
            });
        }
    } catch (e) {}
}); 