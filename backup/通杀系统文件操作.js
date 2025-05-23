/*
 * 脚本名称：通杀系统文件操作.js
 * 功能：自动监控open/read/write/close等系统文件操作，辅助分析文件读写、数据落盘
 * 适用场景：文件加密、数据落盘、反检测、so逆向
 * 使用方法：
 *   1. frida -U -f 包名 -l 通杀系统文件操作.js --no-pause
 *   2. 查看控制台输出，获取文件操作信息
 * 启动方式说明：
 *   - -U 代表USB设备
 *   - -f 代表spawn启动（推荐）
 *   - --no-pause 保证App正常运行
 * 注意事项：
 *   - 某些so需配合反检测脚本
 */
// 通杀系统文件操作
['open', 'read', 'write', 'close', 'fopen', 'fread', 'fwrite', 'fclose'].forEach(function (func) {
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