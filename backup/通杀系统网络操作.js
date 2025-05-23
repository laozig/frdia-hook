/*
 * 脚本名称：通杀系统网络操作.js
 * 功能：自动监控socket/connect/send/recv等系统网络操作，辅助分析网络通信、协议明文
 * 适用场景：网络加密、协议分析、反检测、so逆向
 * 使用方法：
 *   1. frida -U -f 包名 -l 通杀系统网络操作.js --no-pause
 *   2. 查看控制台输出，获取网络操作信息
 * 启动方式说明：
 *   - -U 代表USB设备
 *   - -f 代表spawn启动（推荐）
 *   - --no-pause 保证App正常运行
 * 注意事项：
 *   - 某些so需配合反检测脚本
 */
// 通杀系统网络操作
['socket', 'connect', 'send', 'recv', 'sendto', 'recvfrom'].forEach(function (func) {
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