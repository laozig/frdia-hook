/*
 * 脚本名称：通杀Native加密算法自吐.js
 * 功能：自动监控so库中常见加密算法（如MD5、SHA1、SHA256、AES等）的参数和返回值
 * 适用场景：so层加密算法逆向、协议分析、数据还原
 * 使用方法：
 *   1. frida -U -f 包名 -l 通杀Native加密算法自吐.js --no-pause
 *   2. 查看控制台输出，获取so层加密算法输入输出
 * 启动方式说明：
 *   - -U 代表USB设备
 *   - -f 代表spawn启动（推荐）
 *   - --no-pause 保证App正常运行
 * 注意事项：
 *   - 某些so需配合反检测脚本
 *   - 输出内容较多，建议重定向日志
 */
// 通杀Native加密算法自吐
// 以libcrypto.so的MD5、SHA1、SHA256、AES为例
var nativeSymbols = [
    {lib: 'libcrypto.so', func: 'MD5'},
    {lib: 'libcrypto.so', func: 'SHA1'},
    {lib: 'libcrypto.so', func: 'SHA256'},
    {lib: 'libcrypto.so', func: 'AES_encrypt'},
    {lib: 'libcrypto.so', func: 'AES_decrypt'}
];
nativeSymbols.forEach(function (item) {
    try {
        var addr = Module.findExportByName(item.lib, item.func);
        if (addr) {
            Interceptor.attach(addr, {
                onEnter: function (args) {
                    console.log('[*] ' + item.func + ' 调用, 参数: ' + args[0]);
                },
                onLeave: function (retval) {
                    console.log('[*] ' + item.func + ' 返回: ' + retval);
                }
            });
        }
    } catch (e) {}
}); 