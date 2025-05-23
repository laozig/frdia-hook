/*
 * 脚本名称：通杀Base64编码解码.js
 * 功能：自动监控所有Base64编码和解码操作，辅助数据还原、协议分析
 * 适用场景：数据加密、协议分析、数据还原
 * 使用方法：
 *   1. frida -U -f 包名 -l 通杀Base64编码解码.js --no-pause
 *   2. 查看控制台输出，获取Base64输入输出信息
 * 启动方式说明：
 *   - -U 代表USB设备
 *   - -f 代表spawn启动（推荐）
 *   - --no-pause 保证App正常运行
 * 注意事项：
 *   - 某些壳需配合反检测脚本
 */
// 通杀Base64编码解码
Java.perform(function () {
    var Base64 = Java.use('android.util.Base64');
    Base64.encodeToString.overload('[B', 'int').implementation = function (input, flags) {
        var str = Java.use('java.lang.String').$new(input);
        var result = this.encodeToString(input, flags);
        console.log('[*] Base64.encodeToString 输入: ' + str + ' 输出: ' + result);
        return result;
    };
    Base64.decode.overload('java.lang.String', 'int').implementation = function (str, flags) {
        var result = this.decode(str, flags);
        console.log('[*] Base64.decode 输入: ' + str + ' 输出: ' + result);
        return result;
    };
}); 