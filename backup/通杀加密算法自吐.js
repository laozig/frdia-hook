/*
 * 脚本名称：通杀加密算法自吐.js
 * 功能：自动监控所有常见Java加密/摘要/签名算法的输入输出，适合算法还原、数据分析
 * 适用场景：加密算法逆向、数据还原、协议分析
 * 使用方法：
 *   1. frida -U -f 包名 -l 通杀加密算法自吐.js --no-pause
 *   2. 查看控制台输出，获取明文/密文/摘要等信息
 * 启动方式说明：
 *   - -U 代表USB设备
 *   - -f 代表spawn启动（推荐）
 *   - --no-pause 保证App正常运行
 * 注意事项：
 *   - 某些壳需配合反检测脚本
 *   - 输出内容较多，建议重定向日志
 */
// 通杀加密算法自吐
Java.perform(function () {
    var MessageDigest = Java.use('java.security.MessageDigest');
    MessageDigest.update.overload('[B').implementation = function (input) {
        var str = Java.use('java.lang.String').$new(input);
        console.log('[*] MessageDigest.update 输入: ' + str);
        return this.update(input);
    };
    MessageDigest.digest.overload().implementation = function () {
        var result = this.digest();
        console.log('[*] MessageDigest.digest 输出: ' + result);
        return result;
    };
    var Mac = Java.use('javax.crypto.Mac');
    Mac.update.overload('[B').implementation = function (input) {
        var str = Java.use('java.lang.String').$new(input);
        console.log('[*] Mac.update 输入: ' + str);
        return this.update(input);
    };
    Mac.doFinal.overload().implementation = function () {
        var result = this.doFinal();
        console.log('[*] Mac.doFinal 输出: ' + result);
        return result;
    };
    var Cipher = Java.use('javax.crypto.Cipher');
    Cipher.doFinal.overload('[B').implementation = function (input) {
        var str = Java.use('java.lang.String').$new(input);
        console.log('[*] Cipher.doFinal 输入: ' + str);
        var result = this.doFinal(input);
        console.log('[*] Cipher.doFinal 输出: ' + result);
        return result;
    };
}); 