/*
 * 脚本名称：通杀RSA加密解密.js
 * 功能：自动监控所有RSA加密、解密、签名、验签操作，辅助算法还原、数据分析
 * 适用场景：RSA逆向、数据还原、协议分析
 * 使用方法：
 *   1. frida -U -f 包名 -l 通杀RSA加密解密.js --no-pause
 *   2. 查看控制台输出，获取RSA输入输出信息
 * 启动方式说明：
 *   - -U 代表USB设备
 *   - -f 代表spawn启动（推荐）
 *   - --no-pause 保证App正常运行
 * 注意事项：
 *   - 某些壳需配合反检测脚本
 */
// 通杀RSA加密解密
Java.perform(function () {
    var Cipher = Java.use('javax.crypto.Cipher');
    Cipher.getInstance.overload('java.lang.String').implementation = function (transformation) {
        if (transformation && transformation.indexOf('RSA') !== -1) {
            console.log('[*] 获取RSA Cipher实例: ' + transformation);
        }
        return this.getInstance(transformation);
    };
    Cipher.doFinal.overload('[B').implementation = function (input) {
        var algo = this.getAlgorithm();
        if (algo && algo.indexOf('RSA') !== -1) {
            var str = Java.use('java.lang.String').$new(input);
            var result = this.doFinal(input);
            console.log('[*] RSA doFinal 输入: ' + str + ' 输出: ' + result);
            return result;
        }
        return this.doFinal(input);
    };
}); 