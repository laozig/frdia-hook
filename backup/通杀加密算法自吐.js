/*
 * 脚本名称：通杀加密算法自吐.js
 * 功能描述：自动监控所有常见Java加密/摘要/签名算法的输入输出，适合算法还原、数据分析
 * 
 * 适用场景：
 *   - 加密算法逆向分析与还原
 *   - 通信协议分析与重现
 *   - 数据签名与验证过程分析
 *   - 应用安全性评估与漏洞挖掘
 *   - 调试应用内部加密机制问题
 *   - 提取应用内部敏感数据处理逻辑
 *
 * 使用方法：
 *   1. frida -U -f 目标应用包名 -l 通杀加密算法自吐.js --no-pause
 *   2. 或者 frida -U --attach-pid 目标进程PID -l 通杀加密算法自吐.js
 *   3. 操作应用，查看控制台输出，获取明文/密文/摘要等信息
 *   4. 可通过 frida ... > log.txt 重定向日志到文件
 *
 * 启动方式说明：
 *   - -U: 使用USB连接的设备
 *   - -f: 指定以spawn方式启动的应用包名（推荐，可捕获启动阶段的加密操作）
 *   - --attach-pid: 附加到已运行的进程
 *   - --no-pause: 注入后不暂停应用执行
 *
 * 工作原理：
 *   Hook Java层三大加密相关API：
 *   1. MessageDigest: 用于摘要算法，如MD5、SHA系列算法
 *   2. Mac: 用于消息认证码，如HMAC算法
 *   3. Cipher: 用于加密解密，如AES、DES、RSA等算法
 *   
 *   对每个API的输入(update/doFinal)和输出进行监控和打印，
 *   便于分析加密算法的参数、密钥、向量等关键信息。
 *
 * 注意事项：
 *   - 输出内容较多，建议重定向日志到文件进行分析
 *   - 对于壳应用，可能需要配合反检测、反调试脚本使用
 *   - 某些应用可能使用Native层加密或自实现加密算法，此脚本无法监控
 *   - 对于大型文件加密可能导致日志过大，请谨慎使用
 *   - 可结合其他加密监控脚本如监控AES加密解密.js等一起使用
 *   - 考虑使用更专用的脚本如通杀RSA加密解密.js以获取更详细信息
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