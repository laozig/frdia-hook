// 监控AES加密解密
Java.perform(function () {
    var Cipher = Java.use('javax.crypto.Cipher');
    Cipher.doFinal.overload('[B').implementation = function (input) {
        var str = Java.use('java.lang.String').$new(input);
        console.log('[*] AES doFinal 输入: ' + str);
        var result = this.doFinal(input);
        console.log('[*] AES doFinal 输出: ' + result);
        return result;
    };
}); 