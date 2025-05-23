// 通杀DES加密解密
Java.perform(function () {
    var Cipher = Java.use('javax.crypto.Cipher');
    Cipher.getInstance.overload('java.lang.String').implementation = function (transformation) {
        if (transformation && (transformation.indexOf('DES') !== -1 || transformation.indexOf('3DES') !== -1)) {
            console.log('[*] 获取DES/3DES Cipher实例: ' + transformation);
        }
        return this.getInstance(transformation);
    };
    Cipher.doFinal.overload('[B').implementation = function (input) {
        var algo = this.getAlgorithm();
        if (algo && (algo.indexOf('DES') !== -1 || algo.indexOf('3DES') !== -1)) {
            var str = Java.use('java.lang.String').$new(input);
            var result = this.doFinal(input);
            console.log('[*] DES/3DES doFinal 输入: ' + str + ' 输出: ' + result);
            return result;
        }
        return this.doFinal(input);
    };
}); 