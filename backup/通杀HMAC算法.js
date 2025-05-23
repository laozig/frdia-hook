// 通杀HMAC算法
Java.perform(function () {
    var Mac = Java.use('javax.crypto.Mac');
    Mac.getInstance.overload('java.lang.String').implementation = function (algo) {
        if (algo && algo.indexOf('Hmac') !== -1) {
            console.log('[*] 获取HMAC实例: ' + algo);
        }
        return this.getInstance(algo);
    };
    Mac.doFinal.overload('[B').implementation = function (input) {
        var algo = this.getAlgorithm();
        if (algo && algo.indexOf('Hmac') !== -1) {
            var str = Java.use('java.lang.String').$new(input);
            var result = this.doFinal(input);
            console.log('[*] HMAC doFinal 输入: ' + str + ' 输出: ' + result);
            return result;
        }
        return this.doFinal(input);
    };
});