// Hook Cipher，监控加密解密的明文和密文
Java.perform(function () {
    var Cipher = Java.use('javax.crypto.Cipher');
    Cipher.doFinal.overload('[B').implementation = function (input) {
        var str = Java.use('java.lang.String').$new(input);
        console.log("[*] Cipher.doFinal input: " + str);
        var result = this.doFinal(input);
        console.log("[*] Cipher.doFinal result: " + result);
        return result;
    };
}); 