// Hook MessageDigest，监控常见加密算法的输入和输出
Java.perform(function () {
    var MessageDigest = Java.use('java.security.MessageDigest');
    MessageDigest.update.overload('[B').implementation = function (input) {
        var str = Java.use('java.lang.String').$new(input);
        console.log("[*] MessageDigest.update input: " + str);
        return this.update(input);
    };
    MessageDigest.digest.overload().implementation = function () {
        var result = this.digest();
        console.log("[*] MessageDigest.digest result: " + result);
        return result;
    };
}); 