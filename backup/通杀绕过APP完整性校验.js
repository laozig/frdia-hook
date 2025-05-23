// 通杀绕过APP完整性校验
Java.perform(function () {
    var MessageDigest = Java.use('java.security.MessageDigest');
    MessageDigest.digest.overload().implementation = function () {
        console.log('[*] APP完整性校验拦截: MessageDigest.digest (返回伪造值)');
        var fake = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15];
        return fake;
    };
    var CRC32 = Java.use('java.util.zip.CRC32');
    CRC32.getValue.implementation = function () {
        console.log('[*] APP完整性校验拦截: CRC32.getValue (返回0)');
        return 0;
    };
}); 