// 通杀绕过签名校验
Java.perform(function () {
    var PackageManager = Java.use('android.app.ApplicationPackageManager');
    PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function (pkg, flags) {
        var info = this.getPackageInfo(pkg, flags);
        try {
            var sigs = info.signatures;
            if (sigs && sigs.length > 0) {
                for (var i = 0; i < sigs.length; i++) {
                    sigs[i] = Java.use('android.content.pm.Signature').$new('FAKE_SIGNATURE');
                }
            }
        } catch (e) {}
        console.log('[*] 签名校验拦截: ' + pkg + ' (返回伪造签名)');
        return info;
    };
}); 