// Hook 应用签名校验，绕过签名校验
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
        console.log("[*] getPackageInfo for signature check: " + pkg + " (return fake signature)");
        return info;
    };
}); 