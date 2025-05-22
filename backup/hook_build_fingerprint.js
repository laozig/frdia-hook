// Hook Build.FINGERPRINT，绕过模拟器检测
Java.perform(function () {
    var Build = Java.use('android.os.Build');
    Object.defineProperty(Build, 'FINGERPRINT', {
        get: function () {
            console.log("[*] Build.FINGERPRINT get (return real device)");
            return "google/sdk_gphone_x86/generic_x86:11/RSR1.201013.001/6903274:user/release-keys"; // 可自定义
        }
    });
}); 