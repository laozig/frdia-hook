// Hook Build.MANUFACTURER，绕过模拟器检测
Java.perform(function () {
    var Build = Java.use('android.os.Build');
    Object.defineProperty(Build, 'MANUFACTURER', {
        get: function () {
            console.log("[*] Build.MANUFACTURER get (return real device)");
            return "Google"; // 可自定义
        }
    });
}); 