// Hook Build.BRAND，绕过模拟器检测
Java.perform(function () {
    var Build = Java.use('android.os.Build');
    Object.defineProperty(Build, 'BRAND', {
        get: function () {
            console.log("[*] Build.BRAND get (return real device)");
            return "google"; // 可自定义
        }
    });
}); 