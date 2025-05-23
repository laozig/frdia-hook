// Hook Build.MODEL，绕过模拟器检测
Java.perform(function () {
    var Build = Java.use('android.os.Build');
    Object.defineProperty(Build, 'MODEL', {
        get: function () {
            console.log("[*] Build.MODEL get (return real device)");
            return "Pixel 5"; // 可自定义
        }
    });
}); 