// Hook ApplicationInfo.FLAG_DEBUGGABLE，绕过调试检测
Java.perform(function () {
    var ApplicationInfo = Java.use('android.content.pm.ApplicationInfo');
    Object.defineProperty(ApplicationInfo, 'FLAG_DEBUGGABLE', {
        get: function () {
            console.log("[*] ApplicationInfo.FLAG_DEBUGGABLE get (return 0)");
            return 0;
        }
    });
}); 