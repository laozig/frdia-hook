// Hook getFlags，绕过调试检测
Java.perform(function () {
    var Debug = Java.use('android.os.Debug');
    Debug.getFlags.implementation = function () {
        console.log("[*] Debug.getFlags called (return 0)");
        return 0;
    };
}); 