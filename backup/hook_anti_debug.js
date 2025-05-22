// Hook 反调试检测，绕过 isDebuggerConnected 检查
Java.perform(function () {
    var Debug = Java.use('android.os.Debug');
    Debug.isDebuggerConnected.implementation = function () {
        console.log("[*] Debug.isDebuggerConnected called, return false");
        return false;
    };
}); 