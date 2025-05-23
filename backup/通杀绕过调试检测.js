// 通杀绕过调试检测
Java.perform(function () {
    var Debug = Java.use('android.os.Debug');
    Debug.isDebuggerConnected.implementation = function () {
        console.log('[*] 调试检测拦截: isDebuggerConnected (返回false)');
        return false;
    };
    Debug.getFlags.implementation = function () {
        console.log('[*] 调试检测拦截: getFlags (返回0)');
        return 0;
    };
});
Interceptor.attach(Module.findExportByName('libc.so', 'ptrace'), {
    onEnter: function (args) {
        console.log('[*] 调试检测拦截: ptrace (失效)');
        args[0] = ptr(-1);
    },
    onLeave: function (retval) {
        retval.replace(0);
    }
}); 