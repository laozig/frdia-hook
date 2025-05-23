// 通杀绕过反反调试
Interceptor.attach(Module.findExportByName('libc.so', 'getppid'), {
    onEnter: function (args) {
        console.log('[*] 反反调试检测拦截: getppid (返回0)');
    },
    onLeave: function (retval) {
        retval.replace(0);
    }
});
Interceptor.attach(Module.findExportByName('libc.so', 'prctl'), {
    onEnter: function (args) {
        console.log('[*] 反反调试检测拦截: prctl');
    },
    onLeave: function (retval) {}
}); 