// 通杀绕过内存注入检测
Interceptor.attach(Module.findExportByName('libc.so', 'fopen'), {
    onEnter: function (args) {
        var path = args[0].readCString();
        if (path.indexOf('/proc/self/maps') !== -1 || path.indexOf('/proc/self/mem') !== -1) {
            console.log('[*] 内存注入检测拦截: ' + path + ' (阻断)');
            this.bypass = true;
        }
    },
    onLeave: function (retval) {
        if (this.bypass) {
            retval.replace(ptr(0));
        }
    }
}); 