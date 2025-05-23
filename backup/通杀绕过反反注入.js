// 通杀绕过反反注入
Interceptor.attach(Module.findExportByName('libc.so', 'dlopen'), {
    onEnter: function (args) {
        var soName = args[0].readCString();
        if (soName && (soName.indexOf('frida') !== -1 || soName.indexOf('substrate') !== -1)) {
            console.log('[*] 反反注入检测拦截: ' + soName + ' (阻断)');
            this.bypass = true;
        }
    },
    onLeave: function (retval) {
        if (this.bypass) {
            retval.replace(ptr(0));
        }
    }
}); 