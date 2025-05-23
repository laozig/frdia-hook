// 通杀绕过SO完整性校验
['dlopen', 'stat', 'fopen'].forEach(function (func) {
    try {
        var addr = Module.findExportByName('libc.so', func);
        if (addr) {
            Interceptor.attach(addr, {
                onEnter: function (args) {
                    if (args[0] && args[0].readCString) {
                        var path = args[0].readCString();
                        if (path && path.indexOf('.so') !== -1) {
                            console.log('[*] SO完整性校验拦截: ' + func + ' ' + path + ' (阻断)');
                            this.bypass = true;
                        }
                    }
                },
                onLeave: function (retval) {
                    if (this.bypass) {
                        retval.replace(ptr(0));
                    }
                }
            });
        }
    } catch (e) {}
}); 