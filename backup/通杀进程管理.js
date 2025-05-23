// 通杀进程管理
['ps', 'kill', 'getpid', 'getppid'].forEach(function (func) {
    try {
        var addr = Module.findExportByName('libc.so', func);
        if (addr) {
            Interceptor.attach(addr, {
                onEnter: function (args) {
                    console.log('[*] ' + func + ' 调用, 参数: ' + args[0]);
                },
                onLeave: function (retval) {
                    console.log('[*] ' + func + ' 返回: ' + retval);
                }
            });
        }
    } catch (e) {}
}); 