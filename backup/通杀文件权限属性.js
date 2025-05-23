// 通杀文件权限属性
['chmod', 'chown', 'stat', 'lstat', 'fstat'].forEach(function (func) {
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