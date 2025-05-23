// dump_so文件.js
Interceptor.attach(Module.findExportByName(null, 'dlopen'), {
    onEnter: function (args) {
        var soName = args[0].readCString();
        if (soName && soName.indexOf('.so') !== -1) {
            console.log('[*] so库加载: ' + soName);
            // 这里可结合frida-memdump等工具自动dump内存so
        }
    },
    onLeave: function (retval) {}
}); 