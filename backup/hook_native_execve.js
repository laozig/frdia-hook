// Hook execve，监控进程执行（常用于反检测、反Root）
Interceptor.attach(Module.findExportByName("libc.so", "execve"), {
    onEnter: function (args) {
        var path = args[0].readCString();
        console.log("[*] execve called, path: " + path);
    },
    onLeave: function (retval) {
        // 可选：输出返回值
    }
}); 