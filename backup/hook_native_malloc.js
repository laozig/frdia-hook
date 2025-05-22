// Hook libc 的 malloc，监控内存分配
Interceptor.attach(Module.findExportByName("libc.so", "malloc"), {
    onEnter: function (args) {
        console.log("[*] malloc called, size: " + args[0].toInt32());
    },
    onLeave: function (retval) {
        console.log("[*] malloc return ptr: " + retval);
    }
}); 