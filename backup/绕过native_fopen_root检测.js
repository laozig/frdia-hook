// Hook native fopen，绕过 native 层 root 检测
Interceptor.attach(Module.findExportByName("libc.so", "fopen"), {
    onEnter: function (args) {
        var path = args[0].readCString();
        if (path.indexOf("su") !== -1 || path.indexOf("busybox") !== -1) {
            console.log("[*] fopen called for root check: " + path + " (bypass)");
            this.bypass = true;
        }
    },
    onLeave: function (retval) {
        if (this.bypass) {
            retval.replace(ptr(0)); // 让检测失败
        }
    }
}); 