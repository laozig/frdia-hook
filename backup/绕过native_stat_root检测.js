// Hook native stat，绕过 native 层 root 检测
Interceptor.attach(Module.findExportByName("libc.so", "stat"), {
    onEnter: function (args) {
        var path = args[0].readCString();
        if (path.indexOf("su") !== -1 || path.indexOf("busybox") !== -1) {
            console.log("[*] stat called for root check: " + path + " (bypass)");
            this.bypass = true;
        }
    },
    onLeave: function (retval) {
        if (this.bypass) {
            retval.replace(-1); // 让检测失败
        }
    }
}); 