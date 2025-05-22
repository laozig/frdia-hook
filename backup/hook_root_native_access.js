// Hook native access，绕过 native 层 root 检测
Interceptor.attach(Module.findExportByName("libc.so", "access"), {
    onEnter: function (args) {
        var path = args[0].readCString();
        if (path.indexOf("su") !== -1 || path.indexOf("busybox") !== -1) {
            console.log("[*] access called for root check: " + path + " (bypass)");
            this.bypass = true;
        }
    },
    onLeave: function (retval) {
        if (this.bypass) {
            retval.replace(-1); // 让检测失败
        }
    }
}); 