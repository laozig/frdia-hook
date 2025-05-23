// Hook 读取 /proc/self/maps，绕过内存注入、Frida 检测等
// 作用：阻止应用检测自身内存映射，防止通过 maps 检测 Frida、Xposed、动态注入等。
try {
    Interceptor.attach(Module.findExportByName("libc.so", "fopen"), {
        onEnter: function (args) {
            var path = args[0].readCString();
            // 检查是否读取 maps 文件
            if (path.indexOf("/proc/self/maps") !== -1) {
                console.log("[*] fopen called for /proc/self/maps (bypass)");
                this.bypass = true;
            }
        },
        onLeave: function (retval) {
            if (this.bypass) {
                retval.replace(ptr(0)); // 阻止读取
            }
        }
    });
} catch (e) {
    console.log('[!] hook_native_maps error:', e);
} 