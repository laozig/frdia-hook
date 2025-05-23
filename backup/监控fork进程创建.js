// Hook fork，监控进程创建（常用于反检测、反调试）
Interceptor.attach(Module.findExportByName("libc.so", "fork"), {
    onEnter: function (args) {
        console.log("[*] fork called");
    },
    onLeave: function (retval) {
        // 可选：输出返回值
    }
}); 