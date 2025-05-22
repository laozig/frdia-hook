// Hook __system_property_get，监控系统属性读取（常用于反检测）
Interceptor.attach(Module.findExportByName("libc.so", "__system_property_get"), {
    onEnter: function (args) {
        var key = args[0].readCString();
        console.log("[*] __system_property_get called, key: " + key);
    },
    onLeave: function (retval) {
        // 可选：输出返回值
    }
}); 