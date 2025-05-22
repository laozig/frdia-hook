// Hook dlopen，监控动态库加载
Interceptor.attach(Module.findExportByName(null, "dlopen"), {
    onEnter: function (args) {
        var soName = args[0].readCString();
        console.log("[*] dlopen called, so: " + soName);
    },
    onLeave: function (retval) {
        // 可选：输出返回值
    }
}); 