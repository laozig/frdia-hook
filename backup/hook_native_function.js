// Hook Native 层的导出函数，打印参数和返回值
// 作用：监控 so 库中导出函数的调用，获取参数和返回值，分析底层实现。
try {
    Interceptor.attach(Module.findExportByName("libnative-lib.so", "native_function"), {
        onEnter: function (args) {
            // 记录函数参数
            console.log("[*] native_function called");
            console.log("    arg0: " + args[0]);
            console.log("    arg1: " + args[1]);
        },
        onLeave: function (retval) {
            // 记录返回值
            console.log("    return: " + retval);
        }
    });
} catch (e) {
    console.log('[!] hook_native_function error:', e);
} 