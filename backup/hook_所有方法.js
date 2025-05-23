// Hook 某个类的所有方法，自动打印调用信息
// 作用：批量监控指定类的所有方法调用，无需单独指定每个方法名，适合快速分析类的行为。
Java.perform(function () {
    try {
        var className = "com.example.app.TargetClass";
        var clazz = Java.use(className);
        // 获取所有方法
        var methods = clazz.class.getDeclaredMethods();
        methods.forEach(function (method) {
            var name = method.getName();
            // 遍历方法的所有重载
            clazz[name].overloads.forEach(function (overload) {
                overload.implementation = function () {
                    // 输出方法调用信息
                    console.log("[*] " + className + "." + name + " called");
                    for (var i = 0; i < arguments.length; i++) {
                        console.log("    arg" + i + ": " + arguments[i]);
                    }
                    // 调用原始方法并记录返回值
                    var ret = overload.apply(this, arguments);
                    console.log("    return: " + ret);
                    return ret;
                };
            });
        });
    } catch (e) {
        console.log('[!] hook_all_methods error:', e);
    }
}); 