// Hook Java 构造函数，打印实例化参数
// 作用：监控对象实例化过程，获取构造函数的参数，分析对象创建逻辑。
Java.perform(function () {
    try {
        var TargetClass = Java.use("com.example.app.TargetClass");
        // 监控构造函数
        TargetClass.$init.overload('java.lang.String', 'int').implementation = function (str, num) {
            console.log("[*] TargetClass constructor called");
            console.log("    str: " + str);
            console.log("    num: " + num);
            return this.$init(str, num); // 调用原始构造函数
        };
    } catch (e) {
        console.log('[!] hook_constructor error:', e);
    }
}); 