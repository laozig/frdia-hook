// Hook Java 层的某个类的指定方法，打印参数和返回值
// 作用：监控指定 Java 类方法的调用过程，跟踪输入参数和返回值，用于分析应用逻辑和数据流。
Java.perform(function () {
    try {
        var TargetClass = Java.use("com.example.app.TargetClass");
        // 替换目标方法实现
        TargetClass.targetMethod.implementation = function (arg1, arg2) {
            console.log("[*] targetMethod called");
            console.log("    arg1: " + arg1);
            console.log("    arg2: " + arg2);
            
            // 调用原始方法并记录返回值
            var ret = this.targetMethod(arg1, arg2);
            console.log("    return: " + ret);
            return ret;
        };
    } catch (e) {
        console.log('[!] hook_java_method error:', e);
    }
});
