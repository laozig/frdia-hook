/*
 * 脚本名称：hook_构造函数.js
 * 功能描述：监控Java类的构造函数调用，获取实例化时传入的参数和对象创建过程
 * 
 * 适用场景：
 *   - 分析关键对象的创建逻辑
 *   - 了解应用初始化过程
 *   - 监控敏感数据的传入（如加密参数、认证信息）
 *   - 追踪类实例化的完整流程
 *   - 分析对象依赖关系和参数来源
 *
 * 使用方法：
 *   1. 修改脚本中的类名为目标类
 *      - 将"com.example.app.TargetClass"替换为要监控的实际类名
 *      - 根据构造函数的实际参数调整overload中的参数类型
 *   2. frida -U -f 目标应用包名 -l hook_构造函数.js --no-pause
 *   3. 或者 frida -U --attach-pid 目标进程PID -l hook_构造函数.js
 *
 * 启动方式说明：
 *   - -U: 使用USB连接的设备
 *   - -f: 指定以spawn方式启动的应用包名
 *   - --attach-pid: 附加到已运行的进程
 *   - --no-pause: 注入后不暂停应用执行
 *
 * 高级用法：
 *   - 如需监控多个重载构造函数，可添加多个$init.overload定义
 *   - 修改参数值：在调用原始构造函数前修改参数值可实现参数替换
 *   - 添加Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new())
 *     可打印构造函数的调用堆栈
 *   - 如需监控内部类，使用"外部类$内部类"的命名格式
 */

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
            
            // 可选：打印调用堆栈
            // console.log("    Stack: " + Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
            
            // 可选：修改参数
            // str = str + "_modified";
            // num = num * 2;
            
            return this.$init(str, num); // 调用原始构造函数
        };
    } catch (e) {
        console.log('[!] hook_constructor error:', e);
    }
}); 