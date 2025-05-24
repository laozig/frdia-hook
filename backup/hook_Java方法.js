/*
 * 脚本名称：hook_Java方法.js
 * 功能描述：监控Android应用中指定Java方法的调用，获取方法参数和返回值
 * 
 * 适用场景：
 *   - 分析应用关键逻辑和数据处理流程
 *   - 提取敏感方法的参数和返回值
 *   - 调试应用行为和功能实现
 *   - 逆向工程应用内部API
 *   - 定位应用中的漏洞和安全问题
 *
 * 使用方法：
 *   1. 修改脚本中的类名和方法名为目标类和方法
 *      - 将"com.example.app.TargetClass"替换为要监控的实际类名
 *      - 将"targetMethod"替换为要监控的实际方法名
 *      - 根据方法的实际参数调整overload中的参数类型
 *   2. frida -U -f 目标应用包名 -l hook_Java方法.js --no-pause
 *   3. 或者 frida -U --attach-pid 目标进程PID -l hook_Java方法.js
 *   4. 操作应用，触发目标方法调用，观察控制台输出
 *
 * 启动方式说明：
 *   - -U: 使用USB连接的设备
 *   - -f: 指定以spawn方式启动的应用包名
 *   - --attach-pid: 附加到已运行的进程
 *   - --no-pause: 注入后不暂停应用执行
 *
 * 工作原理：
 *   使用Frida的Java.use API获取目标类和方法的引用，然后通过重写方法的implementation
 *   属性来拦截方法调用。每当方法被调用时，脚本会记录传入的参数和方法返回值，然后调用
 *   原始方法并返回结果，不影响应用的正常功能。
 *
 * 高级用法：
 *   - 可添加调用堆栈打印以跟踪方法调用来源
 *   - 可修改参数值以改变方法行为
 *   - 可修改返回值以影响应用逻辑
 *   - 可结合hook_所有方法.js实现批量监控
 *   - 可在方法调用前后执行自定义逻辑
 */

// Hook Java 方法，打印参数和返回值
// 作用：监控指定类的方法调用，分析方法参数和返回值，了解应用逻辑。
Java.perform(function () {
    try {
        var TargetClass = Java.use("com.example.app.TargetClass");
        // 监控指定方法
        TargetClass.targetMethod.overload('java.lang.String', 'int').implementation = function (str, num) {
            console.log("[*] 方法被调用: com.example.app.TargetClass.targetMethod");
            console.log("    参数1(String): " + str);
            console.log("    参数2(int): " + num);
            
            // 可选：打印调用堆栈
            // console.log("    调用堆栈: \n    " + 
            //     Java.use("android.util.Log").getStackTraceString(
            //     Java.use("java.lang.Exception").$new()).split('\n').slice(1, 4).join('\n    '));
            
            // 可选：修改参数
            // str = str + "_modified";
            // num = num * 2;
            
            // 调用原始方法
            var ret = this.targetMethod(str, num);
            console.log("    返回值: " + ret);
            
            // 可选：修改返回值
            // if(ret == "sensitive_data") {
            //     console.log("    修改返回值");
            //     return "fake_data";
            // }
            
            return ret;
        };
        
        console.log("[*] 成功监控方法: com.example.app.TargetClass.targetMethod");
    } catch (e) {
        console.log('[!] hook_java_method错误:', e);
    }
});
