/*
 * 脚本名称：hook_所有方法.js
 * 功能描述：批量监控Android应用中指定Java类的所有方法调用，自动记录输入参数和返回值
 * 
 * 适用场景：
 *   - 快速分析一个类的完整行为
 *   - 批量监控关键类的方法调用
 *   - 发现隐藏或未文档化的API调用
 *   - 追踪应用内部数据流
 *   - 逆向工程应用的功能模块
 *
 * 使用方法：
 *   1. 修改脚本中的className变量为目标类名
 *      - 将"com.example.app.TargetClass"替换为要监控的实际类名
 *   2. frida -U -f 目标应用包名 -l hook_所有方法.js --no-pause
 *   3. 或者 frida -U --attach-pid 目标进程PID -l hook_所有方法.js
 *   4. 操作应用，观察控制台输出的方法调用信息
 *
 * 启动方式说明：
 *   - -U: 使用USB连接的设备
 *   - -f: 指定以spawn方式启动的应用包名
 *   - --attach-pid: 附加到已运行的进程
 *   - --no-pause: 注入后不暂停应用执行
 *
 * 工作原理：
 *   使用Java反射获取目标类的所有方法，然后遍历每个方法的所有重载版本，
 *   并为每个方法重载添加hook，在方法被调用时记录参数和返回值。
 *   这样可以一次性监控类的所有行为，避免手动编写大量hook代码。
 *
 * 高级配置选项：
 *   - excludeMethods数组：可添加不需要监控的方法名，如常见的toString()等
 *   - includeInheritedMethods：设为true可监控继承的方法
 *   - maxArraySize：限制数组类型参数的显示长度
 *   - maxObjectDepth：限制对象递归解析的深度
 */

// Hook 某个类的所有方法，自动打印调用信息
// 作用：批量监控指定类的所有方法调用，无需单独指定每个方法名，适合快速分析类的行为。
Java.perform(function () {
    try {
        // 配置参数 - 根据需要调整
        var className = "com.example.app.TargetClass"; // 修改为目标类名
        var excludeMethods = ["toString", "hashCode", "equals"]; // 排除监控的方法
        var includeInheritedMethods = false; // 是否包含继承的方法
        var maxArraySize = 10; // 显示数组的最大元素个数
        var maxObjectDepth = 2; // 对象递归解析的最大深度
        
        console.log("[*] 开始监控类: " + className);
        var clazz = Java.use(className);
        
        // 获取所有方法
        var methods;
        if (includeInheritedMethods) {
            methods = clazz.class.getMethods(); // 包含继承的方法
        } else {
            methods = clazz.class.getDeclaredMethods(); // 仅包含类自己的方法
        }
        
        var hookedMethodCount = 0;
        
        methods.forEach(function (method) {
            var name = method.getName();
            
            // 过滤不需要监控的方法
            if (excludeMethods.indexOf(name) != -1) {
                return;
            }
            
            // 遍历方法的所有重载
            try {
                clazz[name].overloads.forEach(function (overload) {
                    overload.implementation = function () {
                        // 输出方法调用信息
                        console.log("\n[*] " + className + "." + name + " 被调用");
                        
                        // 格式化输出参数信息
                        if (arguments.length > 0) {
                            console.log("    参数列表:");
                            for (var i = 0; i < arguments.length; i++) {
                                var arg = arguments[i];
                                var argStr = formatArgument(arg, 0);
                                console.log("      参数" + i + ": " + argStr);
                            }
                        } else {
                            console.log("    无参数");
                        }
                        
                        // 调用原始方法并记录返回值
                        var startTime = new Date().getTime();
                        var ret = overload.apply(this, arguments);
                        var endTime = new Date().getTime();
                        var executionTime = endTime - startTime;
                        
                        // 格式化输出返回值
                        var retStr = formatArgument(ret, 0);
                        console.log("    返回值: " + retStr);
                        console.log("    执行时间: " + executionTime + "ms");
                        
                        return ret;
                    };
                    
                    hookedMethodCount++;
                });
            } catch (e) {
                console.log('    无法Hook方法 ' + name + ': ' + e);
            }
        });
        
        console.log("[*] 成功监控 " + hookedMethodCount + " 个方法");
        
        // 辅助函数：格式化参数或返回值
        function formatArgument(arg, depth) {
            if (depth >= maxObjectDepth) {
                return arg + " (已达到最大深度)";
            }
            
            if (arg === null) {
                return "null";
            }
            
            if (arg === undefined) {
                return "undefined";
            }
            
            // 处理基本类型
            if (typeof arg === 'number' || typeof arg === 'boolean' || typeof arg === 'string') {
                return arg;
            }
            
            // 处理数组
            if (Array.isArray(arg)) {
                var arrStr = "[";
                var length = Math.min(arg.length, maxArraySize);
                for (var i = 0; i < length; i++) {
                    if (i > 0) arrStr += ", ";
                    arrStr += formatArgument(arg[i], depth + 1);
                }
                if (arg.length > maxArraySize) {
                    arrStr += ", ... (共" + arg.length + "项)";
                }
                return arrStr + "]";
            }
            
            // 处理对象
            try {
                return arg.toString();
            } catch (e) {
                return "无法格式化的对象: " + e;
            }
        }
        
    } catch (e) {
        console.log('[!] hook_all_methods错误:', e);
    }
}); 