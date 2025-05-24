/*
 * 脚本名称：dump_反射调用参数.js
 * 功能描述：监控并打印Java反射调用的方法名称、参数和返回值
 * 
 * 适用场景：
 *   - 分析使用反射机制隐藏关键调用的应用
 *   - 追踪动态加载和调用的类和方法
 *   - 识别应用中可能的混淆或加固保护机制
 *   - 调试反射相关的问题和行为
 *   - 寻找应用中通过反射实现的敏感操作
 *
 * 使用方法：
 *   1. frida -U -f 目标应用包名 -l dump_反射调用参数.js --no-pause
 *   2. 或者 frida -U --attach-pid 目标进程PID -l dump_反射调用参数.js
 *   3. 操作应用，观察控制台输出，查看所有通过反射调用的方法及其参数
 *
 * 启动方式说明：
 *   - -U: 使用USB连接的设备
 *   - -f: 指定以spawn方式启动的应用包名
 *   - --attach-pid: 附加到已运行的进程
 *   - --no-pause: 注入后不暂停应用执行
 *
 * 工作原理：
 *   Hook java.lang.reflect.Method类的invoke方法，该方法是Java反射API的核心。
 *   当应用使用反射调用任何方法时，都会通过这个函数。脚本会拦截这些调用，
 *   记录被调用方法的名称、传入的参数以及返回值，从而揭示应用中隐藏的逻辑流程。
 *
 * 注意事项：
 *   - 反射调用非常频繁，可能会产生大量日志，建议针对特定类或方法进行过滤
 *   - 某些框架和库大量使用反射，可能导致日志混乱，需要适当添加过滤条件
 *   - 复杂对象的参数输出可能不完整，可以根据需要修改脚本以获取更详细的信息
 *   - 对于敏感信息（如密码、token等），应注意日志的安全处理
 */

// 配置选项
var config = {
    // 基本设置
    printStacktrace: true,         // 是否打印调用堆栈
    stackTraceDepth: 5,            // 堆栈深度
    detailedObjectInfo: true,      // 是否打印详细对象信息
    maxArrayLength: 10,            // 数组输出最大长度
    
    // 过滤设置
    enableFilter: true,            // 是否启用过滤
    excludeSystemClasses: true,    // 是否排除系统类
    includePackages: [],           // 只包含这些包的反射调用(空数组表示不限制)
    excludePackages: [             // 排除这些包的反射调用
        "androidx.",
        "android.view.",
        "android.widget.",
        "com.google."
    ],
    
    // 敏感方法监控
    sensitiveMethodPatterns: [     // 敏感方法名模式
        "encrypt", 
        "decrypt", 
        "password", 
        "login", 
        "key", 
        "token"
    ]
};

// 统计信息
var stats = {
    totalCalls: 0,
    filteredCalls: 0,
    sensitiveMethodCalls: 0,
    reflectedClasses: new Set(),
    methodCounts: {}
};

// Hook Java反射调用的核心方法
Java.perform(function () {
    // 辅助函数：获取简短的调用堆栈
    function getStackTrace(depth) {
        if (!config.printStacktrace) return "";
        depth = depth || config.stackTraceDepth;
        
        var Exception = Java.use("java.lang.Exception");
        var exception = Exception.$new();
        var stackElements = exception.getStackTrace();
        
        var stack = "\n    调用堆栈:";
        var frameCount = Math.min(stackElements.length, depth);
        
        for (var i = 2; i < frameCount + 2; i++) {  // 跳过前两帧(通常是我们的hook代码)
            var element = stackElements[i];
            var className = element.getClassName();
            var methodName = element.getMethodName();
            var fileName = element.getFileName();
            var lineNumber = element.getLineNumber();
            
            // 排除框架类
            if (config.excludeSystemClasses && 
                (className.startsWith("java.") || 
                className.startsWith("android.") || 
                className.startsWith("dalvik."))) {
                continue;
            }
            
            stack += "\n        " + className + "." + methodName + 
                     "(" + (fileName != null ? fileName : "Unknown Source") + 
                     ":" + lineNumber + ")";
        }
        
        exception.$dispose();
        return stack;
    }
    
    // 辅助函数：智能格式化参数
    function formatParameter(param) {
        if (param === null) return "null";
        
        try {
            // 处理数组
            if (param.getClass().isArray()) {
                var result = "[";
                var length = Java.cast(param, Java.use("java.lang.reflect.Array")).getLength(param);
                var actualLength = Math.min(length, config.maxArrayLength);
                
                for (var i = 0; i < actualLength; i++) {
                    var element = Java.cast(param, Java.use("java.lang.reflect.Array")).get(param, i);
                    result += formatParameter(element);
                    if (i < actualLength - 1) result += ", ";
                }
                
                if (length > config.maxArrayLength) {
                    result += ", ... (" + (length - config.maxArrayLength) + " more)";
                }
                
                return result + "]";
            }
            
            // 处理集合类型
            if (Java.cast(param, Java.use("java.lang.Object")).getClass().getName().startsWith("java.util.")) {
                try {
                    // 尝试转为Collection
                    var collection = Java.cast(param, Java.use("java.util.Collection"));
                    if (collection) {
                        var result = "{";
                        var size = collection.size();
                        var actualSize = Math.min(size, config.maxArrayLength);
                        var iterator = collection.iterator();
                        var count = 0;
                        
                        while (iterator.hasNext() && count < actualSize) {
                            var element = iterator.next();
                            result += formatParameter(element);
                            if (count < actualSize - 1 && iterator.hasNext()) result += ", ";
                            count++;
                        }
                        
                        if (size > config.maxArrayLength) {
                            result += ", ... (" + (size - config.maxArrayLength) + " more)";
                        }
                        
                        return result + "}";
                    }
                } catch (e) {}
                
                try {
                    // 尝试转为Map
                    var map = Java.cast(param, Java.use("java.util.Map"));
                    if (map) {
                        var result = "{";
                        var size = map.size();
                        var actualSize = Math.min(size, config.maxArrayLength);
                        var keySet = map.keySet();
                        var keyIterator = keySet.iterator();
                        var count = 0;
                        
                        while (keyIterator.hasNext() && count < actualSize) {
                            var key = keyIterator.next();
                            var value = map.get(key);
                            result += formatParameter(key) + ":" + formatParameter(value);
                            if (count < actualSize - 1 && keyIterator.hasNext()) result += ", ";
                            count++;
                        }
                        
                        if (size > config.maxArrayLength) {
                            result += ", ... (" + (size - config.maxArrayLength) + " more)";
                        }
                        
                        return result + "}";
                    }
                } catch (e) {}
            }
            
            // 默认使用toString()，但对复杂对象提供更多信息
            if (config.detailedObjectInfo && 
                !param.getClass().getName().startsWith("java.lang.") && 
                !param.getClass().isPrimitive()) {
                return param.toString() + " [" + param.getClass().getName() + "]";
            } else {
                return param.toString();
            }
        } catch (e) {
            return "不可显示对象: " + e;
        }
    }
    
    // 辅助函数：检查是否应该过滤此调用
    function shouldFilter(className, methodName) {
        if (!config.enableFilter) return false;
        
        // 检查是否在排除列表中
        for (var i = 0; i < config.excludePackages.length; i++) {
            if (className.startsWith(config.excludePackages[i])) {
                return true;
            }
        }
        
        // 检查是否在包含列表中(如果包含列表非空)
        if (config.includePackages.length > 0) {
            var included = false;
            for (var i = 0; i < config.includePackages.length; i++) {
                if (className.startsWith(config.includePackages[i])) {
                    included = true;
                    break;
                }
            }
            return !included;
        }
        
        return false;
    }
    
    // 辅助函数：检查是否是敏感方法
    function isSensitiveMethod(methodName) {
        for (var i = 0; i < config.sensitiveMethodPatterns.length; i++) {
            if (methodName.toLowerCase().indexOf(config.sensitiveMethodPatterns[i]) !== -1) {
                return true;
            }
        }
        return false;
    }
    
    // 主Hook点：Method.invoke
    var Method = Java.use('java.lang.reflect.Method');
    Method.invoke.implementation = function (obj, args) {
        stats.totalCalls++;
        
        var methodName = this.getName();
        var className = "";
        
        try {
            className = this.getDeclaringClass().getName();
        } catch (e) {
            className = "未知类";
        }
        
        // 更新统计
        stats.reflectedClasses.add(className);
        var methodKey = className + "." + methodName;
        stats.methodCounts[methodKey] = (stats.methodCounts[methodKey] || 0) + 1;
        
        // 检查是否应该过滤
        if (shouldFilter(className, methodName)) {
            stats.filteredCalls++;
            return this.invoke(obj, args);
        }
        
        // 检查是否为敏感方法
        var isSensitive = isSensitiveMethod(methodName);
        if (isSensitive) {
            stats.sensitiveMethodCalls++;
        }
        
        // 构建标题
        var title = "[*] 反射调用" + (isSensitive ? " [敏感]" : "") + ": " + 
                   className + "." + methodName;
        console.log(title);
        
        // 显示目标对象
        if (obj !== null) {
            try {
                console.log("    对象: " + formatParameter(obj));
            } catch (e) {
                console.log("    对象: <无法格式化>");
            }
        }
        
        // 显示参数
        if (args && args.length > 0) {
            console.log("    参数:");
            for (var i = 0; i < args.length; i++) {
                try {
                    console.log("      " + i + ": " + formatParameter(args[i]));
                } catch (e) {
                    console.log("      " + i + ": <无法格式化> (" + e + ")");
                }
            }
        } else {
            console.log("    参数: 无");
        }
        
        // 调用原始方法并获取返回值
        var startTime = new Date().getTime();
        var ret = this.invoke(obj, args);
        var endTime = new Date().getTime();
        var executionTime = endTime - startTime;
        
        // 显示返回值
        try {
            console.log("    返回值: " + formatParameter(ret) + 
                       " (执行时间: " + executionTime + "ms)");
        } catch (e) {
            console.log("    返回值: <无法格式化> (" + e + ")");
        }
        
        // 显示调用堆栈
        if (config.printStacktrace) {
            console.log(getStackTrace());
        }
        
        // 周期性输出统计信息
        if (stats.totalCalls % 100 === 0) {
            console.log("\n[*] 反射调用统计:");
            console.log("    总调用次数: " + stats.totalCalls);
            console.log("    已过滤调用: " + stats.filteredCalls);
            console.log("    敏感方法调用: " + stats.sensitiveMethodCalls);
            console.log("    独立反射类数量: " + stats.reflectedClasses.size);
            
            // 显示调用最频繁的方法
            var sortedMethods = Object.keys(stats.methodCounts).sort(function(a, b) {
                return stats.methodCounts[b] - stats.methodCounts[a];
            });
            
            if (sortedMethods.length > 0) {
                console.log("    最常调用的方法:");
                for (var i = 0; i < Math.min(5, sortedMethods.length); i++) {
                    console.log("      " + sortedMethods[i] + ": " + 
                               stats.methodCounts[sortedMethods[i]] + "次");
                }
            }
        }
        
        return ret;
    };
    
    console.log("[+] 反射调用监控已启动");
    console.log("    过滤状态: " + (config.enableFilter ? "启用" : "禁用"));
    console.log("    堆栈跟踪: " + (config.printStacktrace ? "启用" : "禁用"));
    console.log("    敏感方法监控: " + config.sensitiveMethodPatterns.length + "种模式");
}); 