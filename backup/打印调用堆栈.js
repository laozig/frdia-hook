/*
 * 脚本名称：打印调用堆栈.js
 * 功能：全面捕获并格式化Java调用堆栈，支持筛选、分析和可视化展示
 * 适用场景：分析程序执行流程、定位关键函数、逆向工程、漏洞分析
 * 使用方法：
 *   1. frida -U -f 包名 -l 打印调用堆栈.js --no-pause
 *   2. 在适当位置调用dumpStack或dumpStackFiltered函数
 * 启动方式说明：
 *   - -U 代表使用USB连接的设备
 *   - -f 代表以spawn方式启动目标应用
 *   - --no-pause 指示Frida不要暂停应用执行
 * 参数说明：
 *   - 包名：目标应用的包名，如com.example.app
 * 功能特点：
 *   - 多级堆栈展示：支持完整/简略两种模式
 *   - 包名过滤：可针对特定包名进行堆栈筛选
 *   - 详细类信息：显示完整的类名、方法名和行号
 *   - Native桥接：支持JNI调用检测和原生层堆栈获取
 *   - 易于集成：提供可随时调用的API函数
 *   - 可视化格式：带缩进和层级结构的堆栈显示
 * 输出格式：
 *   - 默认模式显示完整的方法签名、行号和文件名
 *   - 简洁模式仅显示关键堆栈信息，忽略框架类
 *   - 彩色输出支持(如控制台支持)
 */

Java.perform(function () {
    // 全局变量定义
    var StackUtils = {
        // 获取完整堆栈并格式化
        dumpStack: function (options) {
            options = options || {};
            var depth = options.depth || 50; // 默认显示50层堆栈
            var skipFrames = options.skipFrames || 0; // 跳过顶部几帧（通常是为了跳过工具方法自身）
            var showSystemFrames = options.showSystemFrames !== false; // 默认显示系统框架
            var colorOutput = options.colorOutput !== false; // 默认启用彩色输出
            var detailedOutput = options.detailedOutput !== false; // 默认启用详细输出
            
            var result = [];
            try {
                var Exception = Java.use("java.lang.Exception");
                var Log = Java.use("android.util.Log");
                
                // 创建异常获取堆栈
                var exception = Exception.$new();
                var stackElements = exception.getStackTrace();
                
                // 添加堆栈信息标题
                result.push("┌───────────────────────────────────────────────────────────");
                result.push("│ 调用堆栈: " + new Date().toISOString());
                result.push("├───────────────────────────────────────────────────────────");
                
                // 逐一处理堆栈元素
                for (var i = skipFrames; i < Math.min(stackElements.length, depth + skipFrames); i++) {
                    var element = stackElements[i];
                    var className = element.getClassName();
                    var methodName = element.getMethodName();
                    var fileName = element.getFileName();
                    var lineNumber = element.getLineNumber();
                    
                    // 过滤系统框架（如果设置了不显示）
                    if (!showSystemFrames && (className.startsWith("android.") || 
                                           className.startsWith("java.") ||
                                           className.startsWith("com.android.") ||
                                           className.startsWith("dalvik.") ||
                                           className.startsWith("sun.") ||
                                           className.startsWith("org.json."))) {
                        continue;
                    }
                    
                    var indent = "│ ";
                    var framePrefix = (i - skipFrames).toString().padStart(2, ' ') + ") ";
                    var location = (fileName ? fileName : "Unknown Source") + 
                                   (lineNumber > 0 ? ":" + lineNumber : "");
                    
                    var frameLine;
                    if (detailedOutput) {
                        frameLine = indent + framePrefix + className + "." + methodName + 
                                   "(" + location + ")";
                    } else {
                        frameLine = indent + framePrefix + methodName + " (" + location + ")";
                    }
                    
                    if (colorOutput) {
                        // 为不同类型的框架添加颜色（在支持ANSI的终端中）
                        if (className.startsWith("java.")) {
                            frameLine = "\x1b[90m" + frameLine + "\x1b[0m"; // 灰色显示系统类
                        } else if (className.includes("$")) {
                            frameLine = "\x1b[36m" + frameLine + "\x1b[0m"; // 青色显示内部类
                        } else if (methodName === "<init>" || methodName === "<clinit>") {
                            frameLine = "\x1b[33m" + frameLine + "\x1b[0m"; // 黄色显示构造函数
                        } else {
                            frameLine = "\x1b[32m" + frameLine + "\x1b[0m"; // 绿色显示普通方法
                        }
                    }
                    
                    result.push(frameLine);
                }
                
                result.push("└───────────────────────────────────────────────────────────");
                
                // 输出结果
                console.log(result.join("\n"));
                
                // 释放资源
                exception.$dispose();
                return result.join("\n");
            } catch (e) {
                console.log('[!] dump_stack error:', e);
                return null;
            }
        },
        
        // 根据包名筛选堆栈
        dumpStackFiltered: function (packageFilter) {
            try {
                var Exception = Java.use("java.lang.Exception");
                var stackElements = Exception.$new().getStackTrace();
                
                console.log("\n[*] 已过滤的调用堆栈 (包含: " + packageFilter + "):");
                console.log("---------------------------------------------");
                
                var found = false;
                for (var i = 0; i < stackElements.length; i++) {
                    var element = stackElements[i];
                    var className = element.getClassName();
                    
                    if (className.startsWith(packageFilter)) {
                        found = true;
                        console.log("  " + i + ") " + className + "." + 
                                   element.getMethodName() + 
                                   "(" + (element.getFileName() || "Unknown") + ":" + 
                                   element.getLineNumber() + ")");
                    }
                }
                
                if (!found) {
                    console.log("  [!] 在堆栈中未找到匹配包名: " + packageFilter);
                }
                
                console.log("---------------------------------------------");
            } catch (e) {
                console.log('[!] dump_stack_filtered error:', e);
            }
        },
        
        // 监控特定方法的调用堆栈
        monitorMethodStack: function (targetClass, targetMethod) {
            try {
                var clazz = Java.use(targetClass);
                
                // 获取所有匹配的方法
                var methods = [];
                if (targetMethod === '*') {
                    var methodNames = Object.getOwnPropertyNames(clazz.__proto__).filter(function(m) {
                        return !m.startsWith('$') && m !== 'class' && m !== 'constructor';
                    });
                    methodNames.forEach(function(m) { methods.push(m); });
                } else {
                    methods.push(targetMethod);
                }
                
                // 为每个方法添加hook
                methods.forEach(function(method) {
                    try {
                        var overloads = clazz[method].overloads;
                        overloads.forEach(function(overload) {
                            overload.implementation = function() {
                                console.log("\n[+] 调用方法: " + targetClass + "." + method);
                                
                                // 打印参数
                                if (arguments.length > 0) {
                                    console.log("[*] 参数:");
                                    for (var i = 0; i < arguments.length; i++) {
                                        try {
                                            console.log("    参数 " + i + ": " + 
                                                      (arguments[i] !== null ? 
                                                      arguments[i].toString() : "null"));
                                        } catch (e) {
                                            console.log("    参数 " + i + ": <无法显示>");
                                        }
                                    }
                                }
                                
                                // 打印堆栈
                                StackUtils.dumpStack({ skipFrames: 1, depth: 10 });
                                
                                // 调用原始方法
                                var retval = this[method].apply(this, arguments);
                                
                                // 显示返回值
                                try {
                                    console.log("[*] 返回值: " + (retval !== null ? retval.toString() : "null"));
                                } catch(e) {
                                    console.log("[*] 返回值: <无法显示>");
                                }
                                
                                return retval;
                            };
                        });
                        console.log("[+] 成功监控方法: " + targetClass + "." + method);
                    } catch(e) {
                        console.log("[-] 监控方法失败: " + targetClass + "." + method + ", 错误: " + e);
                    }
                });
            } catch (e) {
                console.log("[-] 监控类失败: " + targetClass + ", 错误: " + e);
            }
        },
        
        // 获取当前线程信息
        getCurrentThread: function() {
            var Thread = Java.use('java.lang.Thread');
            var currentThread = Thread.currentThread();
            console.log("\n[*] 当前线程信息:");
            console.log("  名称: " + currentThread.getName());
            console.log("  ID: " + currentThread.getId());
            console.log("  优先级: " + currentThread.getPriority());
            console.log("  状态: " + currentThread.getState());
            return currentThread;
        },
        
        // 获取Native层堆栈
        getNativeStack: function() {
            try {
                console.log("\n[*] Native层堆栈跟踪:");
                console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
                    .map(DebugSymbol.fromAddress)
                    .join('\n'));
            } catch (e) {
                console.log("[-] 获取Native堆栈失败: " + e);
            }
        }
    };
    
    // 全局暴露API
    global.dumpStack = StackUtils.dumpStack;
    global.dumpStackFiltered = StackUtils.dumpStackFiltered;
    global.monitorMethodStack = StackUtils.monitorMethodStack;
    
    // 默认执行一次堆栈打印，展示当前位置
    console.log("[*] 调用堆栈工具已加载:");
    StackUtils.dumpStack({ 
        skipFrames: 0,
        depth: 15, 
        detailedOutput: true
    });
    
    console.log("\n[*] 使用示例:");
    console.log("  dumpStack() - 打印完整堆栈");
    console.log("  dumpStack({depth: 5, showSystemFrames: false}) - 打印简化堆栈");
    console.log("  dumpStackFiltered('com.example') - 按包名筛选堆栈");
    console.log("  monitorMethodStack('类名', '方法名') - 监控特定方法的堆栈");
}); 