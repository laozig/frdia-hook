/**
 * Native层函数追踪脚本
 * 
 * 功能：追踪Android应用中Native层函数的调用
 * 作用：分析SO库中的函数调用流程，参数和返回值
 * 适用：逆向分析使用JNI/NDK的应用，分析SO库
 */

// 等待Java虚拟机加载完成
Java.perform(function() {
    console.log("[*] Native层函数追踪脚本已启动");

    // 全局配置
    var config = {
        // 是否打印参数和返回值的详细信息
        printArgs: true,
        // 是否打印调用堆栈
        printStack: true,
        // 是否打印内存数据
        printMemory: true,
        // 内存数据打印长度
        memoryDataSize: 64,
        // 是否自动追踪子函数调用
        traceSubCalls: false,
        // 最大追踪深度
        maxTraceDepth: 3
    };

    /**
     * 工具函数：获取调用堆栈
     */
    function getStackTrace() {
        var Exception = Java.use("java.lang.Exception");
        var exception = Exception.$new();
        var stackTrace = exception.getStackTrace();
        exception.$dispose();
        
        var stack = [];
        for (var i = 0; i < stackTrace.length; i++) {
            var element = stackTrace[i];
            var className = element.getClassName();
            var methodName = element.getMethodName();
            var fileName = element.getFileName();
            var lineNumber = element.getLineNumber();
            
            // 过滤掉Frida相关的堆栈
            if (className.indexOf("com.frida") === -1) {
                stack.push(className + "." + methodName + "(" + fileName + ":" + lineNumber + ")");
            }
            
            // 只获取前10个堆栈元素
            if (stack.length >= 10) break;
        }
        
        return stack.join("\n    ");
    }

    /**
     * 工具函数：格式化十六进制数据
     */
    function hexdump(data, size) {
        if (!data) return "null";
        
        size = size || 32;
        if (typeof data === "number") {
            data = ptr(data);
        }
        
        try {
            var buf = Memory.readByteArray(data, size);
            if (buf === null) {
                return "无法读取内存";
            }
            
            var result = [];
            var bytes = new Uint8Array(buf);
            var ascii = "";
            var line = "";
            
            for (var i = 0; i < bytes.length; i++) {
                // 每16字节换行
                if (i % 16 === 0) {
                    if (line !== "") {
                        result.push(line + "  " + ascii);
                        ascii = "";
                        line = "";
                    }
                    line = ("0000" + i.toString(16)).substr(-4) + ": ";
                }
                
                var value = bytes[i].toString(16);
                if (value.length === 1) {
                    value = "0" + value;
                }
                line += value + " ";
                
                if (bytes[i] >= 32 && bytes[i] <= 126) {
                    ascii += String.fromCharCode(bytes[i]);
                } else {
                    ascii += ".";
                }
            }
            
            if (line !== "") {
                var padding = "   ".repeat(16 - (bytes.length % 16));
                result.push(line + padding + "  " + ascii);
            }
            
            return result.join("\n");
        } catch (e) {
            return "hexdump错误: " + e;
        }
    }

    /**
     * 工具函数：格式化函数参数
     */
    function formatArgs(args, count) {
        if (!config.printArgs) return "";
        if (!args || count === 0) return "无参数";
        
        var result = [];
        for (var i = 0; i < count; i++) {
            var arg = args[i];
            if (arg.equals(0)) {
                result.push("arg" + i + ": NULL (0x0)");
            } else {
                result.push("arg" + i + ": " + arg + " (0x" + arg.toString(16) + ")");
                
                // 尝试读取内存数据
                if (config.printMemory) {
                    try {
                        var data = Memory.readByteArray(arg, config.memoryDataSize);
                        if (data) {
                            result.push("    数据: \n" + hexdump(data, Math.min(config.memoryDataSize, 32)));
                        }
                    } catch (e) {
                        // 忽略内存读取错误
                    }
                    
                    // 尝试读取字符串
                    try {
                        var str = Memory.readUtf8String(arg);
                        if (str && str.length > 0) {
                            result.push("    字符串: " + str);
                        }
                    } catch (e) {
                        // 忽略字符串读取错误
                    }
                }
            }
        }
        
        return result.join("\n");
    }

    /**
     * 工具函数：追踪指定模块中的所有导出函数
     */
    function traceModuleExports(moduleName) {
        var module = Process.findModuleByName(moduleName);
        if (!module) {
            console.log("[-] 找不到模块: " + moduleName);
            return;
        }
        
        console.log("[+] 追踪模块: " + moduleName + " 基址: " + module.base);
        
        var exports = module.enumerateExports();
        console.log("[+] 找到 " + exports.length + " 个导出函数");
        
        for (var i = 0; i < exports.length; i++) {
            var exp = exports[i];
            
            // 只追踪函数类型的导出
            if (exp.type === "function") {
                traceFunction(exp.address, exp.name, moduleName);
            }
        }
    }

    /**
     * 工具函数：追踪指定函数
     */
    function traceFunction(address, name, moduleName, depth) {
        depth = depth || 0;
        if (depth >= config.maxTraceDepth && config.traceSubCalls) {
            return;
        }
        
        var indent = "  ".repeat(depth);
        
        try {
            Interceptor.attach(address, {
                onEnter: function(args) {
                    this.name = name;
                    this.module = moduleName;
                    this.depth = depth;
                    this.args = args;
                    this.startTime = new Date().getTime();
                    
                    console.log("\n" + indent + "[+] 调用: " + this.module + "!" + this.name);
                    
                    // 打印参数
                    var argsStr = formatArgs(args, 10); // 最多打印10个参数
                    if (argsStr) {
                        console.log(indent + "    参数:\n" + indent + "    " + argsStr.replace(/\n/g, "\n" + indent + "    "));
                    }
                    
                    // 打印调用堆栈
                    if (config.printStack) {
                        var stack = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress);
                        console.log(indent + "    调用堆栈:");
                        for (var i = 0; i < stack.length; i++) {
                            console.log(indent + "        " + stack[i]);
                        }
                    }
                    
                    // 如果启用了Java堆栈，打印Java调用堆栈
                    if (config.printStack) {
                        try {
                            var javaStack = getStackTrace();
                            if (javaStack) {
                                console.log(indent + "    Java调用堆栈:\n" + indent + "    " + javaStack.replace(/\n/g, "\n" + indent + "    "));
                            }
                        } catch (e) {
                            // 忽略Java堆栈错误
                        }
                    }
                    
                    // 如果启用了子函数追踪，追踪该函数调用的其他函数
                    if (config.traceSubCalls && depth < config.maxTraceDepth) {
                        this.tracing = true;
                        Stalker.follow(this.threadId, {
                            events: {
                                call: true,
                                ret: false,
                                exec: false
                            },
                            onReceive: function(events) {
                                var reader = Stalker.parse(events);
                                var event;
                                while ((event = reader.next()) !== null) {
                                    if (event.type === 'call') {
                                        var target = event.target;
                                        var targetModule = Process.findModuleByAddress(target);
                                        if (targetModule) {
                                            var targetName = DebugSymbol.fromAddress(target).name;
                                            if (targetName && targetName !== this.name) {
                                                traceFunction(target, targetName, targetModule.name, depth + 1);
                                            }
                                        }
                                    }
                                }
                            }
                        });
                    }
                },
                onLeave: function(retval) {
                    var execTime = new Date().getTime() - this.startTime;
                    
                    console.log(indent + "[-] 返回: " + this.module + "!" + this.name);
                    console.log(indent + "    返回值: " + retval + " (0x" + retval.toString(16) + ")");
                    console.log(indent + "    执行时间: " + execTime + "ms");
                    
                    // 如果启用了子函数追踪，停止追踪
                    if (this.tracing) {
                        Stalker.unfollow(this.threadId);
                    }
                    
                    return retval;
                }
            });
            
            console.log("[+] 已Hook: " + (moduleName ? moduleName + "!" : "") + name);
        } catch (e) {
            console.log("[-] Hook失败: " + (moduleName ? moduleName + "!" : "") + name + " - " + e);
        }
    }

    /**
     * 工具函数：追踪指定模式的函数
     */
    function traceFunctionsMatchingPattern(pattern, moduleName) {
        var module = Process.findModuleByName(moduleName);
        if (!module) {
            console.log("[-] 找不到模块: " + moduleName);
            return;
        }
        
        console.log("[+] 在模块中搜索匹配模式的函数: " + moduleName + " 模式: " + pattern);
        
        var regex = new RegExp(pattern);
        var exports = module.enumerateExports();
        var matchCount = 0;
        
        for (var i = 0; i < exports.length; i++) {
            var exp = exports[i];
            
            // 检查函数名是否匹配模式
            if (exp.type === "function" && regex.test(exp.name)) {
                traceFunction(exp.address, exp.name, moduleName);
                matchCount++;
            }
        }
        
        console.log("[+] 找到并Hook了 " + matchCount + " 个匹配的函数");
    }

    /**
     * 工具函数：追踪JNI函数
     */
    function traceJNIFunctions() {
        console.log("[+] 开始追踪JNI函数");
        
        var jniEnvPtr = Java.vm.getEnv().handle;
        var jniEnv = ptr(jniEnvPtr).readPointer();
        
        // JNI函数表中的重要函数偏移
        var jniFunctionOffsets = {
            "FindClass": 6 * Process.pointerSize,
            "GetMethodID": 33 * Process.pointerSize,
            "GetFieldID": 24 * Process.pointerSize,
            "GetStaticMethodID": 113 * Process.pointerSize,
            "GetStaticFieldID": 104 * Process.pointerSize,
            "RegisterNatives": 215 * Process.pointerSize,
            "CallObjectMethod": 34 * Process.pointerSize,
            "CallBooleanMethod": 37 * Process.pointerSize,
            "CallIntMethod": 40 * Process.pointerSize,
            "CallLongMethod": 43 * Process.pointerSize,
            "CallFloatMethod": 46 * Process.pointerSize,
            "CallDoubleMethod": 49 * Process.pointerSize,
            "CallVoidMethod": 61 * Process.pointerSize,
            "CallStaticObjectMethod": 114 * Process.pointerSize,
            "CallStaticBooleanMethod": 117 * Process.pointerSize,
            "CallStaticIntMethod": 120 * Process.pointerSize,
            "CallStaticLongMethod": 123 * Process.pointerSize,
            "CallStaticFloatMethod": 126 * Process.pointerSize,
            "CallStaticDoubleMethod": 129 * Process.pointerSize,
            "CallStaticVoidMethod": 141 * Process.pointerSize,
            "GetStringUTFChars": 169 * Process.pointerSize,
            "NewStringUTF": 167 * Process.pointerSize
        };
        
        // 追踪JNI函数
        for (var funcName in jniFunctionOffsets) {
            var funcPtr = jniEnv.add(jniFunctionOffsets[funcName]).readPointer();
            traceFunction(funcPtr, "JNI_" + funcName, "libart.so");
        }
        
        console.log("[+] JNI函数追踪设置完成");
    }

    /**
     * 工具函数：追踪指定类的所有Native方法
     */
    function traceNativeMethodsInClass(className) {
        try {
            var clazz = Java.use(className);
            var methods = clazz.class.getDeclaredMethods();
            
            console.log("[+] 追踪类中的Native方法: " + className);
            
            var nativeMethodCount = 0;
            for (var i = 0; i < methods.length; i++) {
                var method = methods[i];
                
                // 检查方法是否为native
                if (method.getModifiers() & 0x0100) { // 0x0100是NATIVE修饰符
                    var methodName = method.getName();
                    
                    // 获取方法参数类型
                    var parameterTypes = method.getParameterTypes();
                    var paramTypeNames = [];
                    for (var j = 0; j < parameterTypes.length; j++) {
                        paramTypeNames.push(parameterTypes[j].getName());
                    }
                    
                    console.log("\n[+] 发现Native方法: " + className + "." + methodName);
                    console.log("    参数类型: " + paramTypeNames.join(", "));
                    console.log("    返回类型: " + method.getReturnType().getName());
                    
                    // 尝试hook这个native方法
                    try {
                        var methodSignature = methodName;
                        if (paramTypeNames.length > 0) {
                            methodSignature += ".overload('" + paramTypeNames.join("', '") + "')";
                        } else {
                            methodSignature += ".overload()";
                        }
                        
                        // 使用eval动态构建hook代码
                        var hookCode = "clazz." + methodSignature + ".implementation = function() {";
                        hookCode += "console.log('\\n[+] 调用Native方法: " + className + "." + methodName + "');";
                        
                        // 打印参数
                        if (config.printArgs) {
                            hookCode += "console.log('    参数:');";
                            hookCode += "for (var i = 0; i < arguments.length; i++) {";
                            hookCode += "    var arg = arguments[i];";
                            hookCode += "    if (arg === null) {";
                            hookCode += "        console.log('        arg' + i + ': null');";
                            hookCode += "    } else if (typeof arg === 'object') {";
                            hookCode += "        console.log('        arg' + i + ': ' + (arg.getClass ? arg.getClass().getName() : Object.prototype.toString.call(arg)));";
                            hookCode += "    } else {";
                            hookCode += "        console.log('        arg' + i + ': ' + arg);";
                            hookCode += "    }";
                            hookCode += "}";
                        }
                        
                        // 打印调用堆栈
                        if (config.printStack) {
                            hookCode += "console.log('    Java调用堆栈:\\n    ' + getStackTrace().replace(/\\n/g, '\\n    '));";
                        }
                        
                        hookCode += "var startTime = new Date().getTime();";
                        hookCode += "var result = this." + methodName + ".apply(this, arguments);";
                        hookCode += "var execTime = new Date().getTime() - startTime;";
                        hookCode += "console.log('    返回值: ' + result);";
                        hookCode += "console.log('    执行时间: ' + execTime + 'ms');";
                        hookCode += "return result;";
                        hookCode += "};";
                        
                        eval(hookCode);
                        console.log("    [已Hook]");
                        nativeMethodCount++;
                    } catch (e) {
                        console.log("    [Hook失败]: " + e);
                    }
                }
            }
            
            console.log("[+] 共Hook了 " + nativeMethodCount + " 个Native方法");
        } catch (e) {
            console.log("[-] 追踪类中的Native方法失败: " + e);
        }
    }

    /**
     * 工具函数：追踪所有已加载模块中的导出函数
     */
    function traceAllModulesExports(pattern) {
        var modules = Process.enumerateModules();
        console.log("[+] 找到 " + modules.length + " 个已加载模块");
        
        var regex = pattern ? new RegExp(pattern) : null;
        
        for (var i = 0; i < modules.length; i++) {
            var module = modules[i];
            
            // 跳过系统库
            if (module.name.indexOf("libc.so") !== -1 || 
                module.name.indexOf("libdvm.so") !== -1 || 
                module.name.indexOf("libart.so") !== -1) {
                continue;
            }
            
            // 如果指定了模式，检查模块名是否匹配
            if (regex && !regex.test(module.name)) {
                continue;
            }
            
            console.log("[+] 追踪模块: " + module.name);
            traceModuleExports(module.name);
        }
    }

    /**
     * 导出API到全局
     */
    // 追踪指定模块中的所有导出函数
    global.traceModule = function(moduleName) {
        traceModuleExports(moduleName);
    };
    
    // 追踪指定函数
    global.traceFunction = function(address, name, moduleName) {
        if (typeof address === "string") {
            // 如果address是字符串，尝试解析为地址
            address = ptr(address);
        }
        traceFunction(address, name || "UnknownFunction", moduleName || "UnknownModule");
    };
    
    // 追踪指定模式的函数
    global.traceFunctionsMatching = function(pattern, moduleName) {
        traceFunctionsMatchingPattern(pattern, moduleName);
    };
    
    // 追踪JNI函数
    global.traceJNI = function() {
        traceJNIFunctions();
    };
    
    // 追踪指定类的所有Native方法
    global.traceNativeMethods = function(className) {
        traceNativeMethodsInClass(className);
    };
    
    // 追踪所有已加载模块中的导出函数
    global.traceAllModules = function(pattern) {
        traceAllModulesExports(pattern);
    };
    
    // 修改配置
    global.setConfig = function(newConfig) {
        for (var key in newConfig) {
            if (config.hasOwnProperty(key)) {
                config[key] = newConfig[key];
                console.log("[+] 配置已更新: " + key + " = " + newConfig[key]);
            }
        }
    };
    
    // 打印当前配置
    global.showConfig = function() {
        console.log("[+] 当前配置:");
        for (var key in config) {
            console.log("    " + key + ": " + config[key]);
        }
    };

    console.log("[*] Native层函数追踪脚本已加载");
    console.log("[*] 使用方法:");
    console.log("    traceModule('libxxx.so') - 追踪指定模块中的所有导出函数");
    console.log("    traceFunction(address, 'funcName', 'moduleName') - 追踪指定函数");
    console.log("    traceFunctionsMatching('pattern', 'moduleName') - 追踪指定模式的函数");
    console.log("    traceJNI() - 追踪JNI函数");
    console.log("    traceNativeMethods('com.example.Class') - 追踪指定类的所有Native方法");
    console.log("    traceAllModules('pattern') - 追踪所有已加载模块中的导出函数");
    console.log("    setConfig({key: value}) - 修改配置");
    console.log("    showConfig() - 打印当前配置");
}); 