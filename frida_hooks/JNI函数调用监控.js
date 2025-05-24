/**
 * JNI函数调用监控脚本
 * 
 * 功能：监控Android应用中的JNI函数调用
 * 作用：分析应用对Native层代码的调用，检测敏感操作
 * 适用：分析使用了NDK/JNI的应用，检测Native层的安全风险
 */

// 等待Java虚拟机加载完成
Java.perform(function() {
    console.log("[*] JNI函数调用监控脚本已启动");

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
     * 工具函数：格式化参数
     */
    function formatArguments(args) {
        if (!args || args.length === 0) return "无参数";
        
        var result = [];
        for (var i = 0; i < args.length; i++) {
            var arg = args[i];
            if (arg === null) {
                result.push("null");
            } else if (typeof arg === "object") {
                result.push(arg.getClass ? arg.getClass().getName() : Object.prototype.toString.call(arg));
            } else {
                result.push(String(arg));
            }
        }
        
        return result.join(", ");
    }

    /**
     * 一、监控System.loadLibrary和System.load
     * 用于加载Native库
     */
    var System = Java.use("java.lang.System");
    
    // 拦截loadLibrary方法
    System.loadLibrary.implementation = function(libname) {
        console.log("\n[+] System.loadLibrary");
        console.log("    库名称: " + libname);
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        this.loadLibrary(libname);
        console.log("    库加载成功");
        
        // 尝试枚举已加载的库中的导出函数
        try {
            var libraryName = "lib" + libname + ".so";
            var exports = Module.enumerateExportsSync(libraryName);
            if (exports.length > 0) {
                console.log("    导出函数列表:");
                for (var i = 0; i < Math.min(exports.length, 30); i++) { // 限制显示数量
                    console.log("      - " + exports[i].name + " (类型: " + exports[i].type + ", 地址: " + exports[i].address + ")");
                }
                if (exports.length > 30) {
                    console.log("      ... 共 " + exports.length + " 个导出函数");
                }
            } else {
                console.log("    未找到导出函数");
            }
        } catch (e) {
            console.log("    无法枚举导出函数: " + e);
        }
    };
    
    // 拦截load方法
    System.load.implementation = function(filename) {
        console.log("\n[+] System.load");
        console.log("    文件路径: " + filename);
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        this.load(filename);
        console.log("    库加载成功");
        
        // 尝试获取库名称
        var parts = filename.split("/");
        var libraryName = parts[parts.length - 1];
        
        // 尝试枚举已加载的库中的导出函数
        try {
            var exports = Module.enumerateExportsSync(libraryName);
            if (exports.length > 0) {
                console.log("    导出函数列表:");
                for (var i = 0; i < Math.min(exports.length, 30); i++) { // 限制显示数量
                    console.log("      - " + exports[i].name + " (类型: " + exports[i].type + ", 地址: " + exports[i].address + ")");
                }
                if (exports.length > 30) {
                    console.log("      ... 共 " + exports.length + " 个导出函数");
                }
            } else {
                console.log("    未找到导出函数");
            }
        } catch (e) {
            console.log("    无法枚举导出函数: " + e);
        }
    };

    /**
     * 二、监控带有native修饰符的方法
     * 这些方法会调用Native层的实现
     */
    
    // 遍历已加载的类
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            // 过滤系统类和常见库类，减少日志量
            if (className.startsWith("android.") || 
                className.startsWith("java.") || 
                className.startsWith("javax.") || 
                className.startsWith("sun.") || 
                className.startsWith("com.android.") ||
                className.startsWith("androidx.")) {
                return;
            }
            
            try {
                var jClass = Java.use(className);
                var methods = jClass.class.getDeclaredMethods();
                
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
                            var hookCode = "jClass." + methodSignature + ".implementation = function() {";
                            hookCode += "console.log('\\n[+] 调用Native方法: " + className + "." + methodName + "');";
                            hookCode += "console.log('    参数: ' + formatArguments(arguments));";
                            hookCode += "console.log('    调用堆栈:\\n    ' + getStackTrace());";
                            hookCode += "var result = this." + methodName + ".apply(this, arguments);";
                            hookCode += "console.log('    返回值: ' + result);";
                            hookCode += "return result;";
                            hookCode += "};";
                            
                            eval(hookCode);
                            console.log("    [已Hook]");
                        } catch (e) {
                            console.log("    [Hook失败]: " + e);
                        }
                    }
                }
            } catch (e) {
                // 忽略无法处理的类
            }
        },
        onComplete: function() {
            console.log("[*] Native方法扫描完成");
        }
    });

    /**
     * 三、监控JNI接口函数
     * 拦截常见的JNI函数调用
     */
    
    // 获取当前进程的模块列表
    var modules = Process.enumerateModules();
    console.log("\n[+] 已加载模块列表:");
    for (var i = 0; i < modules.length; i++) {
        console.log("    - " + modules[i].name + " (基址: " + modules[i].base + ", 大小: " + modules[i].size + ")");
    }
    
    // 尝试拦截一些关键的JNI函数
    try {
        // 获取libart.so模块，它包含了Android运行时的JNI实现
        var libart = Process.findModuleByName("libart.so");
        if (libart) {
            console.log("\n[+] 找到libart.so模块，尝试拦截JNI函数");
            
            // 拦截RegisterNatives函数，它用于注册Native方法
            var RegisterNatives = null;
            var symbols = libart.enumerateSymbols();
            for (var i = 0; i < symbols.length; i++) {
                if (symbols[i].name.indexOf("RegisterNatives") !== -1) {
                    RegisterNatives = symbols[i].address;
                    console.log("    找到RegisterNatives函数: " + symbols[i].name + " 地址: " + RegisterNatives);
                    break;
                }
            }
            
            if (RegisterNatives) {
                Interceptor.attach(RegisterNatives, {
                    onEnter: function(args) {
                        var env = args[0];
                        var clazz = args[1];
                        var methods = args[2];
                        var methodCount = args[3].toInt32();
                        
                        // 获取类名
                        var className = Java.vm.getEnv().getClassName(clazz);
                        console.log("\n[+] RegisterNatives调用:");
                        console.log("    类名: " + className);
                        console.log("    方法数量: " + methodCount);
                        
                        // 尝试获取方法信息
                        for (var i = 0; i < methodCount; i++) {
                            var methodInfo = methods.add(i * Process.pointerSize * 3);
                            var namePtr = Memory.readPointer(methodInfo);
                            var name = Memory.readCString(namePtr);
                            var sig = Memory.readCString(Memory.readPointer(methodInfo.add(Process.pointerSize)));
                            var fnPtr = Memory.readPointer(methodInfo.add(Process.pointerSize * 2));
                            
                            console.log("    方法 #" + i + ": " + name + " 签名: " + sig + " 函数地址: " + fnPtr);
                            
                            // 尝试拦截这个native函数
                            try {
                                Interceptor.attach(fnPtr, {
                                    onEnter: function(args) {
                                        this.methodName = name;
                                        console.log("\n[+] 调用Native函数: " + className + "." + this.methodName);
                                    },
                                    onLeave: function(retval) {
                                        console.log("    Native函数返回: " + className + "." + this.methodName + " 返回值: " + retval);
                                    }
                                });
                                console.log("      [已Hook Native函数]");
                            } catch (e) {
                                console.log("      [Hook Native函数失败]: " + e);
                            }
                        }
                    }
                });
                console.log("    [已Hook RegisterNatives函数]");
            }
        }
    } catch (e) {
        console.log("[-] 拦截JNI函数失败: " + e);
    }

    /**
     * 四、监控JNI环境函数
     * 拦截一些重要的JNIEnv函数
     */
    try {
        var libc = Process.findModuleByName("libc.so");
        if (libc) {
            // 拦截dlopen函数，它用于动态加载库
            var dlopen = Module.findExportByName("libc.so", "dlopen");
            if (dlopen) {
                Interceptor.attach(dlopen, {
                    onEnter: function(args) {
                        var path = Memory.readCString(args[0]);
                        var flags = args[1].toInt32();
                        this.path = path;
                        console.log("\n[+] dlopen调用:");
                        console.log("    路径: " + path);
                        console.log("    标志: " + flags);
                    },
                    onLeave: function(retval) {
                        console.log("    dlopen返回: " + this.path + " 句柄: " + retval);
                    }
                });
                console.log("\n[+] 已Hook dlopen函数");
            }
            
            // 拦截dlsym函数，它用于获取库中的函数地址
            var dlsym = Module.findExportByName("libc.so", "dlsym");
            if (dlsym) {
                Interceptor.attach(dlsym, {
                    onEnter: function(args) {
                        var handle = args[0];
                        var symbol = Memory.readCString(args[1]);
                        this.symbol = symbol;
                        console.log("\n[+] dlsym调用:");
                        console.log("    句柄: " + handle);
                        console.log("    符号: " + symbol);
                    },
                    onLeave: function(retval) {
                        console.log("    dlsym返回: " + this.symbol + " 地址: " + retval);
                    }
                });
                console.log("[+] 已Hook dlsym函数");
            }
        }
    } catch (e) {
        console.log("[-] 拦截动态链接函数失败: " + e);
    }

    /**
     * 五、监控常见的Native层敏感函数
     */
    var sensitiveNativeFunctions = [
        // 文件操作
        { module: "libc.so", name: "fopen" },
        { module: "libc.so", name: "fread" },
        { module: "libc.so", name: "fwrite" },
        
        // 内存操作
        { module: "libc.so", name: "mmap" },
        { module: "libc.so", name: "memcpy" },
        
        // 进程操作
        { module: "libc.so", name: "fork" },
        { module: "libc.so", name: "execve" },
        
        // 网络操作
        { module: "libc.so", name: "socket" },
        { module: "libc.so", name: "connect" },
        { module: "libc.so", name: "send" },
        { module: "libc.so", name: "recv" }
    ];
    
    console.log("\n[+] 开始Hook敏感Native函数");
    
    for (var i = 0; i < sensitiveNativeFunctions.length; i++) {
        var func = sensitiveNativeFunctions[i];
        try {
            var address = Module.findExportByName(func.module, func.name);
            if (address) {
                Interceptor.attach(address, {
                    onEnter: function(args) {
                        var funcName = DebugSymbol.fromAddress(this.returnAddress).name || this.returnAddress;
                        console.log("\n[+] 调用敏感Native函数: " + funcName);
                        
                        // 根据不同函数处理参数
                        if (funcName.indexOf("fopen") !== -1) {
                            var path = Memory.readCString(args[0]);
                            var mode = Memory.readCString(args[1]);
                            console.log("    路径: " + path);
                            console.log("    模式: " + mode);
                        } else if (funcName.indexOf("socket") !== -1) {
                            console.log("    域: " + args[0].toInt32());
                            console.log("    类型: " + args[1].toInt32());
                            console.log("    协议: " + args[2].toInt32());
                        } else if (funcName.indexOf("connect") !== -1) {
                            // 这里可以解析sockaddr结构体获取详细信息
                            console.log("    套接字: " + args[0].toInt32());
                        }
                    },
                    onLeave: function(retval) {
                        var funcName = DebugSymbol.fromAddress(this.returnAddress).name || this.returnAddress;
                        console.log("    " + funcName + " 返回: " + retval);
                    }
                });
                console.log("    已Hook " + func.name);
            }
        } catch (e) {
            console.log("    Hook " + func.name + " 失败: " + e);
        }
    }

    console.log("[*] JNI函数调用监控设置完成");
}); 