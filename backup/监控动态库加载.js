/*
 * 脚本名称：监控动态库加载.js
 * 功能：全面监控Android应用动态库加载、符号解析和使用行为
 * 适用场景：
 *   - 分析应用的Native层调用
 *   - 监控动态加载的恶意代码
 *   - 追踪JNI调用流程
 *   - 分析Native库依赖关系
 *   - 检测可能的安全风险
 * 使用方法：
 *   1. frida -U -f 包名 -l 监控动态库加载.js --no-pause
 *   2. 查看控制台输出，了解动态库加载情况
 * 启动方式说明：
 *   - -U 代表使用USB连接的设备
 *   - -f 代表以spawn方式启动目标应用（推荐，可捕获启动阶段的库加载）
 *   - --no-pause 指示Frida不要暂停应用执行
 * 支持特性：
 *   - 监控dlopen/android_dlopen_ext/System.loadLibrary等多种库加载方式
 *   - 分析加载参数和标志位
 *   - 显示库的基地址和加载时间
 *   - 输出符号表信息和导出函数
 *   - 检测可能的安全风险
 *   - 分析库的依赖关系
 *   - 支持自定义过滤规则
 */

(function() {
    // 配置选项
    var config = {
        logLevel: 2,                // 0:关闭 1:错误 2:基本信息 3:详细
        printStacktrace: true,      // 是否打印调用堆栈
        analyzeSymbols: true,       // 是否分析符号表
        detectRisks: true,          // 是否检测安全风险
        maxStackDepth: 10,          // 最大堆栈深度
        ignoreSystemLibs: false,    // 是否忽略系统库
        dumpExports: false,         // 是否输出所有导出函数(可能很多)
        watchJniRegister: true,     // 监控JNI注册
        monitorFunctions: [         // 要监控的特定函数
            "JNI_OnLoad",
            "memcpy", 
            "strncpy",
            "dlsym"
        ],
        dangerFunctions: [          // 可能存在安全风险的函数
            "system",
            "exec",
            "popen",
            "fork",
            "setreuid",
            "setresuid"
        ]
    };
    
    // 加载库的历史记录
    var loadedLibraries = {};
    var libraryLoadCount = 0;
    
    // 辅助函数：日志输出
    function log(level, message) {
        if (level <= config.logLevel) {
            var prefix = "";
            switch (level) {
                case 1: prefix = "[!] "; break;
                case 2: prefix = "[*] "; break;
                case 3: prefix = "[+] "; break;
            }
            console.log(prefix + message);
        }
    }
    
    // 辅助函数：获取Java调用堆栈
    function getStackTrace() {
        if (!config.printStacktrace) return "";
        
        try {
            var stack = "";
            var e = Java.use("java.lang.Exception").$new();
            var stackElements = e.getStackTrace();
            var limit = Math.min(stackElements.length, config.maxStackDepth);
            
            if (limit > 0) {
                stack = "\n    Java Stack:";
                for (var i = 0; i < limit; i++) {
                    var element = stackElements[i];
                    stack += "\n        " + element.getClassName() + "." + element.getMethodName() + 
                           "(" + element.getFileName() + ":" + element.getLineNumber() + ")";
                }
            }
            
            // 添加Native堆栈
            try {
                stack += "\n    Native Stack:";
                stack += "\n        " + Thread.backtrace(this.context, Backtracer.ACCURATE)
                      .map(DebugSymbol.fromAddress).join("\n        ");
            } catch (err) {}
            
            return stack;
        } catch (e) {
            return "\n    无法获取堆栈: " + e;
        }
    }
    
    // 辅助函数：分析模块安全风险
    function analyzeModuleSecurity(moduleName, moduleHandle) {
        if (!config.detectRisks) return;
        
        try {
            var module = Process.findModuleByName(moduleName);
            if (!module) return;
            
            log(2, "分析模块安全风险: " + moduleName);
            
            // 检查可写可执行段
            var wxSegments = 0;
            module.enumerateRanges('rwx').forEach(function(range) {
                wxSegments++;
                log(1, "发现可写可执行段: " + range.base + " - " + range.base.add(range.size) + 
                    " (大小: " + range.size + ")");
            });
            
            if (wxSegments > 0) {
                log(1, "警告: 模块 " + moduleName + " 包含 " + wxSegments + " 个可写可执行内存段，可能存在安全风险");
            }
            
            // 检查危险函数
            if (config.dangerFunctions.length > 0) {
                var foundDangerFunctions = [];
                
                config.dangerFunctions.forEach(function(funcName) {
                    var funcPtr = Module.findExportByName(moduleName, funcName);
                    if (funcPtr) {
                        foundDangerFunctions.push(funcName);
                    }
                });
                
                if (foundDangerFunctions.length > 0) {
                    log(1, "警告: 模块 " + moduleName + " 使用了可能存在风险的函数: " + foundDangerFunctions.join(", "));
                }
            }
            
        } catch (e) {
            log(1, "分析模块安全风险失败: " + e);
        }
    }
    
    // 辅助函数：获取符号表信息
    function getSymbolInfo(moduleName) {
        if (!config.analyzeSymbols) return "";
        
        try {
            var module = Process.findModuleByName(moduleName);
            if (!module) return "";
            
            var symbolInfo = "\n    符号分析:";
            var exports = module.enumerateExports();
            var imports = module.enumerateImports();
            
            symbolInfo += "\n        导出函数: " + exports.length + " 个";
            if (config.dumpExports && exports.length > 0) {
                var limit = Math.min(exports.length, 10);
                symbolInfo += "\n        样例导出: ";
                for (var i = 0; i < limit; i++) {
                    symbolInfo += "\n            " + exports[i].name + " - " + exports[i].address;
                }
                if (exports.length > limit) {
                    symbolInfo += "\n            ... 等" + (exports.length - limit) + "个函数";
                }
            }
            
            symbolInfo += "\n        导入函数: " + imports.length + " 个";
            
            // 检测是否使用了监控目标函数
            var monitoredImports = [];
            imports.forEach(function(imp) {
                if (config.monitorFunctions.indexOf(imp.name) !== -1) {
                    monitoredImports.push(imp.name);
                }
            });
            
            if (monitoredImports.length > 0) {
                symbolInfo += "\n        使用了关注函数: " + monitoredImports.join(", ");
            }
            
            // 获取依赖库
            var dependencies = [];
            imports.forEach(function(imp) {
                if (imp.module && dependencies.indexOf(imp.module) === -1) {
                    dependencies.push(imp.module);
                }
            });
            
            if (dependencies.length > 0) {
                symbolInfo += "\n        依赖库: " + dependencies.join(", ");
            }
            
            return symbolInfo;
        } catch (e) {
            return "\n    符号分析失败: " + e;
        }
    }
    
    // 监控 dlopen
    Interceptor.attach(Module.findExportByName(null, "dlopen"), {
        onEnter: function (args) {
            this.startTime = new Date().getTime();
            this.soPath = args[0].readCString();
            this.mode = args[1].toInt32();
            
            var soName = this.soPath.split("/").pop();
            
            // 过滤系统库
            if (config.ignoreSystemLibs && (
                this.soPath.indexOf("/system/") === 0 || 
                this.soPath.indexOf("/vendor/") === 0)) {
                this.shouldLog = false;
                return;
            }
            
            this.shouldLog = true;
            libraryLoadCount++;
            
            var modeStr = "";
            if (this.mode & 1) modeStr += "RTLD_LAZY|";
            if (this.mode & 2) modeStr += "RTLD_NOW|";
            if (this.mode & 4) modeStr += "RTLD_NOLOAD|";
            if (this.mode & 8) modeStr += "RTLD_GLOBAL|";
            if (this.mode & 256) modeStr += "RTLD_NODELETE|";
            modeStr = modeStr.slice(0, -1); // 去掉末尾的|
            
            log(2, "dlopen调用 (#" + libraryLoadCount + ")");
            log(2, "    路径: " + this.soPath);
            log(2, "    模式: " + this.mode + " (" + modeStr + ")");
            
            if (config.printStacktrace) {
                log(3, "    调用堆栈: " + getStackTrace.call(this));
            }
        },
        onLeave: function (retval) {
            if (!this.shouldLog) return;
            
            var handle = retval;
            var loadTime = new Date().getTime() - this.startTime;
            var soName = this.soPath.split("/").pop();
            
            if (handle.isNull()) {
                log(1, "加载失败: " + this.soPath);
                // 尝试获取错误信息
                var dlerrorPtr = Module.findExportByName(null, "dlerror");
                if (dlerrorPtr) {
                    var dlerror = new NativeFunction(dlerrorPtr, 'pointer', []);
                    var errorPtr = dlerror();
                    if (!errorPtr.isNull()) {
                        log(1, "    错误信息: " + errorPtr.readCString());
                    }
                }
            } else {
                log(2, "加载成功: " + this.soPath);
                log(2, "    句柄: " + handle);
                log(2, "    加载耗时: " + loadTime + "ms");
                
                // 记录库信息以避免重复分析
                loadedLibraries[this.soPath] = {
                    handle: handle,
                    loadTime: new Date(),
                    analyzed: false
                };
                
                // 延迟分析，确保库完全加载
                setTimeout(function() {
                    if (loadedLibraries[this.soPath] && !loadedLibraries[this.soPath].analyzed) {
                        // 获取导出函数信息
                        var symbolInfo = getSymbolInfo(soName);
                        if (symbolInfo) log(2, symbolInfo);
                        
                        // 安全分析
                        analyzeModuleSecurity(soName, handle);
                        
                        loadedLibraries[this.soPath].analyzed = true;
                    }
                }.bind(this), 100);
            }
        }
    });
    
    // 监控 android_dlopen_ext (Android特有API)
    var android_dlopen_ext = Module.findExportByName(null, "android_dlopen_ext");
    if (android_dlopen_ext) {
        Interceptor.attach(android_dlopen_ext, {
            onEnter: function (args) {
                this.startTime = new Date().getTime();
                this.soPath = args[0].readCString();
                this.mode = args[1].toInt32();
                
                // 过滤系统库
                if (config.ignoreSystemLibs && (
                    this.soPath.indexOf("/system/") === 0 || 
                    this.soPath.indexOf("/vendor/") === 0)) {
                    this.shouldLog = false;
                    return;
                }
                
                this.shouldLog = true;
                libraryLoadCount++;
                
                log(2, "android_dlopen_ext调用 (#" + libraryLoadCount + ")");
                log(2, "    路径: " + this.soPath);
                log(2, "    模式: " + this.mode);
                
                // extinfo参数的解析（复杂的结构体，简化处理）
                if (args[2] != 0) {
                    log(3, "    使用了扩展信息");
                }
                
                if (config.printStacktrace) {
                    log(3, "    调用堆栈: " + getStackTrace.call(this));
                }
            },
            onLeave: function (retval) {
                if (!this.shouldLog) return;
                
                var handle = retval;
                var loadTime = new Date().getTime() - this.startTime;
                var soName = this.soPath.split("/").pop();
                
                if (handle.isNull()) {
                    log(1, "加载失败: " + this.soPath);
                } else {
                    log(2, "加载成功: " + this.soPath);
                    log(2, "    句柄: " + handle);
                    log(2, "    加载耗时: " + loadTime + "ms");
                    
                    // 记录库信息
                    loadedLibraries[this.soPath] = {
                        handle: handle,
                        loadTime: new Date(),
                        analyzed: false
                    };
                    
                    // 延迟分析
                    setTimeout(function() {
                        if (loadedLibraries[this.soPath] && !loadedLibraries[this.soPath].analyzed) {
                            var symbolInfo = getSymbolInfo(soName);
                            if (symbolInfo) log(2, symbolInfo);
                            
                            analyzeModuleSecurity(soName, handle);
                            
                            loadedLibraries[this.soPath].analyzed = true;
                        }
                    }.bind(this), 100);
                }
            }
        });
    }
    
    // 监控 System.loadLibrary (Java层加载)
    Java.perform(function() {
        try {
            var System = Java.use("java.lang.System");
            
            System.loadLibrary.implementation = function(libname) {
                var startTime = new Date().getTime();
                log(2, "System.loadLibrary调用");
                log(2, "    库名称: " + libname);
                
                if (config.printStacktrace) {
                    var stack = Java.use("java.lang.Exception").$new().getStackTrace();
                    var stackInfo = "\n    Java调用堆栈:";
                    var limit = Math.min(stack.length, config.maxStackDepth);
                    
                    for (var i = 0; i < limit; i++) {
                        stackInfo += "\n        " + stack[i].getClassName() + "." + 
                                   stack[i].getMethodName() + "(" + 
                                   stack[i].getFileName() + ":" + 
                                   stack[i].getLineNumber() + ")";
                    }
                    log(3, stackInfo);
                }
                
                // 调用原始方法
                try {
                    this.loadLibrary(libname);
                    var loadTime = new Date().getTime() - startTime;
                    log(2, "    加载成功，耗时: " + loadTime + "ms");
                    
                    // 获取实际库名称（添加lib前缀和.so后缀）
                    var actualName = "lib" + libname + ".so";
                    
                    // 延迟分析
                    setTimeout(function() {
                        var symbolInfo = getSymbolInfo(actualName);
                        if (symbolInfo) log(2, symbolInfo);
                        
                        analyzeModuleSecurity(actualName);
                    }, 100);
                    
                } catch (e) {
                    log(1, "    加载失败: " + e);
                }
            };
            
            // 监控 Runtime.loadLibrary (内部使用，不常见)
            var Runtime = Java.use("java.lang.Runtime");
            Runtime.loadLibrary.overload('java.lang.Class', 'java.lang.String').implementation = function(clazz, libname) {
                log(2, "Runtime.loadLibrary调用");
                log(2, "    类: " + clazz.getName());
                log(2, "    库名称: " + libname);
                
                try {
                    this.loadLibrary(clazz, libname);
                    log(2, "    加载成功");
                } catch (e) {
                    log(1, "    加载失败: " + e);
                }
            };
            
        } catch (e) {
            log(1, "监控Java层库加载失败: " + e);
        }
    });
    
    // 监控 dlsym (获取库中的函数符号)
    var dlsym = Module.findExportByName(null, "dlsym");
    if (dlsym && config.watchJniRegister) {
        Interceptor.attach(dlsym, {
            onEnter: function (args) {
                this.handle = args[0];
                this.symbol = args[1].readCString();
                
                // 只记录特定的函数
                if (config.monitorFunctions.indexOf(this.symbol) !== -1 || 
                    this.symbol.indexOf("JNI_") === 0 || 
                    this.symbol.indexOf("Java_") === 0) {
                    log(2, "dlsym调用");
                    log(2, "    句柄: " + this.handle);
                    log(2, "    符号: " + this.symbol);
                    
                    if (config.printStacktrace) {
                        log(3, "    调用堆栈: " + getStackTrace.call(this));
                    }
                } else {
                    this.skip = true;
                }
            },
            onLeave: function (retval) {
                if (this.skip) return;
                
                if (retval.isNull()) {
                    log(1, "    查找符号失败: " + this.symbol);
                } else {
                    log(2, "    查找符号成功: " + this.symbol + " @ " + retval);
                }
            }
        });
    }
    
    // 监控 JNI_OnLoad (特别关注)
    var jni_onload_addresses = [];
    Process.enumerateModules().forEach(function(module) {
        var JNI_OnLoad = Module.findExportByName(module.name, "JNI_OnLoad");
        if (JNI_OnLoad) {
            jni_onload_addresses.push({name: module.name, address: JNI_OnLoad});
        }
    });
    
    jni_onload_addresses.forEach(function(item) {
        Interceptor.attach(item.address, {
            onEnter: function (args) {
                log(2, "JNI_OnLoad调用");
                log(2, "    模块: " + item.name);
                log(2, "    JavaVM: " + args[0]);
                
                if (config.printStacktrace) {
                    log(3, "    调用堆栈: " + getStackTrace.call(this));
                }
            },
            onLeave: function (retval) {
                log(2, "    JNI_OnLoad返回: " + retval);
                
                // JNI版本解析
                if (retval.equals(0x00010001)) {
                    log(2, "    JNI版本: JNI_VERSION_1_1");
                } else if (retval.equals(0x00010002)) {
                    log(2, "    JNI版本: JNI_VERSION_1_2");
                } else if (retval.equals(0x00010004)) {
                    log(2, "    JNI版本: JNI_VERSION_1_4");
                } else if (retval.equals(0x00010006)) {
                    log(2, "    JNI版本: JNI_VERSION_1_6");
                } else if (retval.equals(0x00010008)) {
                    log(2, "    JNI版本: JNI_VERSION_1_8");
                } else if (retval.equals(0x00010009)) {
                    log(2, "    JNI版本: JNI_VERSION_1_9 (Java 9+)");
                }
            }
        });
    });
    
    // 打印初始化信息
    log(2, "动态库加载监控初始化完成");
    log(2, "当前已加载模块: " + Process.enumerateModules().length + "个");
    if (android_dlopen_ext) {
        log(2, "已启用android_dlopen_ext监控");
    }
    if (jni_onload_addresses.length > 0) {
        log(2, "已初始化JNI_OnLoad监控: " + jni_onload_addresses.length + "个函数");
    }
    log(2, "等待库加载事件...");
})(); 