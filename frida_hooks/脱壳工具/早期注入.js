/**
 * Frida早期注入脚本
 * 
 * 功能：在应用启动的最早期阶段绕过反调试保护
 * 适用：具有强力反调试和反Frida检测的应用
 * 使用方法：frida -U -f 目标应用包名 -l 早期注入.js --no-pause
 */

(function() {
    // 配置选项
    const config = {
        // 是否在Native层进行拦截
        enableNativeHooks: true,
        // 是否在Java层进行拦截
        enableJavaHooks: true,
        // 是否打印详细日志
        verbose: true,
        // 是否拦截系统属性检测
        hookSystemProperties: true,
        // 是否拦截文件系统检测
        hookFilesystem: true
    };

    // 颜色输出
    const colors = {
        reset: "\x1b[0m",
        red: "\x1b[31m",
        green: "\x1b[32m",
        yellow: "\x1b[33m",
        blue: "\x1b[34m",
        magenta: "\x1b[35m",
        cyan: "\x1b[36m",
        white: "\x1b[37m"
    };

    function colorLog(color, message) {
        console.log(colors[color] + message + colors.reset);
    }

    function logInfo(message) {
        colorLog("green", "[*] " + message);
    }

    function logWarn(message) {
        colorLog("yellow", "[!] " + message);
    }

    function logError(message) {
        colorLog("red", "[-] " + message);
    }

    function logSuccess(message) {
        colorLog("cyan", "[+] " + message);
    }

    function logDebug(message) {
        if (config.verbose) {
            colorLog("magenta", "[D] " + message);
        }
    }

    // Native层拦截
    function setupNativeHooks() {
        if (!config.enableNativeHooks) return;
        
        logInfo("设置Native层拦截...");
        
        try {
            // 拦截open系统调用
            const openPtr = Module.getExportByName(null, "open");
            Interceptor.attach(openPtr, {
                onEnter: function(args) {
                    const path = Memory.readUtf8String(args[0]);
                    this.path = path;
                    
                    // 拦截对敏感文件的访问
                    if (path && (
                        path.indexOf("/proc/") !== -1 ||
                        path.indexOf("frida") !== -1 ||
                        path.indexOf("gum") !== -1 ||
                        path.indexOf("magisk") !== -1 ||
                        path.indexOf("su") !== -1
                    )) {
                        logDebug("拦截open: " + path);
                        // 重定向到/dev/null
                        Memory.writeUtf8String(args[0], "/dev/null");
                    }
                },
                onLeave: function(retval) {
                    // 如果是敏感文件，返回错误
                    if (this.path && (
                        this.path.indexOf("/proc/self/maps") !== -1 ||
                        this.path.indexOf("/proc/self/status") !== -1 ||
                        this.path.indexOf("/proc/self/task") !== -1
                    )) {
                        retval.replace(-1);
                    }
                }
            });
            
            // 拦截stat系统调用
            const statPtr = Module.getExportByName(null, "stat");
            Interceptor.attach(statPtr, {
                onEnter: function(args) {
                    const path = Memory.readUtf8String(args[0]);
                    this.path = path;
                    
                    // 拦截对敏感文件的检测
                    if (path && (
                        path.indexOf("frida") !== -1 ||
                        path.indexOf("gum") !== -1 ||
                        path.indexOf("magisk") !== -1 ||
                        path.indexOf("su") !== -1
                    )) {
                        logDebug("拦截stat: " + path);
                        Memory.writeUtf8String(args[0], "/dev/null");
                    }
                },
                onLeave: function(retval) {
                    // 如果是敏感文件，返回错误
                    if (this.path && (
                        this.path.indexOf("frida") !== -1 ||
                        this.path.indexOf("gum") !== -1 ||
                        this.path.indexOf("magisk") !== -1 ||
                        this.path.indexOf("su") !== -1
                    )) {
                        retval.replace(-1);
                    }
                }
            });
            
            // 拦截fork系统调用(防止应用派生子进程检测)
            try {
                const forkPtr = Module.getExportByName(null, "fork");
                Interceptor.attach(forkPtr, {
                    onLeave: function(retval) {
                        logDebug("拦截fork调用");
                        retval.replace(-1);
                    }
                });
            } catch (e) {
                logDebug("fork拦截失败: " + e);
            }
            
            // 拦截dlopen (防止加载反调试库)
            try {
                const dlopenPtr = Module.getExportByName(null, "dlopen");
                Interceptor.attach(dlopenPtr, {
                    onEnter: function(args) {
                        const path = Memory.readUtf8String(args[0]);
                        if (path && (
                            path.indexOf("anti") !== -1 ||
                            path.indexOf("debug") !== -1 ||
                            path.indexOf("protect") !== -1 ||
                            path.indexOf("detect") !== -1
                        )) {
                            logWarn("拦截dlopen: " + path);
                            Memory.writeUtf8String(args[0], "/dev/null");
                        }
                    }
                });
            } catch (e) {
                logDebug("dlopen拦截失败: " + e);
            }
            
            logSuccess("Native层拦截设置完成");
        } catch (e) {
            logError("Native层拦截设置失败: " + e);
        }
    }

    // 等待Java环境准备好后执行
    function waitForJava() {
        if (!config.enableJavaHooks) return;
        
        // 尝试执行Java层代码，如果失败则延迟重试
        const tryJava = function(attempt) {
            if (attempt > 20) {
                logError("等待Java环境超时");
                return;
            }
            
            try {
                Java.perform(function() {
                    logInfo("Java环境已准备就绪，开始设置Java层拦截...");
                    setupJavaHooks();
                });
            } catch (e) {
                logDebug("Java环境尚未准备好，等待中... (" + attempt + "/20)");
                setTimeout(function() { tryJava(attempt + 1); }, 200);
            }
        };
        
        tryJava(1);
    }

    // Java层拦截
    function setupJavaHooks() {
        try {
            // 1. 隐藏Frida线程
            const Thread = Java.use("java.lang.Thread");
            Thread.currentThread.implementation = function() {
                const thread = this.currentThread();
                if (thread.getName().indexOf("Frida") >= 0 || 
                    thread.getName().indexOf("frida") >= 0 ||
                    thread.getName().indexOf("gum-js-loop") >= 0) {
                    
                    logDebug("隐藏Frida线程: " + thread.getName());
                    thread.setName("ART-Daemon");
                }
                return thread;
            };
            
            // 2. 禁用调试检测
            const Debug = Java.use("android.os.Debug");
            Debug.isDebuggerConnected.implementation = function() {
                logDebug("调用isDebuggerConnected，返回false");
                return false;
            };
            
            // 3. 隐藏敏感文件
            if (config.hookFilesystem) {
                const File = Java.use("java.io.File");
                File.exists.implementation = function() {
                    const fileName = this.getAbsolutePath();
                    if (fileName.indexOf("frida") !== -1 || 
                        fileName.indexOf("su") !== -1 ||
                        fileName.indexOf("magisk") !== -1) {
                        logDebug("隐藏文件: " + fileName);
                        return false;
                    }
                    return this.exists();
                };
            }
            
            // 4. 拦截系统属性
            if (config.hookSystemProperties) {
                try {
                    const SystemProperties = Java.use("android.os.SystemProperties");
                    SystemProperties.get.overload('java.lang.String').implementation = function(key) {
                        if (key.indexOf("ro.debuggable") !== -1 || 
                            key.indexOf("ro.secure") !== -1) {
                            logDebug("拦截系统属性: " + key);
                            return "0";
                        }
                        return this.get(key);
                    };
                } catch (e) {
                    logDebug("SystemProperties拦截失败: " + e);
                }
            }
            
            // 5. 拦截进程检测
            try {
                const Runtime = Java.use("java.lang.Runtime");
                Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
                    if (cmd.indexOf("ps") !== -1 || 
                        cmd.indexOf("grep") !== -1 || 
                        cmd.indexOf("/proc/") !== -1) {
                        
                        logDebug("拦截命令: " + cmd);
                        cmd = "echo";
                    }
                    return this.exec(cmd);
                };
            } catch (e) {
                logDebug("Runtime.exec拦截失败: " + e);
            }
            
            logSuccess("Java层拦截设置完成");
        } catch (e) {
            logError("Java层拦截设置失败: " + e);
        }
    }

    // 主函数
    function main() {
        logInfo("早期注入脚本启动...");
        
        // 首先设置Native层拦截
        setupNativeHooks();
        
        // 等待Java环境准备好后设置Java层拦截
        waitForJava();
        
        logInfo("早期注入完成，应用将继续启动");
        logInfo("请在另一个终端中注入主脚本");
    }

    // 立即执行
    main();
})(); 