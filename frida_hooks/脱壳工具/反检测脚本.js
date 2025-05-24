/**
 * Frida反检测脚本
 * 
 * 功能：绕过应用中的Frida检测和反调试保护
 * 作用：使Frida能够成功注入被保护的应用
 * 适用：各类具有反调试、反注入、反Frida检测的应用
 * 
 * 使用方法：
 * 1. 先注入此脚本：frida -U -f 目标应用包名 -l 反检测脚本.js --no-pause
 * 2. 然后在另一个终端注入主脚本：frida -U -p 进程PID -l 通用脱壳工具.js
 */

(function() {
    // 配置选项
    const config = {
        // 是否绕过Frida检测
        bypassFridaDetection: true,
        // 是否绕过反调试检测
        bypassAntiDebug: true,
        // 是否绕过文件系统检测
        bypassFilesystemChecks: true,
        // 是否绕过进程名称检测
        bypassProcessNameChecks: true,
        // 是否绕过Native库检测
        bypassNativeHooks: true,
        // 是否绕过SSL固定
        bypassSSLPinning: true,
        // 是否打印详细日志
        verbose: true
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

    // 绕过Frida检测
    function bypassFridaDetection() {
        if (!config.bypassFridaDetection) return;

        logInfo("开始绕过Frida检测...");

        try {
            // 1. 隐藏Frida相关的线程名称
            const ThreadGroup = Java.use("java.lang.ThreadGroup");
            const Thread = Java.use("java.lang.Thread");
            const StackTraceElement = Java.use("java.lang.StackTraceElement");

            // 隐藏线程名
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

            // 隐藏堆栈信息
            Thread.getStackTrace.implementation = function() {
                const stackTraces = this.getStackTrace();
                const filteredTraces = [];
                
                for (let i = 0; i < stackTraces.length; i++) {
                    const trace = stackTraces[i];
                    const className = trace.getClassName();
                    const methodName = trace.getMethodName();
                    
                    if (className.indexOf("frida") === -1 && 
                        className.indexOf("gum") === -1 && 
                        methodName.indexOf("frida") === -1 && 
                        methodName.indexOf("gum") === -1) {
                        filteredTraces.push(trace);
                    }
                }
                
                return filteredTraces;
            };

            // 2. 修改/proc/self/maps和/proc/self/status文件读取
            const BufferedReader = Java.use("java.io.BufferedReader");
            const FileReader = Java.use("java.io.FileReader");
            const String = Java.use("java.lang.String");
            const StringBuilder = Java.use("java.lang.StringBuilder");
            
            BufferedReader.readLine.implementation = function() {
                const line = this.readLine();
                
                if (line === null) {
                    return null;
                }
                
                const lineStr = line.toString();
                
                // 过滤/proc/maps或/proc/status中的Frida相关字符串
                if (lineStr.indexOf("frida") !== -1 || 
                    lineStr.indexOf("gum") !== -1 || 
                    lineStr.indexOf("linjector") !== -1) {
                    
                    logDebug("隐藏敏感行: " + lineStr);
                    return this.readLine(); // 跳过这一行
                }
                
                return line;
            };

            // 3. 绕过常见的Frida检测方法
            try {
                // 修改常见的检测函数
                const SystemProperties = Java.use("android.os.SystemProperties");
                if (SystemProperties) {
                    SystemProperties.get.overload('java.lang.String').implementation = function(key) {
                        if (key.indexOf("ro.debuggable") !== -1 || 
                            key.indexOf("ro.secure") !== -1) {
                            return "0";
                        }
                        return this.get(key);
                    };
                }
            } catch (e) {
                logDebug("SystemProperties不可用: " + e);
            }

            logSuccess("Frida检测绕过设置完成");
        } catch (e) {
            logError("Frida检测绕过失败: " + e);
        }
    }

    // 绕过反调试检测
    function bypassAntiDebug() {
        if (!config.bypassAntiDebug) return;

        logInfo("开始绕过反调试检测...");

        try {
            // 1. 替换Debug.isDebuggerConnected
            const Debug = Java.use("android.os.Debug");
            Debug.isDebuggerConnected.implementation = function() {
                logDebug("调用了isDebuggerConnected，返回false");
                return false;
            };

            // 2. 替换Debug.waitingForDebugger
            Debug.waitingForDebugger.implementation = function() {
                logDebug("调用了waitingForDebugger，返回false");
                return false;
            };

            // 3. 替换Debug.getDebuggerRequestedFlags
            if (Debug.getDebuggerRequestedFlags) {
                Debug.getDebuggerRequestedFlags.implementation = function() {
                    logDebug("调用了getDebuggerRequestedFlags，返回0");
                    return 0;
                };
            }

            // 4. 替换ApplicationInfo.flags检测
            const ApplicationInfo = Java.use("android.content.pm.ApplicationInfo");
            const FLAG_DEBUGGABLE = 0x2;
            
            if (ApplicationInfo.flags) {
                Object.defineProperty(ApplicationInfo.prototype, "flags", {
                    get: function() {
                        const flags = this.flags.value;
                        return flags & ~FLAG_DEBUGGABLE; // 移除DEBUGGABLE标志
                    },
                    set: function(value) {
                        this.flags.value = value;
                    }
                });
            }

            // 5. 替换常见的Native层检测
            try {
                const Runtime = Java.use("java.lang.Runtime");
                const ProcessBuilder = Java.use("java.lang.ProcessBuilder");

                // Hook exec方法，过滤掉检测调试的命令
                Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
                    if (cmd.indexOf("ps") !== -1 || 
                        cmd.indexOf("kill") !== -1 || 
                        cmd.indexOf("grep") !== -1 || 
                        cmd.indexOf("/proc/") !== -1) {
                        
                        logDebug("拦截可疑命令: " + cmd);
                        cmd = "echo";
                    }
                    return this.exec(cmd);
                };

                // Hook ProcessBuilder
                ProcessBuilder.start.implementation = function() {
                    const cmdList = this.command.value;
                    if (cmdList && cmdList.size() > 0) {
                        const firstCmd = cmdList.get(0).toString();
                        
                        if (firstCmd.indexOf("ps") !== -1 || 
                            firstCmd.indexOf("kill") !== -1 || 
                            firstCmd.indexOf("grep") !== -1 || 
                            firstCmd.indexOf("/proc/") !== -1) {
                            
                            logDebug("拦截可疑ProcessBuilder命令: " + cmdList);
                            cmdList.clear();
                            cmdList.add("echo");
                        }
                    }
                    return this.start();
                };
            } catch (e) {
                logDebug("Runtime/ProcessBuilder拦截失败: " + e);
            }

            logSuccess("反调试检测绕过设置完成");
        } catch (e) {
            logError("反调试检测绕过失败: " + e);
        }
    }

    // 绕过文件系统检测
    function bypassFilesystemChecks() {
        if (!config.bypassFilesystemChecks) return;

        logInfo("开始绕过文件系统检测...");

        try {
            // 1. 隐藏敏感文件
            const File = Java.use("java.io.File");
            
            File.exists.implementation = function() {
                const fileName = this.getAbsolutePath();
                
                // 隐藏Frida相关文件
                if (fileName.indexOf("frida") !== -1 || 
                    fileName.indexOf("re.frida.server") !== -1 || 
                    fileName.indexOf("frida-agent") !== -1 || 
                    fileName.indexOf("linjector") !== -1 ||
                    fileName.indexOf("magisk") !== -1 ||
                    fileName.indexOf("su") !== -1) {
                    
                    logDebug("隐藏文件: " + fileName);
                    return false;
                }
                
                return this.exists();
            };
            
            // 2. 隐藏目录列表中的敏感文件
            File.listFiles.implementation = function() {
                const files = this.listFiles();
                
                if (files === null || files.length === 0) {
                    return files;
                }
                
                const filteredFiles = [];
                for (let i = 0; i < files.length; i++) {
                    const file = files[i];
                    const fileName = file.getName();
                    
                    if (fileName.indexOf("frida") === -1 && 
                        fileName.indexOf("gum") === -1 && 
                        fileName.indexOf("magisk") === -1 && 
                        fileName.indexOf("su") === -1) {
                        
                        filteredFiles.push(file);
                    } else {
                        logDebug("从列表中隐藏文件: " + fileName);
                    }
                }
                
                return Java.array('java.io.File', filteredFiles);
            };

            logSuccess("文件系统检测绕过设置完成");
        } catch (e) {
            logError("文件系统检测绕过失败: " + e);
        }
    }

    // 绕过进程名称检测
    function bypassProcessNameChecks() {
        if (!config.bypassProcessNameChecks) return;

        logInfo("开始绕过进程名称检测...");

        try {
            // 1. 修改ActivityThread.currentProcessName
            const ActivityThread = Java.use("android.app.ActivityThread");
            
            if (ActivityThread.currentProcessName) {
                ActivityThread.currentProcessName.implementation = function() {
                    const processName = this.currentProcessName();
                    
                    if (processName !== null && processName.indexOf(":frida") !== -1) {
                        logDebug("隐藏进程名中的frida: " + processName);
                        return processName.replace(":frida", "");
                    }
                    
                    return processName;
                };
            }

            // 2. 修改/proc/self/cmdline读取
            try {
                const FileInputStream = Java.use("java.io.FileInputStream");
                const BufferedReader = Java.use("java.io.BufferedReader");
                const InputStreamReader = Java.use("java.io.InputStreamReader");
                
                FileInputStream.$init.overload("java.lang.String").implementation = function(path) {
                    if (path === "/proc/self/cmdline" || path.indexOf("/proc/") !== -1) {
                        logDebug("访问: " + path);
                    }
                    return this.$init(path);
                };
            } catch (e) {
                logDebug("FileInputStream拦截失败: " + e);
            }

            logSuccess("进程名称检测绕过设置完成");
        } catch (e) {
            logError("进程名称检测绕过失败: " + e);
        }
    }

    // 绕过Native库检测
    function bypassNativeHooks() {
        if (!config.bypassNativeHooks) return;

        logInfo("开始绕过Native库检测...");

        try {
            // 1. 隐藏加载的库
            const System = Java.use("java.lang.System");
            
            System.load.implementation = function(library) {
                logDebug("加载库: " + library);
                return this.load(library);
            };
            
            System.loadLibrary.implementation = function(library) {
                logDebug("加载库: " + library);
                return this.loadLibrary(library);
            };

            // 2. 尝试拦截常见的Native检测
            try {
                const libc = Process.getModuleByName("libc.so");
                const openPtr = Module.getExportByName("libc.so", "open");
                const readPtr = Module.getExportByName("libc.so", "read");
                const mmapPtr = Module.getExportByName("libc.so", "mmap");
                
                // 拦截open调用
                Interceptor.attach(openPtr, {
                    onEnter: function(args) {
                        const path = Memory.readUtf8String(args[0]);
                        if (path && (path.indexOf("/proc/") !== -1 || 
                                     path.indexOf("/system/") !== -1 || 
                                     path.indexOf("/dev/") !== -1)) {
                            this.shouldLog = true;
                            this.path = path;
                        }
                    },
                    onLeave: function(retval) {
                        if (this.shouldLog && this.path) {
                            if (this.path.indexOf("/proc/maps") !== -1 || 
                                this.path.indexOf("/proc/self/maps") !== -1 ||
                                this.path.indexOf("/proc/self/status") !== -1) {
                                logDebug("拦截到open: " + this.path);
                            }
                        }
                    }
                });
                
                logDebug("Native层拦截设置完成");
            } catch (e) {
                logDebug("Native层拦截失败: " + e);
            }

            logSuccess("Native库检测绕过设置完成");
        } catch (e) {
            logError("Native库检测绕过失败: " + e);
        }
    }

    // 绕过SSL证书固定
    function bypassSSLPinning() {
        if (!config.bypassSSLPinning) return;

        logInfo("开始绕过SSL证书固定...");

        try {
            // 1. 绕过X509TrustManager
            const X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
            const SSLContext = Java.use("javax.net.ssl.SSLContext");
            
            // 创建空的TrustManager
            const TrustManager = Java.registerClass({
                name: "com.frida.TrustManager",
                implements: [X509TrustManager],
                methods: {
                    checkClientTrusted: function(chain, authType) {},
                    checkServerTrusted: function(chain, authType) {},
                    getAcceptedIssuers: function() {
                        return [];
                    }
                }
            });
            
            // 替换默认的SSLContext
            const TrustManagers = [TrustManager.$new()];
            const SSLContextInit = SSLContext.init.overload(
                "[Ljavax.net.ssl.KeyManager;", 
                "[Ljavax.net.ssl.TrustManager;", 
                "java.security.SecureRandom"
            );
            
            SSLContextInit.implementation = function(keyManager, trustManager, secureRandom) {
                logDebug("替换SSLContext的TrustManager");
                SSLContextInit.call(this, keyManager, TrustManagers, secureRandom);
            };
            
            // 2. 绕过HostnameVerifier
            const HostnameVerifier = Java.use("javax.net.ssl.HostnameVerifier");
            const AllowAllHostnameVerifier = Java.registerClass({
                name: "com.frida.AllowAllHostnameVerifier",
                implements: [HostnameVerifier],
                methods: {
                    verify: function(hostname, session) {
                        logDebug("绕过主机名验证: " + hostname);
                        return true;
                    }
                }
            });
            
            const HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
            HttpsURLConnection.setDefaultHostnameVerifier.implementation = function(hostnameVerifier) {
                logDebug("替换默认HostnameVerifier");
                return this.setDefaultHostnameVerifier(AllowAllHostnameVerifier.$new());
            };
            
            HttpsURLConnection.setHostnameVerifier.implementation = function(hostnameVerifier) {
                logDebug("替换HostnameVerifier");
                return this.setHostnameVerifier(AllowAllHostnameVerifier.$new());
            };

            logSuccess("SSL证书固定绕过设置完成");
        } catch (e) {
            logError("SSL证书固定绕过失败: " + e);
        }
    }

    // 主函数
    function main() {
        Java.perform(function() {
            try {
                logInfo("开始设置反检测保护...");
                
                bypassFridaDetection();
                bypassAntiDebug();
                bypassFilesystemChecks();
                bypassProcessNameChecks();
                bypassNativeHooks();
                bypassSSLPinning();
                
                logSuccess("反检测脚本初始化完成");
                logInfo("请在另一个终端注入主脚本");
                
            } catch (e) {
                logError("初始化失败: " + e);
            }
        });
    }

    // 启动
    setTimeout(main, 0);
})(); 