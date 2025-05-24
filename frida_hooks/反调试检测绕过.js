/**
 * 反调试检测绕过脚本
 * 
 * 功能：绕过Android应用中的反调试检测机制
 * 作用：使应用无法检测到调试器或Frida的存在
 * 适用：分析具有反调试保护的应用
 */

// 等待Java虚拟机加载完成
Java.perform(function() {
    console.log("[*] 反调试检测绕过脚本已启动");

    // 全局配置
    var config = {
        // 是否显示详细日志
        verbose: true,
        // 是否打印调用堆栈
        printStack: true,
        // 是否绕过TracerPid检测
        bypassTracerPid: true,
        // 是否绕过调试器连接检测
        bypassDebuggerCheck: true,
        // 是否绕过Frida检测
        bypassFridaCheck: true,
        // 是否绕过模拟器检测
        bypassEmulatorCheck: true
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
     * 一、绕过Debug.isDebuggerConnected检测
     */
    if (config.bypassDebuggerCheck) {
        try {
            var Debug = Java.use('android.os.Debug');
            
            // 绕过isDebuggerConnected
            Debug.isDebuggerConnected.implementation = function() {
                if (config.verbose) {
                    console.log('[+] 拦截 Debug.isDebuggerConnected()');
                    
                    if (config.printStack) {
                        console.log("    调用堆栈:\n    " + getStackTrace());
                    }
                }
                
                // 返回false，表示没有调试器连接
                return false;
            };
            
            // 绕过waitingForDebugger
            if (Debug.waitingForDebugger) {
                Debug.waitingForDebugger.implementation = function() {
                    if (config.verbose) {
                        console.log('[+] 拦截 Debug.waitingForDebugger()');
                        
                        if (config.printStack) {
                            console.log("    调用堆栈:\n    " + getStackTrace());
                        }
                    }
                    
                    // 返回false，表示没有等待调试器
                    return false;
                };
            }
            
            // 绕过isDebuggerConnected (旧版本API)
            var ActivityThread = Java.use('android.app.ActivityThread');
            if (ActivityThread.currentActivityThread) {
                ActivityThread.currentActivityThread.implementation = function() {
                    var thread = this.currentActivityThread();
                    if (thread !== null && thread.mHiddenApiWarningShown) {
                        thread.mHiddenApiWarningShown.value = true;
                    }
                    return thread;
                };
            }
            
            console.log("[+] Debug.isDebuggerConnected绕过设置完成");
        } catch (e) {
            console.log("[-] Debug.isDebuggerConnected绕过设置失败: " + e);
        }
    }

    /**
     * 二、绕过TracerPid检测
     * 许多应用会检查/proc/self/status文件中的TracerPid值来检测调试器
     */
    if (config.bypassTracerPid) {
        try {
            // 方法1：Hook文件读取操作
            var FileInputStream = Java.use("java.io.FileInputStream");
            var BufferedReader = Java.use("java.io.BufferedReader");
            var FileReader = Java.use("java.io.FileReader");
            var String = Java.use("java.lang.String");
            
            // Hook FileInputStream构造函数
            FileInputStream.$init.overload("java.io.File").implementation = function(file) {
                var fileName = file.getAbsolutePath();
                
                if (fileName.indexOf("/proc/self/status") !== -1 || fileName.indexOf("/proc/" + Process.id + "/status") !== -1) {
                    if (config.verbose) {
                        console.log('[+] 拦截对 ' + fileName + ' 的访问');
                        
                        if (config.printStack) {
                            console.log("    调用堆栈:\n    " + getStackTrace());
                        }
                    }
                    
                    // 创建一个临时文件，替换TracerPid值
                    var tempFileName = "/data/local/tmp/fake_status_" + Process.id;
                    var cmd = "cat " + fileName + " | sed 's/TracerPid:\\s*[0-9]*/TracerPid:\\t0/' > " + tempFileName;
                    
                    try {
                        var Runtime = Java.use("java.lang.Runtime");
                        Runtime.getRuntime().exec(cmd).waitFor();
                        
                        // 使用临时文件替代原文件
                        var tempFile = Java.use("java.io.File").$new(tempFileName);
                        return this.$init(tempFile);
                    } catch (e) {
                        console.log("[-] 创建假文件失败: " + e);
                        // 如果失败，使用原始文件
                        return this.$init(file);
                    }
                }
                
                // 对于其他文件，使用原始实现
                return this.$init(file);
            };
            
            // Hook FileInputStream构造函数 (字符串路径版本)
            FileInputStream.$init.overload("java.lang.String").implementation = function(path) {
                if (path.indexOf("/proc/self/status") !== -1 || path.indexOf("/proc/" + Process.id + "/status") !== -1) {
                    if (config.verbose) {
                        console.log('[+] 拦截对 ' + path + ' 的访问');
                        
                        if (config.printStack) {
                            console.log("    调用堆栈:\n    " + getStackTrace());
                        }
                    }
                    
                    // 创建一个临时文件，替换TracerPid值
                    var tempFileName = "/data/local/tmp/fake_status_" + Process.id;
                    var cmd = "cat " + path + " | sed 's/TracerPid:\\s*[0-9]*/TracerPid:\\t0/' > " + tempFileName;
                    
                    try {
                        var Runtime = Java.use("java.lang.Runtime");
                        Runtime.getRuntime().exec(cmd).waitFor();
                        
                        // 使用临时文件替代原文件
                        return this.$init(tempFileName);
                    } catch (e) {
                        console.log("[-] 创建假文件失败: " + e);
                        // 如果失败，使用原始文件
                        return this.$init(path);
                    }
                }
                
                // 对于其他文件，使用原始实现
                return this.$init(path);
            };
            
            // Hook BufferedReader.readLine方法
            BufferedReader.readLine.implementation = function() {
                var line = this.readLine();
                
                if (line !== null && line.indexOf("TracerPid:") !== -1) {
                    if (config.verbose) {
                        console.log('[+] 拦截 TracerPid 行: ' + line);
                        
                        if (config.printStack) {
                            console.log("    调用堆栈:\n    " + getStackTrace());
                        }
                    }
                    
                    // 替换TracerPid值为0
                    line = "TracerPid:\t0";
                }
                
                return line;
            };
            
            console.log("[+] TracerPid检测绕过设置完成");
        } catch (e) {
            console.log("[-] TracerPid检测绕过设置失败: " + e);
        }
    }

    /**
     * 三、绕过常见的反调试检测方法
     */
    try {
        // 绕过System.exit调用
        var System = Java.use("java.lang.System");
        System.exit.implementation = function(status) {
            console.log("[!] 应用尝试调用System.exit(" + status + ")");
            console.log("    调用堆栈:\n    " + getStackTrace());
            console.log("    [已绕过] 阻止应用退出");
            
            // 不执行退出操作
            return;
        };
        
        // 绕过Runtime.exit调用
        var Runtime = Java.use("java.lang.Runtime");
        Runtime.exit.implementation = function(status) {
            console.log("[!] 应用尝试调用Runtime.exit(" + status + ")");
            console.log("    调用堆栈:\n    " + getStackTrace());
            console.log("    [已绕过] 阻止应用退出");
            
            // 不执行退出操作
            return;
        };
        
        // 绕过Process.killProcess调用
        var Process = Java.use("android.os.Process");
        Process.killProcess.implementation = function(pid) {
            console.log("[!] 应用尝试调用Process.killProcess(" + pid + ")");
            console.log("    调用堆栈:\n    " + getStackTrace());
            console.log("    [已绕过] 阻止进程被杀死");
            
            // 不执行杀死进程操作
            return;
        };
        
        console.log("[+] 常见反调试检测方法绕过设置完成");
    } catch (e) {
        console.log("[-] 常见反调试检测方法绕过设置失败: " + e);
    }

    /**
     * 四、绕过Frida检测
     */
    if (config.bypassFridaCheck) {
        try {
            // 方法1：Hook常见的Frida检测函数
            var SystemProperties = Java.use("android.os.SystemProperties");
            if (SystemProperties) {
                SystemProperties.get.overload('java.lang.String').implementation = function(key) {
                    var value = this.get(key);
                    
                    if (key === "ro.debuggable" || key === "service.adb.root") {
                        if (config.verbose) {
                            console.log('[+] 拦截 SystemProperties.get("' + key + '") = ' + value);
                            
                            if (config.printStack) {
                                console.log("    调用堆栈:\n    " + getStackTrace());
                            }
                        }
                        
                        // 返回非调试值
                        return "0";
                    }
                    
                    return value;
                };
            }
            
            // 方法2：Hook文件访问，检查是否在查找Frida相关文件
            var File = Java.use("java.io.File");
            File.exists.implementation = function() {
                var fileName = this.getAbsolutePath();
                
                // 检查是否在查找Frida相关文件
                if (fileName.indexOf("frida") !== -1 || 
                    fileName.indexOf("xposed") !== -1 || 
                    fileName.indexOf("substrate") !== -1) {
                    if (config.verbose) {
                        console.log('[+] 拦截对可疑文件的检查: ' + fileName);
                        
                        if (config.printStack) {
                            console.log("    调用堆栈:\n    " + getStackTrace());
                        }
                    }
                    
                    // 返回false，表示文件不存在
                    return false;
                }
                
                return this.exists();
            };
            
            // 方法3：Hook Runtime.exec，检查是否在执行检测Frida的命令
            Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
                if (cmd.indexOf("ps") !== -1 || 
                    cmd.indexOf("frida") !== -1 || 
                    cmd.indexOf("lsof") !== -1) {
                    if (config.verbose) {
                        console.log('[+] 拦截可疑命令执行: ' + cmd);
                        
                        if (config.printStack) {
                            console.log("    调用堆栈:\n    " + getStackTrace());
                        }
                    }
                    
                    // 执行一个无害的命令作为替代
                    return this.exec("echo");
                }
                
                return this.exec(cmd);
            };
            
            // 方法4：Hook常见的网络端口检测
            var NetworkInterface = Java.use("java.net.NetworkInterface");
            if (NetworkInterface.getNetworkInterfaces) {
                NetworkInterface.getNetworkInterfaces.implementation = function() {
                    var interfaces = this.getNetworkInterfaces();
                    
                    if (config.verbose) {
                        console.log('[+] 拦截 NetworkInterface.getNetworkInterfaces()');
                        
                        if (config.printStack) {
                            console.log("    调用堆栈:\n    " + getStackTrace());
                        }
                    }
                    
                    // 过滤掉Frida使用的网络接口
                    // 这里我们简单返回原始结果，但在实际应用中可能需要过滤特定接口
                    return interfaces;
                };
            }
            
            console.log("[+] Frida检测绕过设置完成");
        } catch (e) {
            console.log("[-] Frida检测绕过设置失败: " + e);
        }
    }

    /**
     * 五、绕过模拟器检测
     */
    if (config.bypassEmulatorCheck) {
        try {
            // 方法1：Hook Build类属性
            var Build = Java.use("android.os.Build");
            
            // 常见的模拟器检测属性
            var buildProps = [
                "FINGERPRINT", "MODEL", "MANUFACTURER", 
                "BRAND", "BOARD", "DEVICE", "PRODUCT", 
                "HARDWARE", "HOST"
            ];
            
            for (var i = 0; i < buildProps.length; i++) {
                var prop = buildProps[i];
                
                if (Build[prop] && Build[prop].value) {
                    var originalValue = Build[prop].value;
                    
                    // 检查是否为模拟器特征
                    if (originalValue.toLowerCase().indexOf("generic") !== -1 || 
                        originalValue.toLowerCase().indexOf("sdk") !== -1 || 
                        originalValue.toLowerCase().indexOf("emulator") !== -1 || 
                        originalValue.toLowerCase().indexOf("genymotion") !== -1) {
                        
                        if (config.verbose) {
                            console.log('[+] 检测到模拟器特征: Build.' + prop + ' = ' + originalValue);
                        }
                        
                        // 替换为真实设备的特征
                        var realValues = {
                            "FINGERPRINT": "google/walleye/walleye:8.1.0/OPM1.171019.011/4448085:user/release-keys",
                            "MODEL": "Pixel 2",
                            "MANUFACTURER": "Google",
                            "BRAND": "google",
                            "BOARD": "walleye",
                            "DEVICE": "walleye",
                            "PRODUCT": "walleye",
                            "HARDWARE": "walleye",
                            "HOST": "wdl-git"
                        };
                        
                        if (realValues[prop]) {
                            Build[prop].value = realValues[prop];
                            console.log('[+] 替换 Build.' + prop + ': ' + originalValue + ' -> ' + realValues[prop]);
                        }
                    }
                }
            }
            
            // 方法2：Hook TelephonyManager
            var TelephonyManager = Java.use("android.telephony.TelephonyManager");
            
            // getDeviceId
            if (TelephonyManager.getDeviceId) {
                TelephonyManager.getDeviceId.overload().implementation = function() {
                    if (config.verbose) {
                        console.log('[+] 拦截 TelephonyManager.getDeviceId()');
                        
                        if (config.printStack) {
                            console.log("    调用堆栈:\n    " + getStackTrace());
                        }
                    }
                    
                    // 返回一个看起来合法的IMEI
                    return "867686022836153";
                };
            }
            
            // getPhoneNumber
            if (TelephonyManager.getLine1Number) {
                TelephonyManager.getLine1Number.overload().implementation = function() {
                    if (config.verbose) {
                        console.log('[+] 拦截 TelephonyManager.getLine1Number()');
                        
                        if (config.printStack) {
                            console.log("    调用堆栈:\n    " + getStackTrace());
                        }
                    }
                    
                    // 返回一个看起来合法的电话号码
                    return "+15555215554";
                };
            }
            
            // getNetworkOperatorName
            if (TelephonyManager.getNetworkOperatorName) {
                TelephonyManager.getNetworkOperatorName.overload().implementation = function() {
                    if (config.verbose) {
                        console.log('[+] 拦截 TelephonyManager.getNetworkOperatorName()');
                        
                        if (config.printStack) {
                            console.log("    调用堆栈:\n    " + getStackTrace());
                        }
                    }
                    
                    // 返回一个真实的运营商名称
                    return "China Mobile";
                };
            }
            
            // getSimOperatorName
            if (TelephonyManager.getSimOperatorName) {
                TelephonyManager.getSimOperatorName.overload().implementation = function() {
                    if (config.verbose) {
                        console.log('[+] 拦截 TelephonyManager.getSimOperatorName()');
                        
                        if (config.printStack) {
                            console.log("    调用堆栈:\n    " + getStackTrace());
                        }
                    }
                    
                    // 返回一个真实的SIM卡运营商名称
                    return "China Mobile";
                };
            }
            
            console.log("[+] 模拟器检测绕过设置完成");
        } catch (e) {
            console.log("[-] 模拟器检测绕过设置失败: " + e);
        }
    }

    /**
     * 六、绕过Native层反调试检测
     */
    try {
        // 拦截ptrace系统调用
        Interceptor.replace(Module.findExportByName(null, "ptrace"), new NativeCallback(function(request, pid, addr, data) {
            if (config.verbose) {
                console.log("[+] 拦截 ptrace 系统调用:");
                console.log("    请求: " + request);
                console.log("    PID: " + pid);
            }
            
            // 返回0表示成功
            return 0;
        }, 'long', ['int', 'int', 'pointer', 'pointer']));
        
        // 拦截kill系统调用
        Interceptor.replace(Module.findExportByName(null, "kill"), new NativeCallback(function(pid, signal) {
            if (config.verbose) {
                console.log("[+] 拦截 kill 系统调用:");
                console.log("    PID: " + pid);
                console.log("    信号: " + signal);
            }
            
            // 如果是向自己发送信号，可能是反调试检测
            if (pid === Process.id) {
                return 0;
            }
            
            // 对于其他进程，使用原始实现
            return kill(pid, signal);
        }, 'int', ['int', 'int']));
        
        // 获取原始的kill函数
        var kill = new NativeFunction(Module.findExportByName(null, "kill"), 'int', ['int', 'int']);
        
        console.log("[+] Native层反调试检测绕过设置完成");
    } catch (e) {
        console.log("[-] Native层反调试检测绕过设置失败: " + e);
    }

    /**
     * 修改配置的函数
     */
    global.setAntiDebugConfig = function(newConfig) {
        for (var key in newConfig) {
            if (config.hasOwnProperty(key)) {
                config[key] = newConfig[key];
                console.log("[+] 反调试配置已更新: " + key + " = " + newConfig[key]);
            }
        }
    };

    console.log("[*] 反调试检测绕过脚本已加载");
    console.log("[*] 使用方法:");
    console.log("    setAntiDebugConfig({key: value}) - 修改配置");
    console.log("    例如: setAntiDebugConfig({verbose: false}) - 关闭详细日志");
}); 