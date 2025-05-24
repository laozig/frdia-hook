/**
 * Root检测绕过脚本
 * 
 * 功能：绕过Android应用中的Root检测机制
 * 作用：使应用无法检测到设备已被Root，从而正常运行
 * 适用：分析拒绝在Root设备上运行的应用
 */

// 等待Java虚拟机加载完成
Java.perform(function() {
    console.log("[*] Root检测绕过脚本已启动");

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
     * 一、拦截常见Root检测文件路径检查
     */
    var File = Java.use("java.io.File");
    
    // 拦截构造函数
    File.$init.overload("java.lang.String").implementation = function(path) {
        // 常见的Root相关路径
        var rootPaths = [
            "/system/app/Superuser.apk",
            "/system/xbin/su",
            "/system/xbin/daemonsu",
            "/system/bin/su",
            "/system/bin/failsafe/su",
            "/system/sd/xbin/su",
            "/system/usr/we-need-root/su",
            "/sbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/data/local/su",
            "/su/bin/su",
            "/su/bin",
            "/su",
            "/data/app/com.topjohnwu.magisk",
            "/data/app/eu.chainfire.supersu",
            "/data/app/com.noshufou.android.su",
            "/data/app/com.koushikdutta.superuser"
        ];
        
        // 检查是否为Root相关路径
        for (var i = 0; i < rootPaths.length; i++) {
            if (path === rootPaths[i]) {
                console.log("\n[+] 检测到Root文件路径检查: " + path);
                console.log("    调用堆栈:\n    " + getStackTrace());
                console.log("    [已绕过] 返回假路径");
                
                // 返回一个不存在的路径
                return this.$init("/not_exist_root_path");
            }
        }
        
        return this.$init(path);
    };
    
    // 拦截exists方法
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        
        // 常见的Root相关路径
        var rootPaths = [
            "/system/app/Superuser.apk",
            "/system/xbin/su",
            "/system/xbin/daemonsu",
            "/system/bin/su",
            "/system/bin/failsafe/su",
            "/system/sd/xbin/su",
            "/system/usr/we-need-root/su",
            "/sbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/data/local/su",
            "/su/bin/su",
            "/su/bin",
            "/su",
            "/data/app/com.topjohnwu.magisk",
            "/data/app/eu.chainfire.supersu",
            "/data/app/com.noshufou.android.su",
            "/data/app/com.koushikdutta.superuser"
        ];
        
        // 检查是否为Root相关路径
        for (var i = 0; i < rootPaths.length; i++) {
            if (path.indexOf(rootPaths[i]) !== -1) {
                console.log("\n[+] 检测到Root文件存在检查: " + path);
                console.log("    调用堆栈:\n    " + getStackTrace());
                console.log("    [已绕过] 返回false");
                
                return false;
            }
        }
        
        return this.exists();
    };

    /**
     * 二、拦截Runtime.exec执行命令
     * 通常用于执行"su"或"which su"等命令检测Root
     */
    var Runtime = Java.use("java.lang.Runtime");
    
    // 拦截exec方法
    Runtime.exec.overload("java.lang.String").implementation = function(cmd) {
        if (cmd.indexOf("su") !== -1 || cmd.indexOf("busybox") !== -1 || cmd.indexOf("magisk") !== -1) {
            console.log("\n[+] 检测到Root命令执行: " + cmd);
            console.log("    调用堆栈:\n    " + getStackTrace());
            console.log("    [已绕过] 执行替代命令");
            
            // 执行一个无害的命令作为替代
            return this.exec("echo not_rooted");
        }
        
        return this.exec(cmd);
    };
    
    Runtime.exec.overload("[Ljava.lang.String;").implementation = function(cmdArray) {
        if (cmdArray.length > 0 && (cmdArray[0].indexOf("su") !== -1 || cmdArray[0].indexOf("busybox") !== -1 || cmdArray[0].indexOf("magisk") !== -1)) {
            console.log("\n[+] 检测到Root命令执行(数组): " + JSON.stringify(cmdArray));
            console.log("    调用堆栈:\n    " + getStackTrace());
            console.log("    [已绕过] 执行替代命令");
            
            // 执行一个无害的命令作为替代
            var altCmd = ["echo", "not_rooted"];
            return this.exec(altCmd);
        }
        
        return this.exec(cmdArray);
    };

    /**
     * 三、拦截常见Root检测库
     */
    
    // 1. RootBeer库检测
    try {
        var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
        
        // 拦截isRooted方法
        RootBeer.isRooted.implementation = function() {
            console.log("\n[+] 检测到RootBeer.isRooted()");
            console.log("    调用堆栈:\n    " + getStackTrace());
            console.log("    [已绕过] 返回false");
            
            return false;
        };
        
        // 拦截isRootedWithoutBusyBoxCheck方法
        RootBeer.isRootedWithoutBusyBoxCheck.implementation = function() {
            console.log("\n[+] 检测到RootBeer.isRootedWithoutBusyBoxCheck()");
            console.log("    调用堆栈:\n    " + getStackTrace());
            console.log("    [已绕过] 返回false");
            
            return false;
        };
        
        // 拦截detectRootManagementApps方法
        RootBeer.detectRootManagementApps.implementation = function() {
            console.log("\n[+] 检测到RootBeer.detectRootManagementApps()");
            console.log("    调用堆栈:\n    " + getStackTrace());
            console.log("    [已绕过] 返回false");
            
            return false;
        };
        
        // 拦截detectPotentiallyDangerousApps方法
        RootBeer.detectPotentiallyDangerousApps.implementation = function() {
            console.log("\n[+] 检测到RootBeer.detectPotentiallyDangerousApps()");
            console.log("    调用堆栈:\n    " + getStackTrace());
            console.log("    [已绕过] 返回false");
            
            return false;
        };
        
        // 拦截detectTestKeys方法
        RootBeer.detectTestKeys.implementation = function() {
            console.log("\n[+] 检测到RootBeer.detectTestKeys()");
            console.log("    调用堆栈:\n    " + getStackTrace());
            console.log("    [已绕过] 返回false");
            
            return false;
        };
        
        // 拦截checkForBusyBoxBinary方法
        RootBeer.checkForBusyBoxBinary.implementation = function() {
            console.log("\n[+] 检测到RootBeer.checkForBusyBoxBinary()");
            console.log("    调用堆栈:\n    " + getStackTrace());
            console.log("    [已绕过] 返回false");
            
            return false;
        };
        
        // 拦截checkForSuBinary方法
        RootBeer.checkForSuBinary.implementation = function() {
            console.log("\n[+] 检测到RootBeer.checkForSuBinary()");
            console.log("    调用堆栈:\n    " + getStackTrace());
            console.log("    [已绕过] 返回false");
            
            return false;
        };
        
        // 拦截checkSuExists方法
        RootBeer.checkSuExists.implementation = function() {
            console.log("\n[+] 检测到RootBeer.checkSuExists()");
            console.log("    调用堆栈:\n    " + getStackTrace());
            console.log("    [已绕过] 返回false");
            
            return false;
        };
        
        console.log("[+] RootBeer库检测绕过设置完成");
    } catch (e) {
        console.log("[-] RootBeer库可能未被使用: " + e);
    }
    
    // 2. RootChecker库检测
    try {
        var RootChecker = Java.use("com.jaredrummler.android.device.DeviceSoftware");
        
        // 拦截isRooted方法
        RootChecker.isRooted.implementation = function() {
            console.log("\n[+] 检测到RootChecker.isRooted()");
            console.log("    调用堆栈:\n    " + getStackTrace());
            console.log("    [已绕过] 返回false");
            
            return false;
        };
        
        console.log("[+] RootChecker库检测绕过设置完成");
    } catch (e) {
        console.log("[-] RootChecker库可能未被使用: " + e);
    }

    /**
     * 四、拦截系统属性检查
     * 某些应用会检查ro.build.tags是否为"test-keys"
     */
    try {
        var SystemProperties = Java.use("android.os.SystemProperties");
        
        // 拦截get方法
        SystemProperties.get.overload("java.lang.String").implementation = function(key) {
            var value = this.get(key);
            
            if (key === "ro.build.tags" && value === "test-keys") {
                console.log("\n[+] 检测到系统属性检查: " + key + " = " + value);
                console.log("    调用堆栈:\n    " + getStackTrace());
                console.log("    [已绕过] 返回release-keys");
                
                return "release-keys";
            }
            
            if (key === "ro.debuggable" && value === "1") {
                console.log("\n[+] 检测到系统属性检查: " + key + " = " + value);
                console.log("    调用堆栈:\n    " + getStackTrace());
                console.log("    [已绕过] 返回0");
                
                return "0";
            }
            
            if (key === "ro.secure" && value === "0") {
                console.log("\n[+] 检测到系统属性检查: " + key + " = " + value);
                console.log("    调用堆栈:\n    " + getStackTrace());
                console.log("    [已绕过] 返回1");
                
                return "1";
            }
            
            return value;
        };
        
        console.log("[+] 系统属性检查绕过设置完成");
    } catch (e) {
        console.log("[-] 系统属性检查绕过设置失败: " + e);
    }

    /**
     * 五、拦截Build类检查
     * 检查Build.TAGS是否为"test-keys"
     */
    var Build = Java.use("android.os.Build");
    var BuildTAGS = Build.TAGS.value;
    
    if (BuildTAGS.indexOf("test-keys") !== -1) {
        console.log("\n[+] 检测到Build.TAGS = " + BuildTAGS);
        console.log("    [已绕过] 修改为release-keys");
        
        Build.TAGS.value = "release-keys";
    }

    /**
     * 六、拦截Shell命令执行
     */
    try {
        var ProcessBuilder = Java.use("java.lang.ProcessBuilder");
        
        // 拦截构造函数
        ProcessBuilder.$init.overload("[Ljava.lang.String;").implementation = function(cmdArray) {
            if (cmdArray.length > 0 && (cmdArray[0].indexOf("su") !== -1 || cmdArray[0].indexOf("busybox") !== -1 || cmdArray[0].indexOf("magisk") !== -1)) {
                console.log("\n[+] 检测到ProcessBuilder执行Root命令: " + JSON.stringify(cmdArray));
                console.log("    调用堆栈:\n    " + getStackTrace());
                console.log("    [已绕过] 修改为无害命令");
                
                // 修改为无害命令
                cmdArray[0] = "echo";
                if (cmdArray.length === 1) {
                    var newCmdArray = ["echo", "not_rooted"];
                    return this.$init(newCmdArray);
                }
            }
            
            return this.$init(cmdArray);
        };
        
        // 拦截start方法
        ProcessBuilder.start.implementation = function() {
            var cmd = this.command.value.toString();
            
            if (cmd.indexOf("su") !== -1 || cmd.indexOf("busybox") !== -1 || cmd.indexOf("magisk") !== -1) {
                console.log("\n[+] 检测到ProcessBuilder.start()执行Root命令: " + cmd);
                console.log("    调用堆栈:\n    " + getStackTrace());
                console.log("    [已绕过] 修改为无害命令");
                
                // 修改为无害命令
                var echo = Java.use("java.util.ArrayList").$new();
                echo.add("echo");
                echo.add("not_rooted");
                this.command.value = echo;
            }
            
            return this.start();
        };
        
        console.log("[+] ProcessBuilder检测绕过设置完成");
    } catch (e) {
        console.log("[-] ProcessBuilder检测绕过设置失败: " + e);
    }

    /**
     * 七、拦截Native库中的Root检测
     * 这需要使用Frida的Interceptor功能
     */
    try {
        // 尝试查找常见的Native库中的Root检测函数
        var nativeRootCheckFuncs = [
            "isDeviceRooted",
            "checkRoot",
            "detectRootStatus",
            "jniCheckRoot",
            "nativeCheckRoot"
        ];
        
        // 获取所有加载的模块
        var modules = Process.enumerateModules();
        
        for (var i = 0; i < modules.length; i++) {
            var module = modules[i];
            
            // 跳过系统库
            if (module.name.indexOf("libc.so") !== -1 || 
                module.name.indexOf("libdvm.so") !== -1 || 
                module.name.indexOf("libart.so") !== -1) {
                continue;
            }
            
            // 枚举模块中的导出函数
            var exports = module.enumerateExports();
            
            for (var j = 0; j < exports.length; j++) {
                var exp = exports[j];
                
                // 检查是否为Root检测相关函数
                for (var k = 0; k < nativeRootCheckFuncs.length; k++) {
                    if (exp.name.indexOf(nativeRootCheckFuncs[k]) !== -1) {
                        console.log("\n[+] 检测到Native Root检测函数: " + exp.name + " 在 " + module.name);
                        
                        // 拦截该函数
                        Interceptor.attach(exp.address, {
                            onEnter: function(args) {
                                console.log("    调用Native Root检测函数");
                                console.log("    [已拦截]");
                            },
                            onLeave: function(retval) {
                                console.log("    原始返回值: " + retval);
                                console.log("    [已绕过] 修改返回值为0");
                                
                                // 修改返回值为0，表示未Root
                                retval.replace(0);
                                return retval;
                            }
                        });
                        
                        console.log("    [已Hook] " + exp.name);
                    }
                }
            }
        }
        
        console.log("[+] Native Root检测绕过设置完成");
    } catch (e) {
        console.log("[-] Native Root检测绕过设置失败: " + e);
    }

    console.log("[*] Root检测绕过设置完成");
}); 