/*
 * 脚本名称：anti_debug.js
 * 功能描述：全面绕过各种反调试、反Root、反模拟器等检测机制，确保Frida可以正常工作
 * 
 * 适用场景：
 *   - 分析具有反调试保护的Android应用
 *   - 绕过应用的Root检测机制
 *   - 绕过应用的模拟器检测
 *   - 绕过应用的Frida/Xposed等注入检测
 *   - 绕过应用的签名校验和完整性校验
 *   - 在有安全保护的应用中使用Frida进行分析
 *
 * 使用方法：
 *   1. 可通过frida_master.js主入口文件加载(推荐)
 *   2. 也可单独使用: frida -U -f 目标应用包名 -l anti_debug.js --no-pause
 *   3. 或者 frida -U --attach-pid 目标进程PID -l anti_debug.js
 *
 * 启动方式说明：
 *   - -U: 使用USB连接的设备
 *   - -f: 指定以spawn方式启动的应用包名
 *   - --attach-pid: 附加到已运行的进程
 *   - --no-pause: 注入后不暂停应用执行
 *
 * 工作原理：
 *   1. Java层防护绕过：
 *      - 挂钩Debug.isDebuggerConnected()等调试检测方法
 *      - 修改ApplicationInfo.flags以隐藏调试标志
 *      - 拦截System.exit()阻止应用强制退出
 *      - 绕过FileSystem中的su等Root路径检测
 *      - 伪装Build信息以绕过模拟器检测
 *
 *   2. Native层防护绕过：
 *      - 拦截ptrace调用以绕过反调试保护
 *      - 修改/proc/maps内容以隐藏Frida痕迹
 *      - 拦截常见的Native层Root检测函数
 *
 *   3. 自动记录所有被绕过的检测点，便于分析应用保护机制
 *
 * 注意事项：
 *   - 本脚本需要配合其他保护绕过脚本(如通杀绕过Frida检测.js)使用效果最佳
 *   - 某些高级保护可能需要额外定制的绕过方法
 *   - 建议在spawn模式下使用，以便尽早拦截所有检测
 *   - 可通过config对象的bypassAllDetection开关控制是否启用绕过功能
 */

module.exports = function(config, logger, utils) {
    var tag = "ANTI";
    logger.info(tag, "反调试绕过模块初始化");
    
    // 如果未开启绕过功能，则直接返回
    if (!config.bypassAllDetection) {
        logger.info(tag, "反调试绕过功能未开启，跳过");
        return;
    }
    
    // 记录被绕过的检测
    var bypassedChecks = {
        count: 0,
        details: {}
    };
    
    function recordBypass(type, detail) {
        bypassedChecks.count++;
        if (!bypassedChecks.details[type]) {
            bypassedChecks.details[type] = [];
        }
        bypassedChecks.details[type].push(detail);
        logger.info(tag, "绕过 " + type + " 检测: " + detail);
    }
    
    // 开始Hook各种反调试检测
    Java.perform(function() {
        // 1. 绕过Java层反调试
        bypassJavaDebugChecks();
        
        // 2. 绕过Root检测
        bypassRootChecks();
        
        // 3. 绕过模拟器检测
        bypassEmulatorChecks();
        
        // 4. 绕过Frida/Xposed检测
        bypassInjectionChecks();
        
        // 5. 绕过SSL Pinning
        bypassSSLPinning();
        
        // 6. 绕过签名校验
        bypassSignatureChecks();
    });
    
    // 绕过Native层检测
    try {
        // 1. 绕过ptrace反调试
        bypassPtrace();
        
        // 2. 绕过/proc/maps检测
        bypassProcMaps();
        
        // 3. 绕过Native层root检测
        bypassNativeRootChecks();
    } catch (e) {
        logger.error(tag, "Native层绕过失败: " + e);
    }
    
    // Java层反调试绕过
    function bypassJavaDebugChecks() {
        try {
            // 1. Debug.isDebuggerConnected()
            var Debug = Java.use("android.os.Debug");
            Debug.isDebuggerConnected.implementation = function() {
                recordBypass("反调试", "Debug.isDebuggerConnected");
                return false;
            };
            
            // 2. ActivityManager.isUserAMonkey()
            try {
                var ActivityManager = Java.use("android.app.ActivityManager");
                ActivityManager.isUserAMonkey.implementation = function() {
                    recordBypass("反调试", "ActivityManager.isUserAMonkey");
                    return false;
                };
            } catch (e) {
                logger.debug(tag, "ActivityManager.isUserAMonkey绕过失败: " + e);
            }
            
            // 3. ApplicationInfo.FLAG_DEBUGGABLE
            try {
                var ApplicationInfo = Java.use("android.content.pm.ApplicationInfo");
                var originalFlags = ApplicationInfo.flags.value;
                
                ApplicationInfo.flags.get = function() {
                    var flags = originalFlags.call(this);
                    var DEBUGGABLE = 0x2; // FLAG_DEBUGGABLE值
                    if ((flags & DEBUGGABLE) != 0) {
                        recordBypass("反调试", "ApplicationInfo.FLAG_DEBUGGABLE");
                        return flags & ~DEBUGGABLE;
                    }
                    return flags;
                };
            } catch (e) {
                logger.debug(tag, "ApplicationInfo.flags绕过失败: " + e);
            }
            
            // 4. Debug.getDebuggerConnectedTimeout
            try {
                Debug.getDebuggerConnectedTimeout.implementation = function() {
                    recordBypass("反调试", "Debug.getDebuggerConnectedTimeout");
                    return 0;
                };
            } catch (e) {
                logger.debug(tag, "Debug.getDebuggerConnectedTimeout绕过失败: " + e);
            }
            
            // 5. System.exit绕过
            var System = Java.use("java.lang.System");
            System.exit.implementation = function(status) {
                recordBypass("反调试", "System.exit(" + status + ")");
                logger.warn(tag, "应用尝试退出，已阻止: System.exit(" + status + ")");
                // 不调用原方法，阻止退出
            };
            
            // 6. Process.killProcess绕过
            try {
                var Process = Java.use("android.os.Process");
                Process.killProcess.implementation = function(pid) {
                    recordBypass("反调试", "Process.killProcess(" + pid + ")");
                    logger.warn(tag, "应用尝试杀进程，已阻止: Process.killProcess(" + pid + ")");
                    // 不调用原方法，阻止杀进程
                };
            } catch (e) {
                logger.debug(tag, "Process.killProcess绕过失败: " + e);
            }
            
            logger.info(tag, "Java层反调试绕过设置完成");
        } catch (e) {
            logger.error(tag, "Java层反调试绕过失败: " + e);
        }
    }
    
    // Root检测绕过
    function bypassRootChecks() {
        try {
            // 1. 常见Root文件检测
            var File = Java.use("java.io.File");
            File.exists.implementation = function() {
                var fileName = this.getAbsolutePath();
                
                // 检查是否为常见的Root相关文件
                var rootFiles = ["/system/bin/su", "/system/xbin/su", "/sbin/su", "/system/app/Superuser.apk", 
                                "/system/app/SuperSU.apk", "/data/local/bin/su", "/data/local/xbin/su", 
                                "/system/sd/xbin/su", "/system/bin/failsafe/su", "/data/local/su"];
                
                for (var i = 0; i < rootFiles.length; i++) {
                    if (fileName === rootFiles[i]) {
                        recordBypass("Root检测", "File.exists: " + fileName);
                        return false;
                    }
                }
                
                // 检查su命令
                if (fileName.indexOf("su") >= 0) {
                    logger.debug(tag, "可能的Root检测: " + fileName);
                }
                
                return this.exists();
            };
            
            // 2. 检查是否可执行su命令
            var Runtime = Java.use("java.lang.Runtime");
            var exec = Runtime.exec.overload('java.lang.String');
            exec.implementation = function(cmd) {
                if (cmd.indexOf("su") !== -1 || cmd.indexOf("which") !== -1 || cmd.indexOf("busybox") !== -1) {
                    recordBypass("Root检测", "Runtime.exec: " + cmd);
                    
                    // 返回一个不会产生结果的安全命令
                    return exec.call(this, "echo");
                }
                return exec.call(this, cmd);
            };
            
            // 3. Shell.exec绕过
            try {
                var Shell = Java.use("java.lang.Shell");
                if (Shell) {
                    Shell.exec.implementation = function(cmd) {
                        if (cmd.indexOf("su") !== -1) {
                            recordBypass("Root检测", "Shell.exec: " + cmd);
                            return null;
                        }
                        return this.exec(cmd);
                    };
                }
            } catch (e) {
                logger.debug(tag, "Shell.exec绕过失败: " + e);
            }
            
            logger.info(tag, "Root检测绕过设置完成");
        } catch (e) {
            logger.error(tag, "Root检测绕过失败: " + e);
        }
    }
    
    // 模拟器检测绕过
    function bypassEmulatorChecks() {
        try {
            // 1. Build属性检测
            var Build = Java.use("android.os.Build");
            
            // 伪装成真实设备的Build信息
            Build.FINGERPRINT.value = "google/walleye/walleye:8.1.0/OPM1.171019.011/4448085:user/release-keys";
            Build.MODEL.value = "Pixel 2";
            Build.MANUFACTURER.value = "Google";
            Build.BRAND.value = "google";
            Build.DEVICE.value = "walleye";
            Build.PRODUCT.value = "walleye";
            Build.HARDWARE.value = "walleye";
            Build.TAGS.value = "release-keys";
            Build.TYPE.value = "user";
            
            recordBypass("模拟器检测", "Build属性伪装");
            
            // 2. 电话相关检测
            try {
                var TelephonyManager = Java.use("android.telephony.TelephonyManager");
                
                // getDeviceId
                TelephonyManager.getDeviceId.overloads.forEach(function(overload) {
                    overload.implementation = function() {
                        recordBypass("模拟器检测", "TelephonyManager.getDeviceId");
                        return "867686022106838"; // 随机真实IMEI
                    };
                });
                
                // getSubscriberId (IMSI)
                TelephonyManager.getSubscriberId.overloads.forEach(function(overload) {
                    overload.implementation = function() {
                        recordBypass("模拟器检测", "TelephonyManager.getSubscriberId");
                        return "460030912121001"; // 随机真实IMSI
                    };
                });
                
                // getPhoneType
                TelephonyManager.getPhoneType.implementation = function() {
                    recordBypass("模拟器检测", "TelephonyManager.getPhoneType");
                    return 1; // PHONE_TYPE_GSM
                };
                
                // getNetworkType
                TelephonyManager.getNetworkType.implementation = function() {
                    recordBypass("模拟器检测", "TelephonyManager.getNetworkType");
                    return 13; // NETWORK_TYPE_LTE
                };
            } catch (e) {
                logger.debug(tag, "TelephonyManager绕过失败: " + e);
            }
            
            // 3. 传感器检测
            try {
                var Sensor = Java.use("android.hardware.Sensor");
                var SensorManager = Java.use("android.hardware.SensorManager");
                
                SensorManager.getSensorList.implementation = function() {
                    var ret = this.getSensorList.apply(this, arguments);
                    recordBypass("模拟器检测", "SensorManager.getSensorList");
                    // 不修改返回值，但记录调用
                    return ret;
                };
            } catch (e) {
                logger.debug(tag, "Sensor绕过失败: " + e);
            }
            
            logger.info(tag, "模拟器检测绕过设置完成");
        } catch (e) {
            logger.error(tag, "模拟器检测绕过失败: " + e);
        }
    }
    
    // Frida/Xposed检测绕过
    function bypassInjectionChecks() {
        try {
            // 1. 字符串检测
            var String = Java.use("java.lang.String");
            
            // contains
            var originalContains = String.contains;
            String.contains.implementation = function(str) {
                var shouldBypass = false;
                var injectionKeywords = ["frida", "xposed", "substrate", "Cydia", "cyrket", "Substrate", "nox", "momo", 
                                       "Magisk", "magisk", "MagiskHide", "magiskhide", "NoxApp", "BlackBox"];
                
                if (str) {
                    var s = str.toString();
                    for (var i = 0; i < injectionKeywords.length; i++) {
                        if (s.indexOf(injectionKeywords[i]) !== -1) {
                            recordBypass("注入检测", "String.contains: " + s);
                            shouldBypass = true;
                            break;
                        }
                    }
                }
                
                if (shouldBypass) return false;
                return originalContains.call(this, str);
            };
            
            // 2. 文件存在检测
            var File = Java.use("java.io.File");
            var originalExists = File.exists;
            File.exists.implementation = function() {
                var fileName = this.getAbsolutePath();
                
                // 检查是否为注入框架相关文件
                var injectionFiles = [
                    "/data/local/tmp/frida-server",
                    "/data/local/tmp/re.frida.server",
                    "/data/local/tmp/frida-gadget.so",
                    "/data/local/tmp/frida-gadget-latest.so",
                    "/sdcard/MagiskManager/",
                    "/sdcard/MagiskManager/magisk.db",
                    "/data/data/de.robv.android.xposed.installer",
                    "/data/data/io.va.exposed",
                    "/data/data/me.weishu.exp"
                ];
                
                for (var i = 0; i < injectionFiles.length; i++) {
                    if (fileName === injectionFiles[i]) {
                        recordBypass("注入检测", "File.exists: " + fileName);
                        return false;
                    }
                }
                
                return originalExists.call(this);
            };
            
            // 3. 阻止读取/proc/self/maps
            var FileInputStream = Java.use("java.io.FileInputStream");
            FileInputStream.$init.overload('java.lang.String').implementation = function(path) {
                if (path === "/proc/self/maps" || path === "/proc/maps") {
                    recordBypass("注入检测", "读取: " + path);
                    throw new Java.use("java.io.FileNotFoundException").$new(path);
                }
                return this.$init(path);
            };
            
            // 4. 阻止读取/proc/self/status
            FileInputStream.$init.overload('java.io.File').implementation = function(file) {
                var path = file.getAbsolutePath();
                if (path === "/proc/self/status" || path.indexOf("proc") >= 0 && path.indexOf("status") >= 0) {
                    recordBypass("注入检测", "读取: " + path);
                    throw new Java.use("java.io.FileNotFoundException").$new(path);
                }
                return this.$init(file);
            };
            
            // 5. 阻止反射调用敏感方法
            try {
                var Method = Java.use("java.lang.reflect.Method");
                Method.invoke.implementation = function(obj, args) {
                    var methodName = this.getName();
                    var className = this.getDeclaringClass().getName();
                    
                    // 检查是否为敏感反射调用
                    if ((className === "android.os.Debug" && methodName === "isDebuggerConnected") ||
                        (className.indexOf("Emulator") >= 0) ||
                        (methodName.indexOf("detect") >= 0 && methodName.indexOf("Debug") >= 0)) {
                        recordBypass("反射检测", className + "." + methodName);
                        
                        // 根据返回类型返回安全值
                        var returnType = this.getReturnType().getName();
                        if (returnType === "boolean") return false;
                        if (returnType === "int") return 0;
                        if (returnType === "java.lang.String") return "";
                        return null;
                    }
                    
                    return this.invoke.apply(this, arguments);
                };
            } catch (e) {
                logger.debug(tag, "Method.invoke绕过失败: " + e);
            }
            
            logger.info(tag, "注入检测绕过设置完成");
        } catch (e) {
            logger.error(tag, "注入检测绕过失败: " + e);
        }
    }
    
    // SSL Pinning绕过
    function bypassSSLPinning() {
        try {
            // 1. 绕过X509TrustManager
            var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
            var SSLContext = Java.use('javax.net.ssl.SSLContext');
            
            // 创建空的TrustManager
            var TrustManager = Java.registerClass({
                name: 'com.bypass.SSLTrustManager',
                implements: [X509TrustManager],
                methods: {
                    checkClientTrusted: function(chain, authType) {},
                    checkServerTrusted: function(chain, authType) {},
                    getAcceptedIssuers: function() { return []; }
                }
            });
            
            // 替换SSLContext的init方法
            SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').implementation = function(keyManager, trustManager, secureRandom) {
                recordBypass("SSL Pinning", "SSLContext.init");
                var trustManagers = [TrustManager.$new()];
                this.init(keyManager, trustManagers, secureRandom);
            };
            
            // 2. 绕过OkHttp证书固定
            try {
                var CertificatePinner = Java.use('okhttp3.CertificatePinner');
                if (CertificatePinner) {
                    CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
                        recordBypass("SSL Pinning", "OkHttp3.CertificatePinner.check: " + hostname);
                        return;
                    };
                    
                    CertificatePinner.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function(hostname, peerCertificates) {
                        recordBypass("SSL Pinning", "OkHttp3.CertificatePinner.check: " + hostname);
                        return;
                    };
                }
            } catch (e) {
                logger.debug(tag, "OkHttp CertificatePinner绕过失败: " + e);
            }
            
            // 3. 绕过TrustManagerImpl
            try {
                var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
                if (TrustManagerImpl) {
                    TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
                        recordBypass("SSL Pinning", "TrustManagerImpl.verifyChain: " + host);
                        return untrustedChain;
                    };
                }
            } catch (e) {
                logger.debug(tag, "TrustManagerImpl绕过失败: " + e);
            }
            
            logger.info(tag, "SSL Pinning绕过设置完成");
        } catch (e) {
            logger.error(tag, "SSL Pinning绕过失败: " + e);
        }
    }
    
    // 签名校验绕过
    function bypassSignatureChecks() {
        try {
            // 1. 绕过PackageManager.getPackageInfo签名校验
            var PackageManager = Java.use("android.content.pm.PackageManager");
            var Signature = Java.use("android.content.pm.Signature");
            
            PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function(packageName, flags) {
                var packageInfo = this.getPackageInfo(packageName, flags);
                
                // 检查是否在获取签名
                if ((flags & 0x40) !== 0) { // GET_SIGNATURES = 0x40
                    recordBypass("签名校验", "PackageManager.getPackageInfo: " + packageName);
                    
                    // 不修改返回值，仅记录调用
                    logger.debug(tag, "应用正在获取签名: " + packageName);
                }
                
                return packageInfo;
            };
            
            // 2. 绕过签名比较
            Signature.equals.implementation = function(other) {
                var result = this.equals(other);
                if (!result) {
                    recordBypass("签名校验", "Signature.equals");
                    logger.debug(tag, "签名不匹配，已绕过");
                    return true;
                }
                return result;
            };
            
            logger.info(tag, "签名校验绕过设置完成");
        } catch (e) {
            logger.error(tag, "签名校验绕过失败: " + e);
        }
    }
    
    // Native层ptrace反调试绕过
    function bypassPtrace() {
        try {
            Interceptor.replace(Module.findExportByName(null, "ptrace"), new NativeCallback(function(request, pid, addr, data) {
                if (request == 31) { // PTRACE_ATTACH
                    recordBypass("Native反调试", "ptrace(PTRACE_ATTACH)");
                    return -1;
                }
                
                // 调用原始函数
                return ptrace(request, pid, addr, data);
            }, 'long', ['int', 'int', 'pointer', 'pointer']));
            
            logger.info(tag, "ptrace反调试绕过设置完成");
        } catch (e) {
            logger.error(tag, "ptrace反调试绕过失败: " + e);
        }
    }
    
    // 绕过/proc/maps检测
    function bypassProcMaps() {
        try {
            Interceptor.attach(Module.findExportByName(null, "fopen"), {
                onEnter: function(args) {
                    var path = args[0].readUtf8String();
                    if (path !== null && (path.indexOf("/proc/self/maps") >= 0 || path.indexOf("/proc/maps") >= 0)) {
                        recordBypass("Native注入检测", "fopen: " + path);
                        args[0] = Memory.allocUtf8String("/dev/null");
                    }
                }
            });
            
            logger.info(tag, "/proc/maps检测绕过设置完成");
        } catch (e) {
            logger.error(tag, "/proc/maps检测绕过失败: " + e);
        }
    }
    
    // Native层Root检测绕过
    function bypassNativeRootChecks() {
        try {
            Interceptor.attach(Module.findExportByName(null, "fopen"), {
                onEnter: function(args) {
                    var path = args[0].readUtf8String();
                    
                    // 检查常见的Root文件
                    if (path !== null && (
                        path.indexOf("su") >= 0 || 
                        path.indexOf("magisk") >= 0 || 
                        path.indexOf("supersu") >= 0)) {
                        
                        recordBypass("Native Root检测", "fopen: " + path);
                        args[0] = Memory.allocUtf8String("/dev/null");
                    }
                }
            });
            
            // 拦截stat/access等系统调用
            var statFuncs = ["stat", "stat64", "lstat", "lstat64", "access"];
            statFuncs.forEach(function(func) {
                var funcPtr = Module.findExportByName(null, func);
                if (funcPtr) {
                    Interceptor.attach(funcPtr, {
                        onEnter: function(args) {
                            var path = args[0].readUtf8String();
                            if (path !== null && (
                                path.indexOf("su") >= 0 || 
                                path.indexOf("magisk") >= 0 || 
                                path.indexOf("supersu") >= 0)) {
                                
                                recordBypass("Native Root检测", func + ": " + path);
                                args[0] = Memory.allocUtf8String("/dev/null");
                            }
                        }
                    });
                }
            });
            
            logger.info(tag, "Native层Root检测绕过设置完成");
        } catch (e) {
            logger.error(tag, "Native层Root检测绕过失败: " + e);
        }
    }
    
    logger.info(tag, "反调试绕过模块加载完成");
    return {
        bypassedChecks: bypassedChecks
    };
}; 