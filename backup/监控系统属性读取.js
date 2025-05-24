/*
 * 脚本名称：监控系统属性读取.js
 * 功能：全面监控Android应用中的系统属性读取操作，包括Java和Native层API
 * 适用场景：
 *   - 分析应用如何获取设备信息
 *   - 检测反调试和反模拟器逻辑
 *   - 发现环境检测行为
 *   - 逆向分析设备指纹构建
 * 使用方法：
 *   1. frida -U -f 包名 -l 监控系统属性读取.js --no-pause
 *   2. 查看控制台输出，分析系统属性读取行为
 * 启动方式说明：
 *   - -U 代表使用USB连接的设备
 *   - -f 代表以spawn方式启动目标应用
 *   - --no-pause 指示Frida不要暂停应用执行
 * 支持特性：
 *   - 监控Native层__system_property_get
 *   - 监控Java层System.getProperty和System.getProperties
 *   - 监控Android系统属性读取(SystemProperties)
 *   - 自动识别敏感系统属性访问
 *   - 调用堆栈追踪
 *   - 属性访问统计分析
 *   - 支持篡改返回值
 */

(function() {
    // 全局配置
    var config = {
        logLevel: 2,                  // 0:关闭 1:错误 2:基本信息 3:详细
        printStack: true,             // 是否打印调用堆栈
        maxStackDepth: 5,             // 最大堆栈深度
        spoofEmulatorDetection: false, // 是否伪装模拟器检测结果
        monitorAndroidProps: true,    // 是否监控Android特有属性
        monitorJavaProps: true,       // 是否监控Java系统属性
        filterSystemApps: true        // 是否过滤系统应用调用
    };
    
    // 统计信息
    var stats = {
        nativeCalls: 0,
        javaCalls: 0,
        androidCalls: 0,
        byKey: {}
    };
    
    // 敏感属性列表
    var sensitiveProps = {
        // 模拟器检测相关属性
        emulatorDetection: [
            "ro.kernel.qemu",
            "ro.product.model",
            "ro.product.manufacturer",
            "ro.product.device",
            "ro.hardware",
            "ro.build.fingerprint",
            "init.svc.qemu-props"
        ],
        // 调试相关属性
        debugDetection: [
            "ro.debuggable",
            "ro.secure",
            "service.adb.root",
            "debug.sf.showupdates"
        ],
        // 设备指纹相关属性
        deviceFingerprint: [
            "ro.serialno",
            "ro.bootloader",
            "ro.boot.serialno",
            "ro.build.id",
            "ro.build.display.id"
        ],
        // root相关属性
        rootDetection: [
            "ro.boot.verifiedbootstate",
            "ro.boot.veritymode"
        ]
    };
    
    // 属性伪装值(如果启用伪装)
    var spoofValues = {
        "ro.kernel.qemu": "0",
        "ro.hardware": "ranchu",
        "ro.product.model": "Pixel 6",
        "ro.product.manufacturer": "Google",
        "ro.debuggable": "0",
        "ro.secure": "1"
    };
    
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
    
    // 辅助函数：获取调用堆栈
    function getStackTrace() {
        if (!config.printStack) return "";
        
        try {
            var exception = Java.use("java.lang.Exception").$new();
            var stackElements = exception.getStackTrace();
            var limit = Math.min(stackElements.length, config.maxStackDepth);
            
            var stack = "\n    调用堆栈:";
            for (var i = 0; i < limit; i++) {
                var element = stackElements[i];
                var className = element.getClassName();
                
                // 过滤掉系统类
                if (config.filterSystemApps && 
                    (className.indexOf("android.") === 0 && 
                     className.indexOf("android.app.Application") !== 0)) {
                    continue;
                }
                
                stack += "\n        " + className + "." + 
                         element.getMethodName() + "(" + 
                         (element.getFileName() != null ? element.getFileName() : "Unknown Source") + ":" + 
                         element.getLineNumber() + ")";
            }
            return stack;
        } catch (e) {
            return "\n    调用堆栈获取失败: " + e;
        }
    }
    
    // 辅助函数：获取属性类别
    function getPropertyCategory(key) {
        for (var category in sensitiveProps) {
            if (sensitiveProps[category].indexOf(key) !== -1) {
                return category;
            }
        }
        return null;
    }
    
    // 辅助函数：更新统计信息
    function updateStats(type, key, value) {
        switch(type) {
            case "native": stats.nativeCalls++; break;
            case "java": stats.javaCalls++; break;
            case "android": stats.androidCalls++; break;
        }
        
        if (!stats.byKey[key]) {
            stats.byKey[key] = { count: 0, type: type, lastValue: value };
        }
        
        stats.byKey[key].count++;
        stats.byKey[key].lastValue = value;
    }
    
    // 辅助函数：格式化属性访问日志
    function formatPropertyAccess(type, key, value, category) {
        var message = type + "层读取系统属性: " + key + " = " + value;
        
        if (category) {
            message += " [" + category + "]";
        }
        
        return message;
    }

    // 监控Native层系统属性读取
    if (Process.findModuleByName("libc.so")) {
        try {
            // 监控 __system_property_get
            Interceptor.attach(Module.findExportByName("libc.so", "__system_property_get"), {
                onEnter: function(args) {
                    this.key = args[0].readCString();
                    this.valuePtr = args[1];
                },
                onLeave: function(retval) {
                    var len = retval.toInt32();
                    var value = "";
                    
                    if (len > 0) {
                        value = this.valuePtr.readCString();
                    }
                    
                    var category = getPropertyCategory(this.key);
                    updateStats("native", this.key, value);
                    
                    // 记录属性读取
                    log(2, formatPropertyAccess("Native", this.key, value, category));
                    
                    if (config.printStack) {
                        // 对于Native堆栈，使用Frida的backtrace
                        var nativeStack = Thread.backtrace(this.context, Backtracer.ACCURATE)
                            .map(DebugSymbol.fromAddress)
                            .join('\n        ');
                        log(3, "\n    Native调用堆栈:\n        " + nativeStack);
                    }
                    
                    // 如果启用了伪装并且是敏感属性，则修改返回值
                    if (config.spoofEmulatorDetection && spoofValues[this.key]) {
                        var newValue = spoofValues[this.key];
                        log(1, "    伪装属性值: " + newValue + " (原值: " + value + ")");
                        
                        // 写入新值到输出缓冲区
                        Memory.writeUtf8String(this.valuePtr, newValue);
                        // 返回新值的长度
                        return newValue.length;
                    }
                }
            });
            
            // 可选：监控 __system_property_find
            var sysPropFind = Module.findExportByName("libc.so", "__system_property_find");
            if (sysPropFind) {
                Interceptor.attach(sysPropFind, {
                    onEnter: function(args) {
                        this.key = args[0].readCString();
                    },
                    onLeave: function(retval) {
                        if (!retval.isNull()) {
                            log(3, "Native层查找属性: " + this.key);
                        }
                    }
                });
            }
            
            // 可选：监控 __system_property_read
            var sysPropRead = Module.findExportByName("libc.so", "__system_property_read");
            if (sysPropRead) {
                Interceptor.attach(sysPropRead, {
                    onEnter: function(args) {
                        this.pi = args[0];
                        this.namePtr = args[1];
                        this.valuePtr = args[2];
                    },
                    onLeave: function(retval) {
                        if (!this.namePtr.isNull() && !this.valuePtr.isNull()) {
                            var name = this.namePtr.readCString();
                            var value = this.valuePtr.readCString();
                            
                            var category = getPropertyCategory(name);
                            if (category || config.logLevel >= 3) {
                                log(3, "Native层读取属性(read): " + name + " = " + value + 
                                    (category ? " [" + category + "]" : ""));
                            }
                        }
                    }
                });
            }
            
            log(2, "Native层系统属性监控已启动");
        } catch (e) {
            log(1, "监控Native层系统属性失败: " + e);
        }
    }

    Java.perform(function() {
        // 监控Android特有的系统属性API
        if (config.monitorAndroidProps) {
            try {
                // 反射获取隐藏的SystemProperties类
                var SystemProperties = Java.use("android.os.SystemProperties");
                
                // 监控 SystemProperties.get 方法（无默认值）
                SystemProperties.get.overload('java.lang.String').implementation = function(key) {
                    var value = this.get(key);
                    var category = getPropertyCategory(key);
                    
                    updateStats("android", key, value);
                    log(2, formatPropertyAccess("Android", key, value, category));
                    
                    if (config.printStack) {
                        log(3, getStackTrace());
                    }
                    
                    // 如果启用了伪装并且是敏感属性，则返回伪装值
                    if (config.spoofEmulatorDetection && spoofValues[key]) {
                        var spoofed = spoofValues[key];
                        log(1, "    伪装属性值: " + spoofed + " (原值: " + value + ")");
                        return spoofed;
                    }
                    
                    return value;
                };
                
                // 监控 SystemProperties.get 方法（带默认值）
                SystemProperties.get.overload('java.lang.String', 'java.lang.String').implementation = function(key, def) {
                    var value = this.get(key, def);
                    var category = getPropertyCategory(key);
                    
                    updateStats("android", key, value);
                    log(2, formatPropertyAccess("Android", key, value, category));
                    
                    if (config.printStack) {
                        log(3, getStackTrace());
                    }
                    
                    // 如果启用了伪装并且是敏感属性，则返回伪装值
                    if (config.spoofEmulatorDetection && spoofValues[key]) {
                        var spoofed = spoofValues[key];
                        log(1, "    伪装属性值: " + spoofed + " (原值: " + value + ")");
                        return spoofed;
                    }
                    
                    return value;
                };
                
                // 监控 SystemProperties.getInt 方法
                SystemProperties.getInt.overload('java.lang.String', 'int').implementation = function(key, def) {
                    var value = this.getInt(key, def);
                    var category = getPropertyCategory(key);
                    
                    updateStats("android", key, value);
                    log(2, formatPropertyAccess("Android", key, value, category));
                    
                    if (config.printStack) {
                        log(3, getStackTrace());
                    }
                    
                    // 如果启用了伪装并且是敏感属性，则返回伪装值
                    if (config.spoofEmulatorDetection && spoofValues[key]) {
                        var spoofed = parseInt(spoofValues[key]);
                        if (!isNaN(spoofed)) {
                            log(1, "    伪装属性值: " + spoofed + " (原值: " + value + ")");
                            return spoofed;
                        }
                    }
                    
                    return value;
                };
                
                // 监控 SystemProperties.getLong 方法
                SystemProperties.getLong.overload('java.lang.String', 'long').implementation = function(key, def) {
                    var value = this.getLong(key, def);
                    var category = getPropertyCategory(key);
                    
                    updateStats("android", key, value);
                    log(2, formatPropertyAccess("Android", key, value, category));
                    
                    if (config.printStack) {
                        log(3, getStackTrace());
                    }
                    
                    return value;
                };
                
                // 监控 SystemProperties.getBoolean 方法
                SystemProperties.getBoolean.overload('java.lang.String', 'boolean').implementation = function(key, def) {
                    var value = this.getBoolean(key, def);
                    var category = getPropertyCategory(key);
                    
                    updateStats("android", key, value);
                    log(2, formatPropertyAccess("Android", key, value, category));
                    
                    if (config.printStack) {
                        log(3, getStackTrace());
                    }
                    
                    return value;
                };
                
                log(2, "Android系统属性API监控已启动");
            } catch (e) {
                log(1, "监控Android系统属性API失败: " + e);
            }
        }
        
        // 监控Java标准系统属性
        if (config.monitorJavaProps) {
            try {
                var System = Java.use("java.lang.System");
                
                // 监控 System.getProperty 方法（无默认值）
                System.getProperty.overload('java.lang.String').implementation = function(key) {
                    var value = this.getProperty(key);
                    
                    updateStats("java", key, value);
                    log(2, "Java层读取系统属性: " + key + " = " + value);
                    
                    if (config.printStack) {
                        log(3, getStackTrace());
                    }
                    
                    return value;
                };
                
                // 监控 System.getProperty 方法（带默认值）
                System.getProperty.overload('java.lang.String', 'java.lang.String').implementation = function(key, def) {
                    var value = this.getProperty(key, def);
                    
                    updateStats("java", key, value);
                    log(2, "Java层读取系统属性(带默认值): " + key + " = " + value);
                    
                    if (config.printStack) {
                        log(3, getStackTrace());
                    }
                    
                    return value;
                };
                
                // 监控 System.getProperties 方法
                System.getProperties.implementation = function() {
                    var props = this.getProperties();
                    
                    log(3, "Java层读取所有系统属性");
                    
                    if (config.printStack) {
                        log(3, getStackTrace());
                    }
                    
                    return props;
                };
                
                log(2, "Java系统属性API监控已启动");
            } catch (e) {
                log(1, "监控Java系统属性API失败: " + e);
            }
        }
        
        // 监控Build类（常用于设备信息检测）
        try {
            var Build = Java.use("android.os.Build");
            
            // 监控访问Build类的静态字段
            var fields = [
                "BOARD", "BOOTLOADER", "BRAND", "CPU_ABI", "CPU_ABI2", "DEVICE", 
                "DISPLAY", "FINGERPRINT", "HARDWARE", "HOST", "ID", "MANUFACTURER", 
                "MODEL", "PRODUCT", "SERIAL", "TAGS", "TYPE", "USER"
            ];
            
            fields.forEach(function(field) {
                var fieldName = field;
                
                // 创建getter钩子
                var fieldHook = {
                    get: function() {
                        var value = Build[fieldName].value;
                        
                        log(2, "访问Build." + fieldName + " = " + value);
                        
                        if (config.printStack) {
                            log(3, getStackTrace());
                        }
                        
                        // 如果启用了伪装，根据字段返回伪装值
                        if (config.spoofEmulatorDetection) {
                            if (fieldName === "FINGERPRINT" && value.indexOf("generic") !== -1) {
                                var spoofed = "google/redfin/redfin:12/SQ1A.220105.002/8010698:user/release-keys";
                                log(1, "    伪装Build." + fieldName + ": " + spoofed);
                                return spoofed;
                            }
                            if (fieldName === "MODEL" && (value === "sdk" || value === "google_sdk" || value.indexOf("Emulator") !== -1)) {
                                var spoofed = "Pixel 6";
                                log(1, "    伪装Build." + fieldName + ": " + spoofed);
                                return spoofed;
                            }
                            if (fieldName === "MANUFACTURER" && (value === "Google" || value === "unknown")) {
                                var spoofed = "Google";
                                log(1, "    伪装Build." + fieldName + ": " + spoofed);
                                return spoofed;
                            }
                        }
                        
                        return value;
                    }
                };
                
                // 替换getter
                try {
                    Object.defineProperty(Build, fieldName, fieldHook);
                } catch (e) {
                    // 某些字段可能无法hook，忽略错误
                }
            });
            
            log(2, "Android.os.Build字段监控已启动");
        } catch (e) {
            log(1, "监控Build类失败: " + e);
        }
        
        // 定期输出统计信息
        setInterval(function() {
            var totalCalls = stats.nativeCalls + stats.javaCalls + stats.androidCalls;
            
            if (totalCalls > 0) {
                log(2, "系统属性访问统计: Native调用(" + stats.nativeCalls + 
                     "), Java调用(" + stats.javaCalls + 
                     "), Android调用(" + stats.androidCalls + ")");
                
                // 找出访问最频繁的属性
                var topProps = [];
                for (var key in stats.byKey) {
                    topProps.push({key: key, count: stats.byKey[key].count, value: stats.byKey[key].lastValue});
                }
                
                // 排序并显示前5个
                topProps.sort(function(a, b) { return b.count - a.count; });
                var topPropsInfo = "";
                var limit = Math.min(5, topProps.length);
                
                for (var i = 0; i < limit; i++) {
                    var prop = topProps[i];
                    var category = getPropertyCategory(prop.key);
                    topPropsInfo += "\n    " + prop.key + " = " + prop.value + 
                                  " (访问" + prop.count + "次)" + 
                                  (category ? " [" + category + "]" : "");
                }
                
                if (topPropsInfo) {
                    log(2, "最常访问的属性:" + topPropsInfo);
                }
                
                // 输出敏感属性访问统计
                var sensitiveAccess = 0;
                for (var category in sensitiveProps) {
                    var count = 0;
                    var props = sensitiveProps[category];
                    
                    for (var i = 0; i < props.length; i++) {
                        var propStats = stats.byKey[props[i]];
                        if (propStats) {
                            count += propStats.count;
                        }
                    }
                    
                    if (count > 0) {
                        log(2, category + "相关属性访问: " + count + "次");
                        sensitiveAccess += count;
                    }
                }
                
                if (sensitiveAccess > 0 && config.spoofEmulatorDetection) {
                    log(1, "注意: 检测到" + sensitiveAccess + "次敏感属性访问，已启用属性值伪装");
                }
            }
        }, 10000); // 每10秒输出一次
    });
    
    log(2, "系统属性监控已启动" + (config.spoofEmulatorDetection ? "（已启用属性伪装）" : ""));
})(); 