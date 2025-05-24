/*
 * 脚本名称：通杀系统属性读取.js
 * 功能：自动监控Android系统属性(System Properties)获取操作，辅助分析反模拟器、设备指纹
 * 适用场景：反模拟器对抗、设备指纹分析、环境检测分析
 * 使用方法：
 *   1. frida -U -f 包名 -l 通杀系统属性读取.js --no-pause
 *   2. 查看控制台输出，获取系统属性读取信息
 * 启动方式说明：
 *   - -U 代表使用USB连接的设备
 *   - -f 代表以spawn方式启动目标应用（推荐，可以捕获启动阶段的属性读取）
 *   - --no-pause 指示Frida不要暂停应用执行，保证App正常运行
 *   - 也可使用 -F 以attach方式附加到已运行的进程
 * 参数说明：
 *   - 包名：目标应用的包名，如com.example.app
 * 监控函数说明：
 *   - Java层:
 *     - System.getProperty(): 获取Java系统属性
 *     - SystemProperties.get(): Android隐藏API，获取系统属性
 *     - Build类相关常量：直接读取设备信息
 *   - Native层:
 *     - __system_property_get(): 底层系统属性获取函数
 *     - property_get(): 兼容层系统属性获取函数
 * 系统属性用途：
 *   - ro.product.*: 产品相关信息，如型号、厂商
 *   - ro.build.*: 系统构建信息
 *   - ro.hardware.*: 硬件相关信息
 *   - ro.bootmode: 启动模式，可检测模拟器
 *   - ro.kernel.*: 内核信息
 *   - ro.secure: 系统安全标志
 *   - ro.debuggable: 调试标志
 * 输出内容：
 *   - 属性名：被读取的系统属性键名
 *   - 属性值：系统返回的属性值
 *   - 调用位置：读取属性的代码位置
 *   - 标记：特殊属性会被标记(如模拟器检测相关属性)
 * 实际应用场景：
 *   - 分析App如何检测模拟器
 *   - 了解应用收集了哪些设备信息
 *   - 跟踪应用获取系统敏感配置
 *   - 分析应用环境检测机制
 * 注意事项：
 *   - 某些加固应用需配合反检测脚本
 *   - 大量属性读取可能导致日志过多，可添加过滤器减少输出
 *   - 建议配合通杀绕过模拟器检测.js使用
 */

// 通杀系统属性读取
Java.perform(function () {
    // 定义敏感属性列表，这些属性通常用于检测模拟器或获取设备信息
    var sensitiveProps = [
        // 模拟器检测相关
        "ro.hardware",
        "ro.product.model",
        "ro.product.manufacturer",
        "ro.product.device",
        "ro.product.name",
        "ro.bootloader",
        "ro.bootmode",
        "ro.product.brand",
        "ro.product.board",
        "ro.build.fingerprint",
        "ro.build.characteristics",
        "ro.build.tags",
        // 运行时环境检测
        "ro.debuggable",
        "ro.secure",
        "service.adb.tcp.port",
        // 硬件相关
        "ro.serialno",
        "ro.boot.serialno",
        "persist.sys.usb.config",
        "sys.usb.config",
        // 其他敏感信息
        "ro.kernel.qemu",
        "qemu.hw.mainkeys",
        "ro.kernel.android.qemud"
    ];
    
    // 辅助函数：检查属性是否为敏感属性
    function isSensitiveProp(propName) {
        if (!propName) return false;
        
        // 精确匹配
        if (sensitiveProps.indexOf(propName) >= 0) {
            return true;
        }
        
        // 前缀匹配
        for (var i = 0; i < sensitiveProps.length; i++) {
            if (propName.startsWith(sensitiveProps[i])) {
                return true;
            }
        }
        
        return false;
    }
    
    // 辅助函数：为敏感属性添加说明
    function getSensitivePropDescription(propName) {
        if (!propName) return null;
        
        // 设备模拟器标识相关
        if (propName.includes("ro.hardware") || 
            propName.includes("qemu") ||
            propName.includes("goldfish") ||
            propName.includes("ranchu")) {
            return "模拟器硬件标识";
        }
        
        if (propName.includes("ro.product.model") || 
            propName.includes("ro.product.manufacturer") ||
            propName.includes("ro.product.device") ||
            propName.includes("ro.product.name") ||
            propName.includes("ro.product.brand") ||
            propName.includes("ro.product.board")) {
            return "设备型号信息";
        }
        
        if (propName.includes("ro.build.fingerprint") ||
            propName.includes("ro.build.characteristics") ||
            propName.includes("ro.build.tags")) {
            return "系统指纹标识";
        }
        
        if (propName.includes("ro.debuggable")) {
            return "调试标志";
        }
        
        if (propName.includes("ro.secure")) {
            return "安全标志";
        }
        
        if (propName.includes("adb") || propName.includes("usb")) {
            return "ADB/USB配置";
        }
        
        if (propName.includes("serialno")) {
            return "设备序列号";
        }
        
        if (propName.includes("ro.bootmode") || propName.includes("ro.bootloader")) {
            return "启动模式信息";
        }
        
        return "敏感系统属性";
    }
    
    // 监控Java层的System.getProperty
    var System = Java.use('java.lang.System');
    
    // 重载1：getProperty(String)
    System.getProperty.overload('java.lang.String').implementation = function(propName) {
        var value = this.getProperty(propName);
        
        // 记录属性读取
        console.log('[*] System.getProperty("' + propName + '"): ' + value);
        
        // 如果是敏感属性，提供额外信息
        if (isSensitiveProp(propName)) {
            var desc = getSensitivePropDescription(propName);
            console.log('    [!] 敏感属性: ' + desc);
        }
        
        // 打印调用堆栈
        console.log('    调用堆栈: ' + Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n')[2]);
        
        return value;
    };
    
    // 重载2：getProperty(String, String)
    System.getProperty.overload('java.lang.String', 'java.lang.String').implementation = function(propName, defaultValue) {
        var value = this.getProperty(propName, defaultValue);
        
        // 记录属性读取
        console.log('[*] System.getProperty("' + propName + '", "' + defaultValue + '"): ' + value);
        
        // 如果是敏感属性，提供额外信息
        if (isSensitiveProp(propName)) {
            var desc = getSensitivePropDescription(propName);
            console.log('    [!] 敏感属性: ' + desc);
        }
        
        // 打印调用堆栈
        console.log('    调用堆栈: ' + Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n')[2]);
        
        return value;
    };
    
    // 监控Android隐藏API SystemProperties
    try {
        var SystemProperties = Java.use('android.os.SystemProperties');
        
        // 重载1：get(String)
        SystemProperties.get.overload('java.lang.String').implementation = function(propName) {
            var value = this.get(propName);
            
            // 记录属性读取
            console.log('[*] SystemProperties.get("' + propName + '"): ' + value);
            
            // 如果是敏感属性，提供额外信息
            if (isSensitiveProp(propName)) {
                var desc = getSensitivePropDescription(propName);
                console.log('    [!] 敏感属性: ' + desc);
            }
            
            // 打印调用堆栈
            console.log('    调用堆栈: ' + Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n')[2]);
            
            return value;
        };
        
        // 重载2：get(String, String)
        SystemProperties.get.overload('java.lang.String', 'java.lang.String').implementation = function(propName, defaultValue) {
            var value = this.get(propName, defaultValue);
            
            // 记录属性读取
            console.log('[*] SystemProperties.get("' + propName + '", "' + defaultValue + '"): ' + value);
            
            // 如果是敏感属性，提供额外信息
            if (isSensitiveProp(propName)) {
                var desc = getSensitivePropDescription(propName);
                console.log('    [!] 敏感属性: ' + desc);
            }
            
            // 打印调用堆栈
            console.log('    调用堆栈: ' + Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n')[2]);
            
            return value;
        };
        
        // 重载3：getBoolean(String, boolean)
        SystemProperties.getBoolean.overload('java.lang.String', 'boolean').implementation = function(propName, defaultValue) {
            var value = this.getBoolean(propName, defaultValue);
            
            // 记录属性读取
            console.log('[*] SystemProperties.getBoolean("' + propName + '", ' + defaultValue + '): ' + value);
            
            // 如果是敏感属性，提供额外信息
            if (isSensitiveProp(propName)) {
                var desc = getSensitivePropDescription(propName);
                console.log('    [!] 敏感属性: ' + desc);
            }
            
            // 打印调用堆栈
            console.log('    调用堆栈: ' + Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n')[2]);
            
            return value;
        };
        
        // 重载4：getInt(String, int)
        SystemProperties.getInt.overload('java.lang.String', 'int').implementation = function(propName, defaultValue) {
            var value = this.getInt(propName, defaultValue);
            
            // 记录属性读取
            console.log('[*] SystemProperties.getInt("' + propName + '", ' + defaultValue + '): ' + value);
            
            // 如果是敏感属性，提供额外信息
            if (isSensitiveProp(propName)) {
                var desc = getSensitivePropDescription(propName);
                console.log('    [!] 敏感属性: ' + desc);
            }
            
            // 打印调用堆栈
            console.log('    调用堆栈: ' + Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n')[2]);
            
            return value;
        };
    } catch (e) {
        console.log("[-] SystemProperties类Hook失败: " + e);
    }
    
    // 监控Build类中的常量访问
    var Build = Java.use('android.os.Build');
    var buildFields = [
        {field: "MODEL", description: "设备型号"},
        {field: "MANUFACTURER", description: "设备制造商"},
        {field: "BRAND", description: "设备品牌"},
        {field: "DEVICE", description: "设备名称"},
        {field: "BOARD", description: "主板名称"},
        {field: "HARDWARE", description: "硬件名称"},
        {field: "FINGERPRINT", description: "系统指纹"},
        {field: "PRODUCT", description: "产品名称"}
    ];
    
    // 为每个字段添加getter钩子
    buildFields.forEach(function(item) {
        try {
            var originalValue = Build[item.field].value;
            Build[item.field].value = originalValue;
            
            // 使用Object.defineProperty来监控字段读取
            var fieldName = item.field;
            var fieldDesc = item.description;
            
            Object.defineProperty(Build, fieldName, {
                get: function() {
                    console.log('[*] 读取Build.' + fieldName + ': ' + originalValue);
                    console.log('    [!] ' + fieldDesc);
                    console.log('    调用堆栈: ' + Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n')[2]);
                    return originalValue;
                },
                set: function(value) {
                    console.log('[*] 修改Build.' + fieldName + ': ' + value);
                    originalValue = value;
                }
            });
        } catch (e) {
            console.log("[-] 监控Build." + item.field + "失败: " + e);
        }
    });
    
    // 监控Native层系统属性获取函数
    try {
        // __system_property_get是系统属性读取的底层函数
        // 函数原型: int __system_property_get(const char *name, char *value);
        var sysPropGet = Module.findExportByName(null, '__system_property_get');
        
        if (sysPropGet) {
            Interceptor.attach(sysPropGet, {
                onEnter: function(args) {
                    // 保存参数以便在onLeave中使用
                    this.propName = Memory.readUtf8String(args[0]);
                    this.valuePtr = args[1];
                },
                onLeave: function(retval) {
                    // 获取返回的属性值
                    var propValue = Memory.readUtf8String(this.valuePtr);
                    
                    // 记录属性读取
                    console.log('[*] __system_property_get("' + this.propName + '"): ' + propValue);
                    
                    // 如果是敏感属性，提供额外信息
                    if (isSensitiveProp(this.propName)) {
                        var desc = getSensitivePropDescription(this.propName);
                        console.log('    [!] 敏感属性: ' + desc);
                    }
                    
                    // 打印调用堆栈
                    console.log('    调用堆栈: ');
                    console.log('    ' + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n    '));
                }
            });
            
            console.log("[+] 成功Hook __system_property_get");
        }
        
        // 某些旧系统或兼容层可能使用property_get函数
        var propertyGet = Module.findExportByName(null, 'property_get');
        if (propertyGet) {
            Interceptor.attach(propertyGet, {
                onEnter: function(args) {
                    this.propName = Memory.readUtf8String(args[0]);
                    this.valuePtr = args[1];
                },
                onLeave: function(retval) {
                    var propValue = Memory.readUtf8String(this.valuePtr);
                    console.log('[*] property_get("' + this.propName + '"): ' + propValue);
                    
                    if (isSensitiveProp(this.propName)) {
                        var desc = getSensitivePropDescription(this.propName);
                        console.log('    [!] 敏感属性: ' + desc);
                    }
                    
                    console.log('    调用堆栈: ');
                    console.log('    ' + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n    '));
                }
            });
            
            console.log("[+] 成功Hook property_get");
        }
    } catch (e) {
        console.log("[-] Native层系统属性函数Hook失败: " + e);
    }
    
    console.log("[*] 系统属性监控已启动");
    console.log("[*] 监控范围: Java System.getProperty、SystemProperties、Build类和Native属性函数");
}); 