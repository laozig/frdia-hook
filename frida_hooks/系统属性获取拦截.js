/**
 * 系统属性获取拦截脚本
 * 
 * 功能：拦截Android应用中对系统属性的获取
 * 作用：监控应用获取设备信息、系统信息的行为
 * 适用：分析应用信息收集行为，防止设备指纹识别
 */

// 等待Java虚拟机加载完成
Java.perform(function() {
    console.log("[*] 系统属性获取拦截脚本已启动");

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
     * 一、拦截System.getProperty
     * 用于获取系统属性
     */
    var System = Java.use("java.lang.System");
    
    // 拦截getProperty方法
    System.getProperty.overload("java.lang.String").implementation = function(key) {
        var value = this.getProperty(key);
        console.log("\n[+] System.getProperty");
        console.log("    键: " + key);
        console.log("    值: " + value);
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        return value;
    };
    
    // 拦截getProperty方法(带默认值)
    System.getProperty.overload("java.lang.String", "java.lang.String").implementation = function(key, defaultValue) {
        var value = this.getProperty(key, defaultValue);
        console.log("\n[+] System.getProperty (带默认值)");
        console.log("    键: " + key);
        console.log("    值: " + value);
        console.log("    默认值: " + defaultValue);
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        return value;
    };

    /**
     * 二、拦截SystemProperties
     * Android内部使用的系统属性获取类
     */
    try {
        var SystemProperties = Java.use("android.os.SystemProperties");
        
        // 拦截get方法
        SystemProperties.get.overload("java.lang.String").implementation = function(key) {
            var value = this.get(key);
            console.log("\n[+] SystemProperties.get");
            console.log("    键: " + key);
            console.log("    值: " + value);
            console.log("    调用堆栈:\n    " + getStackTrace());
            
            return value;
        };
        
        // 拦截get方法(带默认值)
        SystemProperties.get.overload("java.lang.String", "java.lang.String").implementation = function(key, defaultValue) {
            var value = this.get(key, defaultValue);
            console.log("\n[+] SystemProperties.get (带默认值)");
            console.log("    键: " + key);
            console.log("    值: " + value);
            console.log("    默认值: " + defaultValue);
            console.log("    调用堆栈:\n    " + getStackTrace());
            
            return value;
        };
        
        // 拦截getInt方法
        SystemProperties.getInt.overload("java.lang.String", "int").implementation = function(key, defaultValue) {
            var value = this.getInt(key, defaultValue);
            console.log("\n[+] SystemProperties.getInt");
            console.log("    键: " + key);
            console.log("    值: " + value);
            console.log("    默认值: " + defaultValue);
            console.log("    调用堆栈:\n    " + getStackTrace());
            
            return value;
        };
        
        // 拦截getLong方法
        SystemProperties.getLong.overload("java.lang.String", "long").implementation = function(key, defaultValue) {
            var value = this.getLong(key, defaultValue);
            console.log("\n[+] SystemProperties.getLong");
            console.log("    键: " + key);
            console.log("    值: " + value);
            console.log("    默认值: " + defaultValue);
            console.log("    调用堆栈:\n    " + getStackTrace());
            
            return value;
        };
        
        // 拦截getBoolean方法
        SystemProperties.getBoolean.overload("java.lang.String", "boolean").implementation = function(key, defaultValue) {
            var value = this.getBoolean(key, defaultValue);
            console.log("\n[+] SystemProperties.getBoolean");
            console.log("    键: " + key);
            console.log("    值: " + value);
            console.log("    默认值: " + defaultValue);
            console.log("    调用堆栈:\n    " + getStackTrace());
            
            return value;
        };
        
        console.log("[+] SystemProperties拦截设置完成");
    } catch (e) {
        console.log("[-] SystemProperties拦截设置失败: " + e);
    }

    /**
     * 三、拦截Build类
     * 包含设备和系统信息
     */
    var Build = Java.use("android.os.Build");
    
    // 监控对Build类字段的访问
    var buildFields = [
        "BOARD", "BOOTLOADER", "BRAND", "DEVICE", "DISPLAY", 
        "FINGERPRINT", "HARDWARE", "HOST", "ID", "MANUFACTURER", 
        "MODEL", "PRODUCT", "SERIAL", "TAGS", "TYPE", "USER"
    ];
    
    for (var i = 0; i < buildFields.length; i++) {
        var fieldName = buildFields[i];
        
        // 使用反射获取字段值
        try {
            var field = Build.class.getDeclaredField(fieldName);
            field.setAccessible(true);
            var value = field.get(null);
            
            // 创建getter拦截
            eval(`
                Object.defineProperty(Build, '${fieldName}', {
                    get: function() {
                        console.log("\\n[+] 访问 Build.${fieldName}");
                        console.log("    值: " + '${value}');
                        console.log("    调用堆栈:\\n    " + getStackTrace());
                        return '${value}';
                    }
                });
            `);
        } catch (e) {
            console.log("[-] 无法拦截 Build." + fieldName + ": " + e);
        }
    }
    
    // 拦截Build.VERSION类
    try {
        var BuildVersion = Java.use("android.os.Build$VERSION");
        var versionFields = [
            "CODENAME", "INCREMENTAL", "RELEASE", "SDK", "SDK_INT"
        ];
        
        for (var i = 0; i < versionFields.length; i++) {
            var fieldName = versionFields[i];
            
            // 使用反射获取字段值
            try {
                var field = BuildVersion.class.getDeclaredField(fieldName);
                field.setAccessible(true);
                var value = field.get(null);
                
                // 创建getter拦截
                eval(`
                    Object.defineProperty(BuildVersion, '${fieldName}', {
                        get: function() {
                            console.log("\\n[+] 访问 Build.VERSION.${fieldName}");
                            console.log("    值: " + '${value}');
                            console.log("    调用堆栈:\\n    " + getStackTrace());
                            return '${value}';
                        }
                    });
                `);
            } catch (e) {
                console.log("[-] 无法拦截 Build.VERSION." + fieldName + ": " + e);
            }
        }
        
        console.log("[+] Build类拦截设置完成");
    } catch (e) {
        console.log("[-] Build类拦截设置失败: " + e);
    }

    /**
     * 四、拦截Settings.Secure
     * 包含安全相关的系统设置
     */
    try {
        var Secure = Java.use("android.provider.Settings$Secure");
        
        // 拦截getString方法
        Secure.getString.implementation = function(resolver, name) {
            var value = this.getString(resolver, name);
            console.log("\n[+] Settings.Secure.getString");
            console.log("    名称: " + name);
            console.log("    值: " + value);
            console.log("    调用堆栈:\n    " + getStackTrace());
            
            // 特殊处理ANDROID_ID，这是一个常用于设备识别的唯一标识符
            if (name === "android_id") {
                console.log("    [!] 检测到获取ANDROID_ID");
            }
            
            return value;
        };
        
        // 拦截getInt方法
        Secure.getInt.overload("android.content.ContentResolver", "java.lang.String", "int").implementation = function(resolver, name, defaultValue) {
            var value = this.getInt(resolver, name, defaultValue);
            console.log("\n[+] Settings.Secure.getInt");
            console.log("    名称: " + name);
            console.log("    值: " + value);
            console.log("    默认值: " + defaultValue);
            console.log("    调用堆栈:\n    " + getStackTrace());
            
            return value;
        };
        
        // 拦截getLong方法
        Secure.getLong.overload("android.content.ContentResolver", "java.lang.String", "long").implementation = function(resolver, name, defaultValue) {
            var value = this.getLong(resolver, name, defaultValue);
            console.log("\n[+] Settings.Secure.getLong");
            console.log("    名称: " + name);
            console.log("    值: " + value);
            console.log("    默认值: " + defaultValue);
            console.log("    调用堆栈:\n    " + getStackTrace());
            
            return value;
        };
        
        // 拦截getFloat方法
        Secure.getFloat.overload("android.content.ContentResolver", "java.lang.String", "float").implementation = function(resolver, name, defaultValue) {
            var value = this.getFloat(resolver, name, defaultValue);
            console.log("\n[+] Settings.Secure.getFloat");
            console.log("    名称: " + name);
            console.log("    值: " + value);
            console.log("    默认值: " + defaultValue);
            console.log("    调用堆栈:\n    " + getStackTrace());
            
            return value;
        };
        
        console.log("[+] Settings.Secure拦截设置完成");
    } catch (e) {
        console.log("[-] Settings.Secure拦截设置失败: " + e);
    }

    /**
     * 五、拦截Settings.System
     * 包含系统设置
     */
    try {
        var System = Java.use("android.provider.Settings$System");
        
        // 拦截getString方法
        System.getString.implementation = function(resolver, name) {
            var value = this.getString(resolver, name);
            console.log("\n[+] Settings.System.getString");
            console.log("    名称: " + name);
            console.log("    值: " + value);
            console.log("    调用堆栈:\n    " + getStackTrace());
            
            return value;
        };
        
        // 拦截getInt方法
        System.getInt.overload("android.content.ContentResolver", "java.lang.String", "int").implementation = function(resolver, name, defaultValue) {
            var value = this.getInt(resolver, name, defaultValue);
            console.log("\n[+] Settings.System.getInt");
            console.log("    名称: " + name);
            console.log("    值: " + value);
            console.log("    默认值: " + defaultValue);
            console.log("    调用堆栈:\n    " + getStackTrace());
            
            return value;
        };
        
        console.log("[+] Settings.System拦截设置完成");
    } catch (e) {
        console.log("[-] Settings.System拦截设置失败: " + e);
    }

    /**
     * 六、拦截TelephonyManager
     * 用于获取电话和网络相关信息
     */
    var TelephonyManager = Java.use("android.telephony.TelephonyManager");
    
    // 拦截获取设备ID
    if (TelephonyManager.getDeviceId) {
        TelephonyManager.getDeviceId.overload().implementation = function() {
            var deviceId = this.getDeviceId();
            console.log("\n[+] TelephonyManager.getDeviceId");
            console.log("    设备ID: " + deviceId);
            console.log("    调用堆栈:\n    " + getStackTrace());
            
            return deviceId;
        };
    }
    
    // 拦截获取IMEI
    if (TelephonyManager.getImei) {
        TelephonyManager.getImei.overload().implementation = function() {
            var imei = this.getImei();
            console.log("\n[+] TelephonyManager.getImei");
            console.log("    IMEI: " + imei);
            console.log("    调用堆栈:\n    " + getStackTrace());
            
            return imei;
        };
    }
    
    // 拦截获取MEID
    if (TelephonyManager.getMeid) {
        TelephonyManager.getMeid.overload().implementation = function() {
            var meid = this.getMeid();
            console.log("\n[+] TelephonyManager.getMeid");
            console.log("    MEID: " + meid);
            console.log("    调用堆栈:\n    " + getStackTrace());
            
            return meid;
        };
    }
    
    // 拦截获取电话号码
    TelephonyManager.getLine1Number.implementation = function() {
        var phoneNumber = this.getLine1Number();
        console.log("\n[+] TelephonyManager.getLine1Number");
        console.log("    电话号码: " + phoneNumber);
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        return phoneNumber;
    };
    
    // 拦截获取SIM卡序列号
    TelephonyManager.getSimSerialNumber.implementation = function() {
        var simSerial = this.getSimSerialNumber();
        console.log("\n[+] TelephonyManager.getSimSerialNumber");
        console.log("    SIM卡序列号: " + simSerial);
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        return simSerial;
    };
    
    // 拦截获取网络运营商名称
    TelephonyManager.getNetworkOperatorName.implementation = function() {
        var operatorName = this.getNetworkOperatorName();
        console.log("\n[+] TelephonyManager.getNetworkOperatorName");
        console.log("    网络运营商名称: " + operatorName);
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        return operatorName;
    };
    
    // 拦截获取网络类型
    TelephonyManager.getNetworkType.implementation = function() {
        var networkType = this.getNetworkType();
        console.log("\n[+] TelephonyManager.getNetworkType");
        console.log("    网络类型: " + networkType);
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        return networkType;
    };
    
    // 拦截获取SIM卡状态
    TelephonyManager.getSimState.implementation = function() {
        var simState = this.getSimState();
        console.log("\n[+] TelephonyManager.getSimState");
        console.log("    SIM卡状态: " + simState);
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        return simState;
    };

    /**
     * 七、拦截WifiManager
     * 用于获取WiFi相关信息
     */
    try {
        var WifiManager = Java.use("android.net.wifi.WifiManager");
        
        // 拦截获取WiFi信息
        WifiManager.getConnectionInfo.implementation = function() {
            var info = this.getConnectionInfo();
            console.log("\n[+] WifiManager.getConnectionInfo");
            
            // 获取MAC地址
            var macAddress = info.getMacAddress ? info.getMacAddress() : "未知";
            console.log("    MAC地址: " + macAddress);
            
            // 获取SSID
            var ssid = info.getSSID ? info.getSSID() : "未知";
            console.log("    SSID: " + ssid);
            
            console.log("    调用堆栈:\n    " + getStackTrace());
            
            return info;
        };
        
        // 拦截获取WiFi扫描结果
        WifiManager.getScanResults.implementation = function() {
            var results = this.getScanResults();
            console.log("\n[+] WifiManager.getScanResults");
            console.log("    扫描结果数量: " + (results ? results.size() : 0));
            console.log("    调用堆栈:\n    " + getStackTrace());
            
            return results;
        };
        
        console.log("[+] WifiManager拦截设置完成");
    } catch (e) {
        console.log("[-] WifiManager拦截设置失败: " + e);
    }

    /**
     * 八、拦截BluetoothAdapter
     * 用于获取蓝牙相关信息
     */
    try {
        var BluetoothAdapter = Java.use("android.bluetooth.BluetoothAdapter");
        
        // 拦截获取默认适配器
        BluetoothAdapter.getDefaultAdapter.implementation = function() {
            var adapter = this.getDefaultAdapter();
            console.log("\n[+] BluetoothAdapter.getDefaultAdapter");
            console.log("    调用堆栈:\n    " + getStackTrace());
            
            return adapter;
        };
        
        // 拦截获取蓝牙地址
        BluetoothAdapter.getAddress.implementation = function() {
            var address = this.getAddress();
            console.log("\n[+] BluetoothAdapter.getAddress");
            console.log("    蓝牙地址: " + address);
            console.log("    调用堆栈:\n    " + getStackTrace());
            
            return address;
        };
        
        // 拦截获取蓝牙名称
        BluetoothAdapter.getName.implementation = function() {
            var name = this.getName();
            console.log("\n[+] BluetoothAdapter.getName");
            console.log("    蓝牙名称: " + name);
            console.log("    调用堆栈:\n    " + getStackTrace());
            
            return name;
        };
        
        console.log("[+] BluetoothAdapter拦截设置完成");
    } catch (e) {
        console.log("[-] BluetoothAdapter拦截设置失败: " + e);
    }

    /**
     * 九、拦截DisplayMetrics
     * 用于获取屏幕相关信息
     */
    try {
        var DisplayMetrics = Java.use("android.util.DisplayMetrics");
        
        // 监控对DisplayMetrics字段的访问
        var displayFields = [
            "widthPixels", "heightPixels", "density", "densityDpi",
            "scaledDensity", "xdpi", "ydpi"
        ];
        
        for (var i = 0; i < displayFields.length; i++) {
            var fieldName = displayFields[i];
            
            // 使用反射获取字段
            try {
                var field = DisplayMetrics.class.getDeclaredField(fieldName);
                field.setAccessible(true);
                
                // 创建字段访问拦截
                eval(`
                    DisplayMetrics.${fieldName}.get = function() {
                        var value = field.get(this);
                        console.log("\\n[+] 访问 DisplayMetrics.${fieldName}");
                        console.log("    值: " + value);
                        console.log("    调用堆栈:\\n    " + getStackTrace());
                        return value;
                    };
                    
                    DisplayMetrics.${fieldName}.set = function(value) {
                        console.log("\\n[+] 设置 DisplayMetrics.${fieldName}");
                        console.log("    新值: " + value);
                        console.log("    调用堆栈:\\n    " + getStackTrace());
                        field.set(this, value);
                    };
                `);
            } catch (e) {
                console.log("[-] 无法拦截 DisplayMetrics." + fieldName + ": " + e);
            }
        }
        
        console.log("[+] DisplayMetrics拦截设置完成");
    } catch (e) {
        console.log("[-] DisplayMetrics拦截设置失败: " + e);
    }

    console.log("[*] 系统属性获取拦截设置完成");
}); 