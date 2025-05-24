/*
 * 脚本名称：通杀UUID生成.js
 * 功能：自动监控应用中的UUID生成、设备ID获取、唯一标识符提取等操作
 * 适用场景：设备指纹分析、广告追踪、反作弊系统、设备识别
 * 使用方法：
 *   1. frida -U -f 包名 -l 通杀UUID生成.js --no-pause
 *   2. 查看控制台输出，获取UUID生成和设备标识符获取信息
 * 启动方式说明：
 *   - -U 代表使用USB连接的设备
 *   - -f 代表以spawn方式启动目标应用（推荐，可以捕获启动阶段的标识符生成）
 *   - --no-pause 指示Frida不要暂停应用执行，保证App正常运行
 *   - 也可使用 -F 以attach方式附加到已运行的进程
 * 参数说明：
 *   - 包名：目标应用的包名，如com.example.app
 * 监控函数说明：
 *   标准UUID生成API:
 *   - UUID.randomUUID(): 生成随机UUID
 *   - UUID.fromString(): 从字符串解析UUID
 *   
 *   设备标识符API:
 *   - Settings.Secure.getString(): 获取Android安全设置，如ANDROID_ID
 *   - TelephonyManager.getDeviceId(): 获取IMEI（Android 10以下）
 *   - TelephonyManager.getImei(): 获取IMEI（Android 8.0+）
 *   - TelephonyManager.getMeid(): 获取MEID
 *   - Build.SERIAL: 获取序列号
 *   - MacAddress相关API: 获取MAC地址
 *   - AdvertisingIdClient: 获取广告ID
 *   - OAID/AAID: 厂商联盟ID
 *   
 *   存储标识符API:
 *   - SharedPreferences: 保存和读取持久化标识符
 *   - getExternalStorageDirectory(): 通常用于存储标识符文件
 *   
 *   硬件信息收集:
 *   - 传感器信息: SensorManager
 *   - 屏幕参数: DisplayMetrics
 *   - CPU信息: /proc/cpuinfo
 *   
 *   第三方设备指纹库:
 *   - 移动安全联盟OAID SDK
 *   - 友盟统计SDK
 *   - AppsFlyer归因SDK
 *   - TalkingData分析SDK
 *   - 个推/极光推送SDK
 * 
 * 输出内容：
 *   - 函数调用：具体生成UUID或获取设备标识符的API调用
 *   - 返回值：生成或获取的标识符
 *   - 调用堆栈：标识符生成或获取的代码位置
 *   - 标识符类型：明确标记不同类型的设备标识符
 *   
 * 实际应用场景：
 *   - 分析应用的设备指纹收集行为
 *   - 跟踪用户识别机制
 *   - 了解应用如何规避设备重置
 *   - 分析广告追踪系统
 *   - 检测指纹伪造防护
 *   
 * 注意事项：
 *   - Android 10+对标识符获取有更严格的限制
 *   - 一些应用可能使用自定义算法生成指纹，需要单独分析
 *   - 部分API需要特定权限，可能不会在所有应用中被调用
 *   - 指纹算法可能使用多种信息组合，单个标识符可能不是最终指纹
 */

// 通杀UUID生成
Java.perform(function () {
    // 辅助函数：获取简短调用堆栈
    function getStackShort() {
        return Java.use("android.util.Log").getStackTraceString(
            Java.use("java.lang.Exception").$new()).split('\n').slice(2, 5).join('\n    ');
    }
    
    // 辅助函数：检测伪造标识符尝试
    function detectSpoofingAttempt(stack) {
        var keywords = ["hook", "xposed", "frida", "spoof", "fake", "mock"];
        var lowerStack = stack.toLowerCase();
        
        for (var i = 0; i < keywords.length; i++) {
            if (lowerStack.indexOf(keywords[i]) !== -1) {
                return true;
            }
        }
        return false;
    }
    
    // 辅助函数：检测生成的UUID是否符合标准格式
    function isStandardUUID(uuid) {
        if (!uuid) return false;
        var uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
        return uuidRegex.test(uuid);
    }
    
    //===== 1. 监控标准UUID类 =====
    var UUID = Java.use('java.util.UUID');
    
    // 监控随机UUID生成
    UUID.randomUUID.implementation = function () {
        var uuid = this.randomUUID();
        console.log('[*] 生成随机UUID: ' + uuid.toString());
        
        // 获取调用堆栈
        var stack = getStackShort();
        console.log('    调用堆栈: \n    ' + stack);
        
        // 检测可能的伪造尝试
        if (detectSpoofingAttempt(stack)) {
            console.log('    [!] 警告: 可能存在UUID伪造尝试');
        }
        
        return uuid;
    };
    
    // 监控从字符串解析UUID
    UUID.fromString.implementation = function (uuidStr) {
        var uuid = this.fromString(uuidStr);
        console.log('[*] 从字符串解析UUID: ' + uuidStr);
        
        // 检查格式是否标准
        if (!isStandardUUID(uuidStr)) {
            console.log('    [!] 警告: 非标准格式UUID');
        }
        
        console.log('    调用堆栈: \n    ' + getStackShort());
        return uuid;
    };
    
    //===== 2. 监控Android ID =====
    var Secure = Java.use('android.provider.Settings$Secure');
    Secure.getString.implementation = function (resolver, name) {
        var value = this.getString(resolver, name);
        
        // 检测ANDROID_ID获取
        if (name === 'android_id') {
            console.log('[*] 获取ANDROID_ID: ' + value);
            console.log('    标识符类型: 应用安装标识符 (重装应用会改变)');
            console.log('    调用堆栈: \n    ' + getStackShort());
            
            // 如果ANDROID_ID为null或为0，可能是模拟器或新安装
            if (!value || value === "9774d56d682e549c" || value === "0") {
                console.log('    [!] 警告: 检测到可能的模拟器ANDROID_ID或全新设备');
            }
        }
        
        return value;
    };
    
    //===== 3. 监控TelephonyManager相关标识符 =====
    var TelephonyManager = Java.use('android.telephony.TelephonyManager');
    
    // getDeviceId() - 获取IMEI (Android 10以下)
    if (TelephonyManager.getDeviceId) {
        try {
            // 无参数版本
            TelephonyManager.getDeviceId.overload().implementation = function () {
                var imei;
                try {
                    imei = this.getDeviceId();
                } catch (e) {
                    imei = "<需要权限或API已弃用>";
                }
                console.log('[*] 获取IMEI(getDeviceId): ' + imei);
                console.log('    标识符类型: 硬件标识符 (设备唯一)');
                console.log('    调用堆栈: \n    ' + getStackShort());
                return imei;
            };
            
            // 带槽位参数版本 (Android 6.0+)
            if (TelephonyManager.getDeviceId.overload('int')) {
                TelephonyManager.getDeviceId.overload('int').implementation = function (slotIndex) {
                    var imei;
                    try {
                        imei = this.getDeviceId(slotIndex);
                    } catch (e) {
                        imei = "<需要权限或API已弃用>";
                    }
                    console.log('[*] 获取IMEI(getDeviceId), 卡槽: ' + slotIndex + ', 值: ' + imei);
                    console.log('    标识符类型: 硬件标识符 (设备唯一)');
                    console.log('    调用堆栈: \n    ' + getStackShort());
                    return imei;
                };
            }
        } catch (e) {
            console.log("[-] getDeviceId监控失败: " + e);
        }
    }
    
    // getImei() - 获取IMEI (Android 8.0+)
    if (TelephonyManager.getImei) {
        try {
            // 无参数版本
            TelephonyManager.getImei.overload().implementation = function () {
                var imei;
                try {
                    imei = this.getImei();
                } catch (e) {
                    imei = "<需要权限>";
                }
                console.log('[*] 获取IMEI(getImei): ' + imei);
                console.log('    标识符类型: 硬件标识符 (设备唯一)');
                console.log('    调用堆栈: \n    ' + getStackShort());
                return imei;
            };
            
            // 带槽位参数版本
            if (TelephonyManager.getImei.overload('int')) {
                TelephonyManager.getImei.overload('int').implementation = function (slotIndex) {
                    var imei;
                    try {
                        imei = this.getImei(slotIndex);
                    } catch (e) {
                        imei = "<需要权限>";
                    }
                    console.log('[*] 获取IMEI(getImei), 卡槽: ' + slotIndex + ', 值: ' + imei);
                    console.log('    标识符类型: 硬件标识符 (设备唯一)');
                    console.log('    调用堆栈: \n    ' + getStackShort());
                    return imei;
                };
            }
        } catch (e) {
            console.log("[-] getImei监控失败: " + e);
        }
    }
    
    // getMeid() - 获取MEID (Android 8.0+)
    if (TelephonyManager.getMeid) {
        try {
            // 无参数版本
            TelephonyManager.getMeid.overload().implementation = function () {
                var meid;
                try {
                    meid = this.getMeid();
                } catch (e) {
                    meid = "<需要权限>";
                }
                console.log('[*] 获取MEID: ' + meid);
                console.log('    标识符类型: 硬件标识符 (CDMA设备唯一)');
                console.log('    调用堆栈: \n    ' + getStackShort());
                return meid;
            };
            
            // 带槽位参数版本
            if (TelephonyManager.getMeid.overload('int')) {
                TelephonyManager.getMeid.overload('int').implementation = function (slotIndex) {
                    var meid;
                    try {
                        meid = this.getMeid(slotIndex);
                    } catch (e) {
                        meid = "<需要权限>";
                    }
                    console.log('[*] 获取MEID, 卡槽: ' + slotIndex + ', 值: ' + meid);
                    console.log('    标识符类型: 硬件标识符 (CDMA设备唯一)');
                    console.log('    调用堆栈: \n    ' + getStackShort());
                    return meid;
                };
            }
        } catch (e) {
            console.log("[-] getMeid监控失败: " + e);
        }
    }
    
    // getSubscriberId() - 获取IMSI
    if (TelephonyManager.getSubscriberId) {
        try {
            TelephonyManager.getSubscriberId.overload().implementation = function () {
                var imsi;
                try {
                    imsi = this.getSubscriberId();
                } catch (e) {
                    imsi = "<需要权限>";
                }
                console.log('[*] 获取IMSI: ' + imsi);
                console.log('    标识符类型: SIM卡标识符 (用户唯一)');
                console.log('    调用堆栈: \n    ' + getStackShort());
                return imsi;
            };
        } catch (e) {
            console.log("[-] getSubscriberId监控失败: " + e);
        }
    }
    
    // getSimSerialNumber() - 获取SIM卡序列号
    if (TelephonyManager.getSimSerialNumber) {
        try {
            TelephonyManager.getSimSerialNumber.overload().implementation = function () {
                var simSerial;
                try {
                    simSerial = this.getSimSerialNumber();
                } catch (e) {
                    simSerial = "<需要权限>";
                }
                console.log('[*] 获取SIM卡序列号: ' + simSerial);
                console.log('    标识符类型: SIM卡标识符 (用户唯一)');
                console.log('    调用堆栈: \n    ' + getStackShort());
                return simSerial;
            };
        } catch (e) {
            console.log("[-] getSimSerialNumber监控失败: " + e);
        }
    }
    
    //===== 4. 监控系统序列号等硬件标识符 =====
    var Build = Java.use('android.os.Build');
    
    // 监控Build.SERIAL
    var buildSerialValue = Build.SERIAL.value;
    Build.SERIAL.value = buildSerialValue;
    
    Object.defineProperty(Build, 'SERIAL', {
        get: function() {
            console.log('[*] 读取Build.SERIAL: ' + buildSerialValue);
            console.log('    标识符类型: 系统硬件标识符 (设备唯一)');
            console.log('    调用堆栈: \n    ' + getStackShort());
            return buildSerialValue;
        },
        set: function(value) {
            console.log('[*] 修改Build.SERIAL: ' + value);
            buildSerialValue = value;
        }
    });
    
    // 监控Build.getSerial() (Android 8.0+)
    try {
        if (Build.getSerial) {
            Build.getSerial.implementation = function () {
                var serial;
                try {
                    serial = this.getSerial();
                } catch (e) {
                    serial = "<需要权限>";
                }
                console.log('[*] Build.getSerial(): ' + serial);
                console.log('    标识符类型: 系统硬件标识符 (设备唯一)');
                console.log('    调用堆栈: \n    ' + getStackShort());
                return serial;
            };
        }
    } catch (e) {}
    
    //===== 5. 监控MAC地址获取 =====
    try {
        // WiFi MAC地址
        var WifiInfo = Java.use('android.net.wifi.WifiInfo');
        WifiInfo.getMacAddress.implementation = function () {
            var mac = this.getMacAddress();
            console.log('[*] 获取WiFi MAC地址: ' + mac);
            console.log('    标识符类型: 网络硬件标识符 (设备唯一)');
            console.log('    调用堆栈: \n    ' + getStackShort());
            return mac;
        };
        
        // WifiManager获取MAC地址
        var WifiManager = Java.use('android.net.wifi.WifiManager');
        if (WifiManager.getConnectionInfo) {
            var original_getConnectionInfo = WifiManager.getConnectionInfo;
            WifiManager.getConnectionInfo.implementation = function () {
                var wifiInfo = original_getConnectionInfo.call(this);
                // 不直接输出，因为在getMacAddress钩子中会捕获
                return wifiInfo;
            };
        }
        
        // 监控通过反射或特殊方法获取实际MAC地址的行为
        try {
            var NetworkInterface = Java.use('java.net.NetworkInterface');
            NetworkInterface.getHardwareAddress.implementation = function () {
                var mac = this.getHardwareAddress();
                if (mac != null) {
                    var macHex = "";
                    for (var i = 0; i < mac.length; i++) {
                        var byteStr = (mac[i] & 0xFF).toString(16);
                        if (byteStr.length < 2) byteStr = "0" + byteStr;
                        if (i < mac.length - 1) byteStr += ":";
                        macHex += byteStr;
                    }
                    console.log('[*] 通过NetworkInterface获取硬件地址: ' + macHex);
                    console.log('    网络接口名称: ' + this.getName());
                    console.log('    标识符类型: 网络硬件标识符 (设备唯一)');
                    console.log('    调用堆栈: \n    ' + getStackShort());
                }
                return mac;
            };
            
            NetworkInterface.getNetworkInterfaces.implementation = function () {
                var interfaces = this.getNetworkInterfaces();
                console.log('[*] 获取所有网络接口列表');
                console.log('    调用堆栈: \n    ' + getStackShort());
                return interfaces;
            };
        } catch (e) {
            console.log("[-] NetworkInterface监控失败: " + e);
        }
    } catch (e) {
        console.log("[-] WiFi相关API监控失败: " + e);
    }
    
    //===== 6. 监控GooglePlay服务的广告ID获取 =====
    try {
        var AdvertisingIdClient = Java.use('com.google.android.gms.ads.identifier.AdvertisingIdClient');
        AdvertisingIdClient.getAdvertisingIdInfo.implementation = function (context) {
            var adInfo = this.getAdvertisingIdInfo(context);
            console.log('[*] 获取广告ID信息');
            
            // 尝试提取广告ID
            if (adInfo) {
                try {
                    var adId = adInfo.getId();
                    var isLimitAdTrackingEnabled = adInfo.isLimitAdTrackingEnabled();
                    console.log('    广告ID: ' + adId);
                    console.log('    限制广告追踪: ' + isLimitAdTrackingEnabled);
                    console.log('    标识符类型: 广告追踪标识符 (可重置)');
                } catch (e) {
                    console.log('    无法读取广告ID: ' + e);
                }
            }
            
            console.log('    调用堆栈: \n    ' + getStackShort());
            return adInfo;
        };
        
        var AdvertisingIdClientInfo = Java.use('com.google.android.gms.ads.identifier.AdvertisingIdClient$Info');
        if (AdvertisingIdClientInfo) {
            AdvertisingIdClientInfo.getId.implementation = function () {
                var adId = this.getId();
                console.log('[*] 读取广告ID: ' + adId);
                console.log('    标识符类型: 广告追踪标识符 (可重置)');
                console.log('    调用堆栈: \n    ' + getStackShort());
                return adId;
            };
        }
    } catch (e) {
        // GooglePlay服务可能不可用
    }
    
    //===== 7. 监控移动安全联盟OAID/匿名设备标识符 =====
    try {
        // 中国移动安全联盟OAID
        var classes = [
            "com.bun.miitmdid.core.MdidSdkHelper",    // 1.0版本
            "com.bun.miitmdid.core.MsaIdHelper",      // 2.0版本
            "com.bun.supplier.IIdentifierListener",   // 监听器接口
            "com.umeng.umsdk.oaid.UMOAIDHelper",      // 友盟OAID封装
            "com.baidu.mobads.aaid.OaidHelper",       // 百度OAID封装
            "com.kwai.kaid.sdk.KwaiOaidManager"       // 快手OAID封装
        ];
        
        for (var i = 0; i < classes.length; i++) {
            try {
                var clazz = Java.use(classes[i]);
                
                if (clazz) {
                    console.log('[+] 检测到OAID相关类: ' + classes[i]);
                    
                    var methods = clazz.class.getDeclaredMethods();
                    for (var j = 0; j < methods.length; j++) {
                        var methodName = methods[j].getName();
                        if (methodName.toLowerCase().indexOf("oaid") !== -1 || 
                            methodName.toLowerCase().indexOf("deviceid") !== -1 || 
                            methodName.toLowerCase().indexOf("getid") !== -1) {
                            console.log('    发现可能的OAID获取方法: ' + methodName);
                        }
                    }
                    
                    // 尝试挂钩一些通用方法
                    try {
                        if (clazz.getOAID) {
                            clazz.getOAID.implementation = function () {
                                var oaid = this.getOAID();
                                console.log('[*] 获取OAID: ' + oaid);
                                console.log('    标识符类型: 厂商联盟标识符 (可重置)');
                                console.log('    调用堆栈: \n    ' + getStackShort());
                                return oaid;
                            };
                        }
                    } catch (e) {}
                }
            } catch (e) {}
        }
    } catch (e) {
        // OAID SDK可能不存在
    }
    
    //===== 8. 监控SharedPreferences存储标识符 =====
    try {
        var SharedPreferences = Java.use('android.content.SharedPreferences');
        var Editor = Java.use('android.content.SharedPreferences$Editor');
        
        // 监控读取可能的设备标识符
        SharedPreferences.getString.implementation = function (key, defValue) {
            var value = this.getString(key, defValue);
            
            // 检测可能是标识符的键名
            if (key && (
                key.toLowerCase().indexOf("uuid") !== -1 ||
                key.toLowerCase().indexOf("device") !== -1 ||
                key.toLowerCase().indexOf("id") !== -1 ||
                key.toLowerCase().indexOf("identifier") !== -1)
            ) {
                console.log('[*] 从SharedPreferences读取可能的标识符');
                console.log('    键名: ' + key);
                console.log('    值: ' + value);
                console.log('    标识符类型: 应用存储标识符 (应用卸载后丢失)');
                console.log('    调用堆栈: \n    ' + getStackShort());
            }
            
            return value;
        };
        
        // 监控写入可能的设备标识符
        Editor.putString.implementation = function (key, value) {
            // 检测可能是标识符的键名和值
            if (key && (
                key.toLowerCase().indexOf("uuid") !== -1 ||
                key.toLowerCase().indexOf("device") !== -1 ||
                key.toLowerCase().indexOf("id") !== -1 ||
                key.toLowerCase().indexOf("identifier") !== -1) &&
                value && value.length > 8
            ) {
                console.log('[*] 向SharedPreferences写入可能的标识符');
                console.log('    键名: ' + key);
                console.log('    值: ' + value);
                console.log('    标识符类型: 应用存储标识符 (应用卸载后丢失)');
                console.log('    调用堆栈: \n    ' + getStackShort());
            }
            
            return this.putString(key, value);
        };
    } catch (e) {
        console.log("[-] SharedPreferences监控失败: " + e);
    }
    
    //===== 9. 监控常见广告/统计SDK =====
    // 尝试监控一些常见的第三方统计SDK
    var sdkPrefixes = [
        "com.umeng",          // 友盟
        "com.appsflyer",      // AppsFlyer
        "com.adjust",         // Adjust
        "com.talkingdata",    // TalkingData
        "com.kochava",        // Kochava
        "com.igexin",         // 个推
        "cn.jpush",           // 极光推送
        "com.google.firebase.analytics", // Firebase分析
        "com.facebook.appevents"         // Facebook事件
    ];
    
    try {
        // 使用Java的ClassLoader查找可能加载的类
        var DexClassLoader = Java.use("dalvik.system.DexClassLoader");
        var PathClassLoader = Java.use("dalvik.system.PathClassLoader");
        
        // 通用的loadClass方法监控
        var loadClassMethod = function(className) {
            try {
                // 检查是否是我们感兴趣的SDK类
                for (var i = 0; i < sdkPrefixes.length; i++) {
                    if (className.startsWith(sdkPrefixes[i])) {
                        console.log('[+] 检测到第三方统计/广告SDK类: ' + className);
                        console.log('    调用堆栈: \n    ' + getStackShort());
                        break;
                    }
                }
                
                if (className.toLowerCase().indexOf("deviceid") !== -1 ||
                    className.toLowerCase().indexOf("identifier") !== -1 ||
                    className.toLowerCase().indexOf("fingerprint") !== -1 ||
                    className.toLowerCase().indexOf("uuid") !== -1) {
                    console.log('[!] 检测到可能与设备标识相关的类: ' + className);
                    console.log('    调用堆栈: \n    ' + getStackShort());
                }
            } catch (e) {}
            
            // 调用原始方法
            var result;
            try {
                result = this.loadClass.apply(this, arguments);
            } catch (err) {
                throw err;
            }
            return result;
        };
        
        // 挂钩不同类型的ClassLoader
        if (DexClassLoader.loadClass) {
            DexClassLoader.loadClass.implementation = loadClassMethod;
        }
        
        if (PathClassLoader.loadClass) {
            PathClassLoader.loadClass.implementation = loadClassMethod;
        }
    } catch (e) {
        console.log("[-] ClassLoader监控失败: " + e);
    }
    
    console.log("[*] UUID生成监控已启动");
    console.log("[*] 监控范围扩展: UUID, ANDROID_ID, IMEI/MEID, IMSI, Build.SERIAL");
    console.log("[*] 监控范围扩展: MAC地址, 广告ID, OAID, SharedPreferences存储标识符");
    console.log("[*] 监控范围扩展: 常见第三方统计/广告SDK");
}); 