/*
 * Frida全功能Hook框架使用示例
 * 
 * 本文件展示如何针对特定应用场景使用Frida框架
 */

// 1. 基本使用 - 直接加载主文件
/*
 * 最简单的使用方式，直接加载主文件即可启用所有功能
 * 命令: frida -U -f com.example.app -l frida_master.js --no-pause
 */

// 2. 自定义配置 - 修改frida_master.js中的配置
/*
 * // 示例: 在frida_master.js中修改配置
 * var config = {
 *     logLevel: 'debug',         // 改为debug以获取更详细日志
 *     fileLogging: true,
 *     logFilePath: '/sdcard/custom_frida_log.txt',  // 自定义日志路径
 *     autoExtractKeys: true,
 *     bypassAllDetection: true,
 *     colorOutput: true,
 *     stackTrace: true           // 启用调用栈跟踪
 * };
 */

// 3. 场景示例: 只需加密监控和网络监控功能
/*
 * // 在frida_master.js中的loadModules()函数中注释掉不需要的模块
 * function loadModules() {
 *     require('./modules/crypto_monitor.js')(config, logger, utils);
 *     require('./modules/network_monitor.js')(config, logger, utils);
 *     // 注释掉不需要的模块
 *     // require('./modules/anti_debug.js')(config, logger, utils);
 *     // require('./modules/sensitive_api.js')(config, logger, utils);
 *     // require('./modules/auto_extractor.js')(config, logger, utils);
 * }
 */

// 4. 针对特定API监控的自定义脚本示例

// 4.1 监控特定类的所有加密相关方法
Java.perform(function() {
    try {
        // 假设我们要监控应用中的CustomEncryptionUtil类
        var CustomEncryptionUtil = Java.use("com.example.app.security.CustomEncryptionUtil");
        
        // 获取所有方法
        var methods = CustomEncryptionUtil.class.getDeclaredMethods();
        methods.forEach(function(method) {
            var methodName = method.getName();
            
            // 检查是否是加密相关方法
            if (methodName.indexOf("encrypt") !== -1 || 
                methodName.indexOf("decrypt") !== -1 || 
                methodName.indexOf("hash") !== -1) {
                
                // 监控所有重载
                CustomEncryptionUtil[methodName].overloads.forEach(function(overload) {
                    overload.implementation = function() {
                        console.log("[*] 调用 " + methodName);
                        
                        // 打印参数
                        for (var i = 0; i < arguments.length; i++) {
                            console.log("    参数" + i + ": " + arguments[i]);
                        }
                        
                        // 调用原方法
                        var ret = this[methodName].apply(this, arguments);
                        
                        // 打印返回值
                        console.log("    返回: " + ret);
                        return ret;
                    };
                });
            }
        });
        
        console.log("[+] 已监控 CustomEncryptionUtil 的所有加密方法");
    } catch (e) {
        console.log("[-] 监控失败: " + e);
    }
});

// 4.2 监控网络请求中特定域名
Java.perform(function() {
    try {
        var URL = Java.use("java.net.URL");
        URL.$init.overload('java.lang.String').implementation = function(url) {
            // 检查是否包含特定域名
            if (url.indexOf("api.example.com") !== -1) {
                console.log("[*] 检测到目标域名请求: " + url);
                
                // 获取调用栈以分析请求来源
                console.log(Java.use("android.util.Log").getStackTraceString(
                    Java.use("java.lang.Exception").$new()
                ));
            }
            return this.$init(url);
        };
        
        console.log("[+] 已设置URL监控");
    } catch (e) {
        console.log("[-] URL监控设置失败: " + e);
    }
});

// 4.3 提取特定SharedPreferences中的密钥
Java.perform(function() {
    try {
        // 监控SharedPreferences访问
        var SharedPreferences = Java.use("android.content.SharedPreferences");
        SharedPreferences.getString.implementation = function(key, defValue) {
            var value = this.getString(key, defValue);
            
            // 检查是否访问特定配置文件中的敏感键值
            if (key.indexOf("api_key") !== -1 || 
                key.indexOf("auth_token") !== -1 || 
                key.indexOf("secret") !== -1) {
                
                console.log("[*] 提取到密钥:");
                console.log("    键: " + key);
                console.log("    值: " + value);
                
                // 获取SharedPreferences文件名
                // 注意: 这种方法不一定在所有版本Android上都有效
                try {
                    var obj = this.toString();
                    var match = /\w+\.xml/.exec(obj);
                    if (match) {
                        console.log("    文件: " + match[0]);
                    }
                } catch (e) {
                    // 忽略错误
                }
            }
            
            return value;
        };
        
        console.log("[+] 已设置SharedPreferences监控");
    } catch (e) {
        console.log("[-] SharedPreferences监控设置失败: " + e);
    }
});

// 4.4 绕过特定的签名检测
Java.perform(function() {
    try {
        var PackageManager = Java.use("android.content.pm.PackageManager");
        PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function(packageName, flags) {
            var packageInfo = this.getPackageInfo(packageName, flags);
            
            // 检查是否在获取签名
            if ((flags & 0x40) !== 0) { // GET_SIGNATURES = 0x40
                console.log("[*] 应用正在检查签名: " + packageName);
                
                // 这里可以替换为有效的签名，或者不做修改
                // 如果需要替换，可以使用Java.array('java.lang.Signature', [...])创建签名数组
            }
            
            return packageInfo;
        };
        
        console.log("[+] 已设置签名检测绕过");
    } catch (e) {
        console.log("[-] 签名检测绕过设置失败: " + e);
    }
});

// 5. 将通用工具函数与框架结合使用

// 十六进制转换工具函数
function bytesToHex(bytes) {
    var hex = '';
    for (var i = 0; i < bytes.length; i++) {
        hex += ('0' + (bytes[i] & 0xFF).toString(16)).slice(-2);
    }
    return hex;
}

// Base64编码工具函数
function base64Encode(str) {
    try {
        if (Java.available) {
            var Base64 = Java.use("android.util.Base64");
            var strBytes = [];
            for (var i = 0; i < str.length; i++) {
                strBytes.push(str.charCodeAt(i));
            }
            var javaBytes = Java.array('byte', strBytes);
            return Base64.encodeToString(javaBytes, 0);
        }
    } catch (e) {
        console.log("[-] Base64编码失败: " + e);
    }
    return null;
}

// 提取完整异常堆栈
function getFullStackTrace(exception) {
    var Log = Java.use("android.util.Log");
    var Exception = Java.use("java.lang.Exception");
    
    if (!exception) {
        exception = Exception.$new();
    }
    
    return Log.getStackTraceString(exception);
}

// 6. 特定场景示例：只提取JWT Token

Java.perform(function() {
    try {
        // 查找请求中的JWT Token
        var patterns = [
            /Bearer\s+([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)/,  // Authorization 头
            /"token"\s*:\s*"([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)"/  // JSON中的token字段
        ];
        
        // Hook OkHttp的请求构建
        var Request$Builder = Java.use("okhttp3.Request$Builder");
        Request$Builder.build.implementation = function() {
            var request = this.build();
            var headers = request.headers();
            
            // 检查Authorization头
            var authHeader = headers.get("Authorization");
            if (authHeader) {
                for (var i = 0; i < patterns.length; i++) {
                    var matches = patterns[i].exec(authHeader);
                    if (matches && matches.length > 1) {
                        console.log("[*] 发现JWT Token: " + matches[1]);
                        
                        // 分析JWT的各部分
                        var parts = matches[1].split(".");
                        if (parts.length === 3) {
                            try {
                                // 解码头部和负载
                                var header = JSON.parse(decodeJWT(parts[0]));
                                var payload = JSON.parse(decodeJWT(parts[1]));
                                
                                console.log("    头部: " + JSON.stringify(header));
                                console.log("    负载: " + JSON.stringify(payload));
                            } catch (e) {
                                console.log("    JWT解析错误: " + e);
                            }
                        }
                    }
                }
            }
            
            return request;
        };
        
        // Hook StringRequest以检查请求体
        try {
            var StringRequest = Java.use("com.android.volley.toolbox.StringRequest");
            StringRequest.deliverResponse.implementation = function(response) {
                // 检查响应中是否包含JWT
                if (response) {
                    for (var i = 0; i < patterns.length; i++) {
                        var matches = patterns[i].exec(response);
                        if (matches && matches.length > 1) {
                            console.log("[*] 响应中发现JWT Token: " + matches[1]);
                        }
                    }
                }
                
                return this.deliverResponse(response);
            };
        } catch (e) {
            // Volley可能不在应用中
        }
        
        console.log("[+] JWT Token提取器已设置");
    } catch (e) {
        console.log("[-] JWT Token提取器设置失败: " + e);
    }
});

// JWT解码辅助函数
function decodeJWT(str) {
    // Base64 URL解码
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    var padding = str.length % 4;
    if (padding) {
        str += '===='.slice(padding);
    }
    
    // 使用atob解码
    var decoded = '';
    try {
        decoded = Java.use('java.lang.String').$new(
            Java.use('android.util.Base64').decode(str, 0)
        ).toString();
    } catch (e) {
        // 回退到简单解码
        console.log("Base64解码失败，使用简单解码");
        var base64chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
        var result = '';
        var bits = 0, bitcount = 0;
        
        for (var i = 0; i < str.length; i++) {
            if (str[i] === '=') continue;
            var index = base64chars.indexOf(str[i]);
            if (index < 0) continue;
            
            bits = (bits << 6) | index;
            bitcount += 6;
            
            if (bitcount >= 8) {
                bitcount -= 8;
                result += String.fromCharCode((bits >> bitcount) & 0xff);
                bits &= (1 << bitcount) - 1;
            }
        }
        
        decoded = result;
    }
    
    return decoded;
}

console.log("[+] Frida全功能Hook框架 - 使用示例脚本已加载"); 