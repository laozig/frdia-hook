/*
 * Frida全功能Hook框架使用示例
 * 
 * 本文件展示如何针对特定应用场景使用Frida框架
 * 包含多种实用场景和定制化监控方法
 */

/**
 * ================== 使用方法详解 ==================
 * 
 * 【环境准备】
 * 1. 安装Frida命令行工具: npm install -g frida-tools
 * 2. 在Android设备上安装frida-server:
 *    - 下载对应版本: https://github.com/frida/frida/releases
 *    - 推送到设备: adb push frida-server /data/local/tmp/
 *    - 设置权限: adb shell "chmod 755 /data/local/tmp/frida-server"
 *    - 启动服务: adb shell "/data/local/tmp/frida-server &"
 *
 * 【启动方式】
 * 1. 标准注入方式
 *    frida -U -l examples/usage_example.js -f com.target.package --no-pause
 * 
 * 2. 附加到运行中的进程
 *    frida -U -l examples/usage_example.js -p <进程ID>
 *    
 * 3. 远程设备注入 (通过TCP连接)
 *    frida -H 192.168.1.x:27042 -l examples/usage_example.js -f com.target.package
 *
 * 4. 持久化注入 (系统范围内)
 *    frida --file examples/usage_example.js --runtime=v8 --persist
 *
 * 【脚本使用说明】
 * - 本脚本包含多个使用场景示例，根据需要选择合适的部分
 * - 默认情况下，脚本会同时监控多种功能（加密、网络请求等）
 * - 可以注释掉不需要的功能部分以提高性能
 * - 支持动态开关监控功能（见脚本最后部分的条件监控示例）
 *
 * 【功能模块说明】
 * 1. 加密监控 - 监控应用中的加密/解密操作
 * 2. 网络监控 - 监控HTTP/HTTPS请求和响应
 * 3. 数据库操作 - 监控SQLite数据库读写
 * 4. JWT令牌提取 - 识别并解析JWT格式授权令牌
 * 5. 反调试绕过 - 绕过应用的安全检测机制
 * 6. 条件监控 - 根据特定条件激活/关闭监控
 *
 * 【自定义配置】
 * - 可修改各监控函数的参数，定制监控行为
 * - 可结合其他Frida模块使用，例如dex_dumper.js
 * - 可修改日志输出格式和内容
 *
 * 【使用场景】
 * - 安全研究：分析应用安全机制和潜在漏洞
 * - 逆向工程：理解应用内部工作原理
 * - 功能扩展：修改或增强应用行为
 * - 兼容性测试：模拟不同环境下的应用行为
 */

// 1. 基本使用 - 直接加载主文件
/*
 * 最简单的使用方式，直接加载主文件即可启用所有功能
 * 命令: frida -U -f com.example.app -l frida_master.js --no-pause
 * 
 * 说明:
 * -U: 使用USB连接的设备
 * -f: 指定以spawn方式启动的应用包名
 * --no-pause: 注入后不暂停应用执行
 */

// 2. 自定义配置 - 修改frida_master.js中的配置
/*
 * // 示例: 在frida_master.js中修改配置
 * var config = {
 *     logLevel: 'debug',         // 改为debug以获取更详细日志
 *     fileLogging: true,         // 启用文件日志记录
 *     logFilePath: '/sdcard/custom_frida_log.txt',  // 自定义日志路径
 *     autoExtractKeys: true,     // 自动提取密钥
 *     bypassAllDetection: true,  // 绕过所有检测机制
 *     colorOutput: true,         // 彩色输出
 *     stackTrace: true           // 启用调用栈跟踪
 * };
 * 
 * 配置说明:
 * - logLevel: 设置日志级别，可选值有'info', 'debug', 'warn', 'error'
 * - fileLogging: 是否将日志保存到文件
 * - logFilePath: 日志文件保存路径
 * - autoExtractKeys: 是否自动提取加密密钥
 * - bypassAllDetection: 是否绕过所有检测（反调试、反注入等）
 * - colorOutput: 是否使用彩色输出日志
 * - stackTrace: 是否显示调用栈信息
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
 * 
 * 说明:
 * - 这种方式可以只加载需要的模块，减少内存占用和对应用性能的影响
 * - 特别适合只关注特定功能（如网络请求或加密操作）的分析场景
 * - 可以根据具体需求自由组合不同的功能模块
 */

// 4. 针对特定API监控的自定义脚本示例

// 4.1 监控特定类的所有加密相关方法
/*
 * 此示例展示如何监控应用中特定加密类的所有相关方法
 * 适用于分析自定义加密算法或关注特定安全实现的场景
 */
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
/*
 * 此示例展示如何监控针对特定域名的所有网络请求
 * 适用于只关注与特定服务器通信的应用分析场景
 */
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
/*
 * 此示例展示如何从应用的SharedPreferences中提取敏感信息
 * 适用于分析应用本地存储的API密钥、令牌等场景
 */
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
/*
 * 此示例展示如何绕过应用的签名校验机制
 * 适用于绕过反重新打包保护、证书绑定等安全机制
 */
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
// 以下是一些实用的工具函数，可以在脚本中重复使用

// 十六进制转换工具函数
/**
 * 将字节数组转换为十六进制字符串
 * @param {byte[]} bytes - 要转换的字节数组
 * @return {string} 十六进制字符串表示
 */
function bytesToHex(bytes) {
    var hex = '';
    for (var i = 0; i < bytes.length; i++) {
        hex += ('0' + (bytes[i] & 0xFF).toString(16)).slice(-2);
    }
    return hex;
}

// Base64编码工具函数
/**
 * 将字符串转换为Base64编码
 * @param {string} str - 要编码的字符串
 * @return {string} Base64编码后的字符串，或失败时返回null
 */
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
/**
 * 获取完整的异常堆栈信息
 * @param {java.lang.Exception} exception - 异常对象，如不提供则创建新异常
 * @return {string} 格式化的堆栈跟踪信息
 */
function getFullStackTrace(exception) {
    var Log = Java.use("android.util.Log");
    var Exception = Java.use("java.lang.Exception");
    
    if (!exception) {
        exception = Exception.$new();
    }
    
    return Log.getStackTraceString(exception);
}

// 6. 特定场景示例：只提取JWT Token
/**
 * 此示例展示如何仅从网络请求中提取JWT令牌
 * 适用于只关注身份验证和授权机制的安全分析
 */
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
        
        // 检查请求体中的JSON数据
        try {
            var RequestBody = Java.use("okhttp3.RequestBody");
            var Buffer = Java.use("okio.Buffer");
            
            // 如果有writeTo方法，通常意味着它是一个RequestBody
            if (RequestBody.writeTo) {
                var oldWriteTo = RequestBody.writeTo.overload("okio.BufferedSink");
                
                oldWriteTo.implementation = function(sink) {
                    try {
                        // 复制请求体内容到缓冲区
                        var buffer = Buffer.$new();
                        this.writeTo(buffer);
                        var content = buffer.readUtf8();
                        
                        // 检查JSON中的token
                    for (var i = 0; i < patterns.length; i++) {
                            var matches = patterns[i].exec(content);
                        if (matches && matches.length > 1) {
                                console.log("[*] 在请求体中发现JWT Token: " + matches[1]);
                                
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
                    } catch (e) {
                        console.log("[-] 检查请求体时出错: " + e);
                    }
                    
                    // 调用原始方法
                    return oldWriteTo.call(this, sink);
                };
            }
        } catch (e) {
            console.log("[-] Hook请求体失败: " + e);
        }
        
        console.log("[+] JWT Token提取器已设置");
    } catch (e) {
        console.log("[-] JWT Token提取器设置失败: " + e);
    }
});

/**
 * 解码JWT令牌的Base64部分
 * @param {string} str - JWT令牌的Base64编码部分
 * @return {string} 解码后的字符串
 */
function decodeJWT(str) {
    // 补全Base64填充
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    switch (str.length % 4) {
        case 0:
            break;
        case 2:
            str += "==";
            break;
        case 3:
            str += "=";
            break;
        default:
            throw "非法Base64字符串长度";
    }
    
    try {
        // 使用Android的Base64解码
        var Base64 = Java.use("android.util.Base64");
        var decoded = Base64.decode(str, 0);
        return Java.use("java.lang.String").$new(decoded, "UTF-8");
    } catch (e) {
        console.log("[-] Base64解码失败: " + e);
        return "";
    }
}

// 7. 监控SQLite数据库操作
/**
 * 此示例展示如何监控应用的SQLite数据库操作
 * 适用于分析应用数据存储和处理的场景
 */
Java.perform(function() {
    try {
        // 监控数据库查询
        var SQLiteDatabase = Java.use("android.database.sqlite.SQLiteDatabase");
        
        // 监控insert操作
        SQLiteDatabase.insert.overload('java.lang.String', 'java.lang.String', 'android.content.ContentValues').implementation = function(table, nullColumnHack, values) {
            console.log("[*] 数据库插入操作:");
            console.log("    表: " + table);
            
            // 打印要插入的值
            if (values) {
                var keySet = values.keySet();
                var keys = keySet.toArray();
                for (var i = 0; i < keys.length; i++) {
                    var key = keys[i];
                    console.log("    " + key + " = " + values.get(key));
                }
            }
            
            // 获取调用栈跟踪
            console.log("    调用栈: " + getFullStackTrace().split("\n")[2]);
            
            return this.insert(table, nullColumnHack, values);
        };
        
        // 监控查询操作
        var queryMethods = ["query", "rawQuery"];
        queryMethods.forEach(function(method) {
            SQLiteDatabase[method].overloads.forEach(function(overload) {
                overload.implementation = function() {
                    var sql = "";
                    var args = [];
                    
                    // 提取SQL语句和参数
                    if (arguments[0]) {
                        if (typeof arguments[0] === "string") {
                            sql = arguments[0];
                        } else if (method === "query") {
                            sql = "SELECT * FROM " + arguments[0]; // 表名
                        }
                    }
                    
                    // 提取查询参数
                    if (arguments[1] && Array.isArray(arguments[1])) {
                        args = arguments[1];
                    }
                    
                    console.log("[*] 数据库查询:");
                    console.log("    SQL: " + sql);
                    if (args.length > 0) {
                        console.log("    参数: " + args.join(", "));
                    }
                    
                    var cursor = overload.apply(this, arguments);
                    console.log("    结果行数: " + (cursor ? cursor.getCount() : 0));
                    
                    return cursor;
                };
            });
        });
        
        console.log("[+] SQLite数据库监控已设置");
    } catch (e) {
        console.log("[-] SQLite数据库监控设置失败: " + e);
    }
});

// 8. 辅助功能: 仅在特定情况下激活监控
/**
 * 此示例展示如何在特定条件满足时才激活监控
 * 可以避免长时间监控导致的性能问题和日志过多
 */
Java.perform(function() {
    // 创建一个激活标志
    var monitoringActive = false;
    
    // 激活/停用监控的函数
    function toggleMonitoring(active) {
        monitoringActive = active;
        console.log("[*] 监控状态: " + (monitoringActive ? "已激活" : "已停用"));
    }
    
    // 在特定Activity创建时激活监控
    try {
        var targetActivity = "com.example.app.PaymentActivity";
        var Activity = Java.use(targetActivity);
        
        Activity.onCreate.overload('android.os.Bundle').implementation = function(bundle) {
            console.log("[+] 检测到目标Activity启动，激活监控");
            toggleMonitoring(true);
            return this.onCreate(bundle);
        };
        
        Activity.onDestroy.implementation = function() {
            console.log("[+] 检测到目标Activity销毁，停用监控");
            toggleMonitoring(false);
            return this.onDestroy();
        };
        
        // 下面是一个使用激活标志的监控实例
        var HttpURLConnection = Java.use("java.net.HttpURLConnection");
        HttpURLConnection.getOutputStream.implementation = function() {
            var stream = this.getOutputStream();
            
            // 仅在监控激活时记录
            if (monitoringActive) {
                console.log("[*] 发起HTTP请求: " + this.getURL().toString());
                console.log("    方法: " + this.getRequestMethod());
            }
            
            return stream;
        };
        
        console.log("[+] 条件监控已设置");
    } catch (e) {
        console.log("[-] 条件监控设置失败: " + e);
    }
});

console.log("[+] Frida全功能Hook框架 - 使用示例脚本已加载"); 