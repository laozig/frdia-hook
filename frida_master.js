/**
 * Frida全功能Hook框架主入口文件
 * 支持Frida 14.0.0及以上版本
 */

// 配置参数
var config = {
    logLevel: 'info',           // 日志级别: debug, info, warn, error
    fileLogging: false,         // 是否保存日志到文件，默认关闭
    logFilePath: '/data/local/tmp/frida_log.txt',  // 日志文件路径，修改为一个通常可写的位置
    modulesPath: null,          // 设为null，我们将直接内联模块代码
    autoExtractKeys: true,      // 自动提取加密密钥
    bypassAllDetection: true,   // 绕过所有检测机制
    colorOutput: true,          // 控制台彩色输出
    stackTrace: false,          // 打印调用栈
    fridaCompatMode: false,     // Frida 14.x兼容模式
    fridaVersion: null          // 存储检测到的Frida版本号
};

// 检测Frida版本并设置兼容模式
function checkFridaVersion() {
    try {
        // 尝试获取Frida版本
        var fridaVersion = null;
        
        // 不同版本的Frida获取版本的方式可能不同
        if (typeof Frida !== 'undefined' && Frida.version) {
            fridaVersion = Frida.version;
        } else if (typeof Process !== 'undefined' && Process.id) {
            // 在某些14.x版本中可能需要使用替代方法
            console.log('[*] 使用替代方法检测Frida版本');
            // 在这种情况下，我们无法准确获取版本，默认使用兼容模式
            config.fridaCompatMode = true;
            fridaVersion = "14.x (推测)";
        }
        
        if (typeof fridaVersion === 'string') {
            config.fridaVersion = fridaVersion; // 存储版本号
            var versionParts = fridaVersion.split('.');
            if (versionParts.length >= 2) {
                var majorVersion = parseInt(versionParts[0]);
                if (majorVersion < 15) {
                    console.log('[*] 检测到Frida版本: ' + fridaVersion + '，启用兼容模式');
                    config.fridaCompatMode = true;
                } else {
                    console.log('[*] 检测到Frida版本: ' + fridaVersion);
                }
            }
        }
    } catch (e) {
        // 如果无法获取版本，假设需要兼容模式
        console.log('[*] 无法检测Frida版本，默认启用兼容模式: ' + e);
        config.fridaCompatMode = true;
    }
}

// 日志系统
var logger = {
    debug: function(tag, message) {
        if (config.logLevel === 'debug') {
            var logMessage = '[' + getCurrentTime() + '][DEBUG] (' + tag + ') ' + message;
            console.log(config.colorOutput ? '\x1b[90m' + logMessage + '\x1b[0m' : logMessage);
            if (config.fileLogging) {
                appendToLogFile('[DEBUG] (' + tag + ') ' + message);
            }
        }
    },
    
    info: function(tag, message) {
        if (config.logLevel === 'debug' || config.logLevel === 'info') {
            var logMessage = '[' + getCurrentTime() + '][INFO] (' + tag + ') ' + message;
            console.log(config.colorOutput ? '\x1b[32m' + logMessage + '\x1b[0m' : logMessage);
            if (config.fileLogging) {
                appendToLogFile('[INFO] (' + tag + ') ' + message);
            }
        }
    },
    
    warn: function(tag, message) {
        if (config.logLevel === 'debug' || config.logLevel === 'info' || config.logLevel === 'warn') {
            var logMessage = '[' + getCurrentTime() + '][WARN] (' + tag + ') ' + message;
            console.log(config.colorOutput ? '\x1b[33m' + logMessage + '\x1b[0m' : logMessage);
            if (config.fileLogging) {
                appendToLogFile('[WARN] (' + tag + ') ' + message);
            }
        }
    },
    
    error: function(tag, message) {
        var logMessage = '[' + getCurrentTime() + '][ERROR] (' + tag + ') ' + message;
        console.log(config.colorOutput ? '\x1b[31m' + logMessage + '\x1b[0m' : logMessage);
        if (config.fileLogging) {
            appendToLogFile('[ERROR] (' + tag + ') ' + message);
        }
    }
};

// 工具函数
var utils = {
    hexdump: function(array) {
        if (config.fridaCompatMode) {
            // Frida 14.x兼容模式下的hexdump实现
            try {
                return hexdump(array);
            } catch (e) {
                // 14.x中某些hexdump调用可能有问题，提供备选方案
                var result = '';
                var length = (typeof array.length !== 'undefined') ? array.length : 16;
                for (var i = 0; i < length; i += 16) {
                    var line = '';
                    var hex = '';
                    var ascii = '';
                    
                    for (var j = 0; j < 16; j++) {
                        if (i + j < length) {
                            var value = (typeof array.readU8 === 'function') ? 
                                        array.readU8(i + j) : 
                                        ((typeof array[i + j] !== 'undefined') ? array[i + j] : 0);
                            
                            hex += padLeft(value.toString(16), 2, '0') + ' ';
                            ascii += (value >= 32 && value <= 126) ? String.fromCharCode(value) : '.';
                        } else {
                            hex += '   ';
                            ascii += ' ';
                        }
                    }
                    
                    line = padLeft(i.toString(16), 8, '0') + '  ' + hex + ' |' + ascii + '|';
                    result += line + '\n';
                }
                return result;
            }
        } else {
            // 标准hexdump
            return hexdump(array);
        }
    },
    
    bytesToString: function(bytes) {
        if (!bytes) return '';
        return String.fromCharCode.apply(null, bytes);
    },
    
    stringToBytes: function(str) {
        if (!str) return [];
        var bytes = [];
        for (var i = 0; i < str.length; i++) {
            bytes.push(str.charCodeAt(i));
        }
        return bytes;
    },
    
    getStackTrace: function() {
        if (config.stackTrace) {
            // 兼容不同版本的获取栈方法
            try {
                return Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n');
            } catch (e) {
                try {
                    return Thread.backtrace(this.context, Backtracer.FUZZY).map(DebugSymbol.fromAddress).join('\n');
                } catch (e2) {
                    // 在Frida 14.x中，某些API可能不可用或有不同签名
                    if (config.fridaCompatMode) {
                        try {
                            // 尝试简化版本的栈跟踪
                            return Thread.backtrace(this.context, 'fuzzy').map(DebugSymbol.fromAddress).join('\n');
                        } catch (e3) {
                            return 'Stack trace unavailable in compatibility mode: ' + e3;
                        }
                    }
                    return 'Stack trace unavailable: ' + e2;
                }
            }
        }
        return '';
    },
    
    // 14.x兼容性函数 - 内存读写
    readMemory: function(address, size) {
        if (config.fridaCompatMode) {
            try {
                // 在兼容模式下使用替代方法读取内存
                var buffer = Memory.alloc(size);
                Memory.copy(buffer, ptr(address), size);
                return buffer.readByteArray(size);
            } catch (e) {
                logger.error('UTILS', '兼容模式下内存读取失败: ' + e);
                return new Uint8Array(0);
            }
        } else {
            // 标准方法
            return Memory.readByteArray(ptr(address), size);
        }
    },
    
    // 版本兼容性检查
    isCompatibilityRequired: function(featureName) {
        // 检查特定功能是否需要兼容性处理
        return config.fridaCompatMode; 
    }
};

// 辅助函数
function getCurrentTime() {
    var now = new Date();
    var hours = padLeft(now.getHours(), 2, '0');
    var minutes = padLeft(now.getMinutes(), 2, '0');
    var seconds = padLeft(now.getSeconds(), 2, '0');
    return hours + ':' + minutes + ':' + seconds;
}

function padLeft(str, length, char) {
    str = String(str);
    char = char || ' ';
    while (str.length < length) {
        str = char + str;
    }
    return str;
}

// 写入日志文件
function appendToLogFile(message) {
    try {
        var file = new File(config.logFilePath, 'a');
        file.write(getCurrentTime() + ' ' + message + '\n');
        file.flush();
        file.close();
    } catch (e) {
        console.log('[ERROR] 写入日志文件失败: ' + e);
    }
}

// 创建日志文件
function createLogFile() {
    try {
        var file = new File(config.logFilePath, 'w');
        file.write('=== Frida Hook框架日志 - ' + new Date().toISOString() + ' ===\n');
        file.flush();
        file.close();
        logger.info('SYSTEM', '日志文件已创建: ' + config.logFilePath);
        return true;
    } catch (e) {
        console.log('[ERROR] 创建日志文件失败: ' + e);
        // 无法创建日志文件时禁用文件日志
        config.fileLogging = false;
        return false;
    }
}

// 模块定义 - 内联代码
var modules = {
    // 反调试模块
    anti_debug: function(config, logger, utils) {
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
        if (Java.available) {
            Java.perform(function() {
                try {
                    // 1. Debug.isDebuggerConnected()
                    var Debug = Java.use("android.os.Debug");
                    Debug.isDebuggerConnected.implementation = function() {
                        recordBypass("反调试", "Debug.isDebuggerConnected");
                        return false;
                    };
                    
                    // 2. System.exit绕过
                    var System = Java.use("java.lang.System");
                    System.exit.implementation = function(status) {
                        recordBypass("反调试", "System.exit(" + status + ")");
                        logger.warn(tag, "应用尝试退出，已阻止: System.exit(" + status + ")");
                        // 不调用原方法，阻止退出
                    };
                    
                    logger.info(tag, "Java层反调试绕过设置完成");
                } catch (e) {
                    logger.error(tag, "Java层反调试绕过失败: " + e);
                }
            });
        } else {
            logger.warn(tag, "Java环境不可用，跳过Java层反调试");
        }
        
        // 尝试绕过Native层检测
        try {
            // 绕过ptrace
            Interceptor.replace(Module.findExportByName(null, "ptrace"), new NativeCallback(function(request, pid, addr, data) {
                if (request == 31) { // PTRACE_ATTACH
                    recordBypass("Native反调试", "ptrace(PTRACE_ATTACH)");
                    return -1;
                }
                
                // 调用原始函数
                var ptr_ptrace = Module.findExportByName(null, "ptrace");
                var ptrace = new NativeFunction(ptr_ptrace, 'long', ['int', 'int', 'pointer', 'pointer']);
                return ptrace(request, pid, addr, data);
            }, 'long', ['int', 'int', 'pointer', 'pointer']));
            
            logger.info(tag, "Native层ptrace绕过设置完成");
        } catch (e) {
            logger.error(tag, "Native层绕过失败: " + e);
        }
        
        logger.info(tag, "反调试绕过模块加载完成");
        return {
            bypassedChecks: bypassedChecks
        };
    },
    
    // 加密监控模块
    crypto_monitor: function(config, logger, utils) {
        var tag = "CRYPTO";
        logger.info(tag, "加密监控模块初始化");
        console.log("[*] 加密监控模块初始化");
        
        // 存储加密信息
        var keyStore = {
            keys: {}
        };
        
        // 开始Hook加密相关API
        if (Java.available) {
            Java.perform(function() {
                console.log("[+] 开始监控加密操作...");
                
                // 通用工具函数
                var ByteString;
                try {
                    ByteString = Java.use("com.android.okhttp.okio.ByteString");
                } catch (e) {
                    try {
                        ByteString = Java.use("okio.ByteString");
                    } catch (e2) {
                        console.log("[!] ByteString类不存在，将使用内置方法");
                    }
                }
                
                function toBase64(tag, data) {
                    try {
                        if (ByteString) {
                            console.log(tag + " Base64: ", ByteString.of(data).base64());
                        } else {
                            // 内置实现
                            var base64 = Java.use("android.util.Base64");
                            console.log(tag + " Base64: ", base64.encodeToString(data, 0));
                        }
                    } catch (e) {
                        console.log(tag + " Base64转换失败: " + e);
                    }
                }
                
                function toHex(tag, data) {
                    try {
                        if (ByteString) {
                            console.log(tag + " Hex: ", ByteString.of(data).hex());
                        } else {
                            // 内置实现
                            var result = "";
                            for (var i = 0; i < data.length; i++) {
                                var val = (data[i] & 0xFF).toString(16);
                                if (val.length == 1) val = "0" + val;
                                result += val;
                            }
                            console.log(tag + " Hex: ", result);
                        }
                    } catch (e) {
                        console.log(tag + " Hex转换失败: " + e);
                    }
                }
                
                function toUtf8(tag, data) {
                    try {
                        if (ByteString) {
                            console.log(tag + " Utf8: ", ByteString.of(data).utf8());
                        } else {
                            // 内置实现
                            try {
                                var str = "";
                                for (var i = 0; i < data.length; i++) {
                                    var c = data[i];
                                    if (c >= 32 && c <= 126) { // 可打印ASCII字符
                                        str += String.fromCharCode(c);
                                    } else {
                                        str += ".";
                                    }
                                }
                                console.log(tag + " Utf8: ", str);
                            } catch (e) {
                                console.log(tag + " Utf8转换失败: " + e);
                            }
                        }
                    } catch (e) {
                        console.log(tag + " Utf8转换失败: " + e);
                    }
                }
                
                function showStacks() {
                    try {
                        console.log(
                            Java.use("android.util.Log")
                                .getStackTraceString(
                                    Java.use("java.lang.Throwable").$new()
                                )
                        );
                    } catch (e) {
                        console.log("[!] 获取调用栈失败: " + e);
                    }
                }
                
                try {
                    // 1. 监控MessageDigest (哈希函数)
                    var messageDigest = Java.use("java.security.MessageDigest");
                    
                    messageDigest.update.overload('byte').implementation = function (data) {
                        console.log("MessageDigest.update('byte') is called!");
                        return this.update(data);
                    }
                    
                    messageDigest.update.overload('java.nio.ByteBuffer').implementation = function (data) {
                        console.log("MessageDigest.update('java.nio.ByteBuffer') is called!");
                        return this.update(data);
                    }
                    
                    messageDigest.update.overload('[B').implementation = function (data) {
                        console.log("MessageDigest.update('[B') is called!");
                        var algorithm = this.getAlgorithm();
                        var tag = algorithm + " update data";
                        toUtf8(tag, data);
                        toHex(tag, data);
                        toBase64(tag, data);
                        console.log("=======================================================");
                        return this.update(data);
                    }
                    
                    messageDigest.update.overload('[B', 'int', 'int').implementation = function (data, start, length) {
                        console.log("MessageDigest.update('[B', 'int', 'int') is called!");
                        var algorithm = this.getAlgorithm();
                        var tag = algorithm + " update data";
                        toUtf8(tag, data);
                        toHex(tag, data);
                        toBase64(tag, data);
                        console.log("=======================================================", start, length);
                        return this.update(data, start, length);
                    }
                    
                    messageDigest.digest.overload().implementation = function () {
                        console.log("MessageDigest.digest() is called!");
                        var result = this.digest();
                        var algorithm = this.getAlgorithm();
                        var tag = algorithm + " digest result";
                        toHex(tag, result);
                        toBase64(tag, result);
                        console.log("=======================================================");
                        return result;
                    }
                    
                    messageDigest.digest.overload('[B').implementation = function (data) {
                        console.log("MessageDigest.digest('[B') is called!");
                        var algorithm = this.getAlgorithm();
                        var tag = algorithm + " digest data";
                        toUtf8(tag, data);
                        toHex(tag, data);
                        toBase64(tag, data);
                        var result = this.digest(data);
                        var tags = algorithm + " digest result";
                        toHex(tags, result);
                        toBase64(tags, result);
                        console.log("=======================================================");
                        return result;
                    }
                    
                    messageDigest.digest.overload('[B', 'int', 'int').implementation = function (data, start, length) {
                        console.log("MessageDigest.digest('[B', 'int', 'int') is called!");
                        var algorithm = this.getAlgorithm();
                        var tag = algorithm + " digest data";
                        toUtf8(tag, data);
                        toHex(tag, data);
                        toBase64(tag, data);
                        var result = this.digest(data, start, length);
                        var tags = algorithm + " digest result";
                        toHex(tags, result);
                        toBase64(tags, result);
                        console.log("=======================================================", start, length);
                        return result;
                    }
                    
                    console.log("[*] 已Hook MessageDigest");
                    
                    // 2. 监控Mac
                    var mac = Java.use("javax.crypto.Mac");
                    
                    mac.init.overload('java.security.Key', 'java.security.spec.AlgorithmParameterSpec').implementation = function (key, AlgorithmParameterSpec) {
                        console.log("Mac.init('java.security.Key', 'java.security.spec.AlgorithmParameterSpec') is called!");
                        return this.init(key, AlgorithmParameterSpec);
                    }
                    
                    mac.init.overload('java.security.Key').implementation = function (key) {
                        console.log("Mac.init('java.security.Key') is called!");
                        var algorithm = this.getAlgorithm();
                        var tag = algorithm + " init Key";
                        var keyBytes = key.getEncoded();
                        toUtf8(tag, keyBytes);
                        toHex(tag, keyBytes);
                        toBase64(tag, keyBytes);
                        console.log("=======================================================");
                        return this.init(key);
                    }
                    
                    mac.update.overload('byte').implementation = function (data) {
                        console.log("Mac.update('byte') is called!");
                        return this.update(data);
                    }
                    
                    mac.update.overload('java.nio.ByteBuffer').implementation = function (data) {
                        console.log("Mac.update('java.nio.ByteBuffer') is called!");
                        return this.update(data);
                    }
                    
                    mac.update.overload('[B').implementation = function (data) {
                        console.log("Mac.update('[B') is called!");
                        var algorithm = this.getAlgorithm();
                        var tag = algorithm + " update data";
                        toUtf8(tag, data);
                        toHex(tag, data);
                        toBase64(tag, data);
                        console.log("=======================================================");
                        return this.update(data);
                    }
                    
                    mac.update.overload('[B', 'int', 'int').implementation = function (data, start, length) {
                        console.log("Mac.update('[B', 'int', 'int') is called!");
                        var algorithm = this.getAlgorithm();
                        var tag = algorithm + " update data";
                        toUtf8(tag, data);
                        toHex(tag, data);
                        toBase64(tag, data);
                        console.log("=======================================================", start, length);
                        return this.update(data, start, length);
                    }
                    
                    mac.doFinal.overload().implementation = function () {
                        console.log("Mac.doFinal() is called!");
                        var result = this.doFinal();
                        var algorithm = this.getAlgorithm();
                        var tag = algorithm + " doFinal result";
                        toHex(tag, result);
                        toBase64(tag, result);
                        console.log("=======================================================");
                        return result;
                    }
                    
                    console.log("[*] 已Hook Mac");
                    
                    // 3. 监控Cipher
                    var cipher = Java.use("javax.crypto.Cipher");
                    
                    // 所有的init重载
                    cipher.init.overload('int', 'java.security.cert.Certificate').implementation = function () {
                        console.log("Cipher.init('int', 'java.security.cert.Certificate') is called!");
                        return this.init.apply(this, arguments);
                    }
                    
                    cipher.init.overload('int', 'java.security.Key', 'java.security.SecureRandom').implementation = function () {
                        console.log("Cipher.init('int', 'java.security.Key', 'java.security.SecureRandom') is called!");
                        return this.init.apply(this, arguments);
                    }
                    
                    cipher.init.overload('int', 'java.security.cert.Certificate', 'java.security.SecureRandom').implementation = function () {
                        console.log("Cipher.init('int', 'java.security.cert.Certificate', 'java.security.SecureRandom') is called!");
                        return this.init.apply(this, arguments);
                    }
                    
                    cipher.init.overload('int', 'java.security.Key', 'java.security.AlgorithmParameters', 'java.security.SecureRandom').implementation = function () {
                        console.log("Cipher.init('int', 'java.security.Key', 'java.security.AlgorithmParameters', 'java.security.SecureRandom') is called!");
                        return this.init.apply(this, arguments);
                    }
                    
                    cipher.init.overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec', 'java.security.SecureRandom').implementation = function () {
                        console.log("Cipher.init('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec', 'java.security.SecureRandom') is called!");
                        return this.init.apply(this, arguments);
                    }
                    
                    cipher.init.overload('int', 'java.security.Key', 'java.security.AlgorithmParameters').implementation = function () {
                        console.log("Cipher.init('int', 'java.security.Key', 'java.security.AlgorithmParameters') is called!");
                        return this.init.apply(this, arguments);
                    }
                    
                    cipher.init.overload('int', 'java.security.Key').implementation = function () {
                        console.log("Cipher.init('int', 'java.security.Key') is called!");
                        var algorithm = this.getAlgorithm();
                        var tag = algorithm + " init Key";
                        var className = JSON.stringify(arguments[1]);
                        if(className.indexOf("OpenSSLRSAPrivateKey") === -1){
                            var keyBytes = arguments[1].getEncoded();
                            toUtf8(tag, keyBytes);
                            toHex(tag, keyBytes);
                            toBase64(tag, keyBytes);
                        }
                        console.log("=======================================================");
                        return this.init.apply(this, arguments);
                    }
                    
                    cipher.init.overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec').implementation = function () {
                        console.log("Cipher.init('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec') is called!");
                        var algorithm = this.getAlgorithm();
                        var tag = algorithm + " init Key";
                        var keyBytes = arguments[1].getEncoded();
                        toUtf8(tag, keyBytes);
                        toHex(tag, keyBytes);
                        toBase64(tag, keyBytes);
                        var tags = algorithm + " init iv";
                        try {
                            var iv = Java.cast(arguments[2], Java.use("javax.crypto.spec.IvParameterSpec"));
                            var ivBytes = iv.getIV();
                            toUtf8(tags, ivBytes);
                            toHex(tags, ivBytes);
                            toBase64(tags, ivBytes);
                        } catch (e) {
                            console.log("[!] 获取IV失败: " + e);
                        }
                        console.log("=======================================================");
                        return this.init.apply(this, arguments);
                    }
                    
                    // 所有的doFinal重载
                    cipher.doFinal.overload('java.nio.ByteBuffer', 'java.nio.ByteBuffer').implementation = function () {
                        console.log("Cipher.doFinal('java.nio.ByteBuffer', 'java.nio.ByteBuffer') is called!");
                        return this.doFinal.apply(this, arguments);
                    }
                    
                    cipher.doFinal.overload('[B', 'int').implementation = function () {
                        console.log("Cipher.doFinal('[B', 'int') is called!");
                        return this.doFinal.apply(this, arguments);
                    }
                    
                    cipher.doFinal.overload('[B', 'int', 'int', '[B').implementation = function () {
                        console.log("Cipher.doFinal('[B', 'int', 'int', '[B') is called!");
                        return this.doFinal.apply(this, arguments);
                    }
                    
                    cipher.doFinal.overload('[B', 'int', 'int', '[B', 'int').implementation = function () {
                        console.log("Cipher.doFinal('[B', 'int', 'int', '[B', 'int') is called!");
                        return this.doFinal.apply(this, arguments);
                    }
                    
                    cipher.doFinal.overload().implementation = function () {
                        console.log("Cipher.doFinal() is called!");
                        return this.doFinal.apply(this, arguments);
                    }
                    
                    cipher.doFinal.overload('[B').implementation = function () {
                        console.log("Cipher.doFinal('[B') is called!");
                        var algorithm = this.getAlgorithm();
                        var tag = algorithm + " doFinal data";
                        var data = arguments[0];
                        toUtf8(tag, data);
                        toHex(tag, data);
                        toBase64(tag, data);
                        var result = this.doFinal.apply(this, arguments);
                        var tags = algorithm + " doFinal result";
                        toHex(tags, result);
                        toBase64(tags, result);
                        console.log("=======================================================");
                        return result;
                    }
                    
                    cipher.doFinal.overload('[B', 'int', 'int').implementation = function () {
                        console.log("Cipher.doFinal('[B', 'int', 'int') is called!");
                        var algorithm = this.getAlgorithm();
                        var tag = algorithm + " doFinal data";
                        var data = arguments[0];
                        toUtf8(tag, data);
                        toHex(tag, data);
                        toBase64(tag, data);
                        var result = this.doFinal.apply(this, arguments);
                        var tags = algorithm + " doFinal result";
                        toHex(tags, result);
                        toBase64(tags, result);
                        console.log("=======================================================", arguments[1], arguments[2]);
                        return result;
                    }
                    
                    console.log("[*] 已Hook Cipher");
                    
                    // 4. 监控Signature
                    var signature = Java.use("java.security.Signature");
                    
                    signature.update.overload('byte').implementation = function (data) {
                        console.log("Signature.update('byte') is called!");
                        return this.update(data);
                    }
                    
                    signature.update.overload('java.nio.ByteBuffer').implementation = function (data) {
                        console.log("Signature.update('java.nio.ByteBuffer') is called!");
                        return this.update(data);
                    }
                    
                    signature.update.overload('[B', 'int', 'int').implementation = function (data, start, length) {
                        console.log("Signature.update('[B', 'int', 'int') is called!");
                        var algorithm = this.getAlgorithm();
                        var tag = algorithm + " update data";
                        toUtf8(tag, data);
                        toHex(tag, data);
                        toBase64(tag, data);
                        console.log("=======================================================", start, length);
                        return this.update(data, start, length);
                    }
                    
                    signature.sign.overload('[B', 'int', 'int').implementation = function () {
                        console.log("Signature.sign('[B', 'int', 'int') is called!");
                        return this.sign.apply(this, arguments);
                    }
                    
                    signature.sign.overload().implementation = function () {
                        console.log("Signature.sign() is called!");
                        var result = this.sign();
                        var algorithm = this.getAlgorithm();
                        var tag = algorithm + " sign result";
                        toHex(tag, result);
                        toBase64(tag, result);
                        console.log("=======================================================");
                        return result;
                    }
                    
                    console.log("[*] 已Hook Signature");
                    
                    // 5. 监控SecretKeySpec
                    var SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
                    SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function(keyBytes, algorithm) {
                        console.log("\n[+] 创建密钥 - 算法: " + algorithm);
                        toUtf8("SecretKeySpec", keyBytes);
                        toHex("SecretKeySpec", keyBytes);
                        toBase64("SecretKeySpec", keyBytes);
                        console.log("=======================================================");
                        return this.$init(keyBytes, algorithm);
                    };
                    
                    // 6. 监控IvParameterSpec
                    var IvParameterSpec = Java.use("javax.crypto.spec.IvParameterSpec");
                    IvParameterSpec.$init.overload('[B').implementation = function(ivBytes) {
                        console.log("\n[+] 创建IV参数");
                        toHex("IvParameterSpec", ivBytes);
                        toBase64("IvParameterSpec", ivBytes);
                        console.log("=======================================================");
                        return this.$init(ivBytes);
                    };
                    
                    // 7. 监控Base64
                    try {
                        var Base64 = Java.use("android.util.Base64");
                        
                        Base64.encodeToString.overload('[B', 'int').implementation = function(input, flags) {
                            var result = this.encodeToString(input, flags);
                            console.log("\n[+] Base64编码");
                            toUtf8("Base64 原始数据", input);
                            toHex("Base64 原始数据", input);
                            console.log("Base64 结果: " + result);
                            console.log("=======================================================");
                            return result;
                        };
                        
                        Base64.decode.overload('java.lang.String', 'int').implementation = function(input, flags) {
                            var result = this.decode(input, flags);
                            console.log("\n[+] Base64解码");
                            console.log("Base64 输入: " + input);
                            toUtf8("Base64 解码结果", result);
                            toHex("Base64 解码结果", result);
                            console.log("=======================================================");
                            return result;
                        };
                        
                        console.log("[*] 已Hook Base64");
                    } catch (e) {
                        console.log("[!] 无法Hook Base64: " + e);
                    }
                    
                    console.log("[+] 加密监控设置完成");
                } catch (e) {
                    console.log("[!] 加密监控设置失败: " + e);
                }
            });
        } else {
            console.log("[!] Java环境不可用，跳过加密监控");
        }
        
        logger.info(tag, "加密监控模块加载完成");
        return {
            keyStore: keyStore
        };
    },
    
    // 网络监控模块
    network_monitor: function(config, logger, utils) {
        var tag = "NETWORK";
        logger.info(tag, "网络监控模块初始化");
        
        if (Java.available) {
            Java.perform(function() {
                try {
                    // 监控URL连接 - 修复重载问题
                    var URL = Java.use("java.net.URL");
                    
                    // 处理无参数的openConnection重载
                    URL.openConnection.overload().implementation = function() {
                        var url = this.toString();
                        logger.info(tag, "URL连接: " + url);
                        console.log("\n[+] URL连接: " + url);
                        return this.openConnection();
                    };
                    
                    // 处理带Proxy参数的openConnection重载
                    try {
                        URL.openConnection.overload('java.net.Proxy').implementation = function(proxy) {
                            var url = this.toString();
                            logger.info(tag, "URL连接(带代理): " + url);
                            console.log("\n[+] URL连接(带代理): " + url);
                            return this.openConnection(proxy);
                        };
                    } catch (e) {
                        logger.debug(tag, "URL.openConnection(Proxy)重载不存在: " + e);
                    }
                    
                    // 监控HttpURLConnection
                    var HttpURLConnection = Java.use("java.net.HttpURLConnection");
                    HttpURLConnection.connect.implementation = function() {
                        try {
                            var url = this.getURL().toString();
                            var method = this.getRequestMethod();
                            logger.info(tag, method + " " + url);
                            console.log("\n[+] HTTP请求: " + method + " " + url);
                            
                            // 获取请求头
                            var headers = {};
                            var headerFields = this.getRequestProperties();
                            if (headerFields) {
                                var it = headerFields.keySet().iterator();
                                while(it.hasNext()) {
                                    var key = it.next();
                                    var value = headerFields.get(key);
                                    if (key && value) {
                                        headers[key] = value.toString();
                                    }
                                }
                                logger.info(tag, "请求头: " + JSON.stringify(headers));
                                console.log("[+] 请求头: " + JSON.stringify(headers));
                            }
                            
                            return this.connect();
                        } catch (e) {
                            logger.error(tag, "获取请求信息失败: " + e);
                            return this.connect();
                        }
                    };
                    
                    // 监控OkHttp (如果存在)
                    try {
                        // 尝试监控OkHttp3
                        var OkHttpClient = null;
                        try {
                            OkHttpClient = Java.use("okhttp3.OkHttpClient");
                            logger.info(tag, "检测到OkHttp3");
                            
                            var Request = Java.use("okhttp3.Request");
                            var Request$Builder = Java.use("okhttp3.Request$Builder");
                            
                            Request$Builder.build.implementation = function() {
                                var request = this.build();
                                var url = request.url().toString();
                                var method = request.method();
                                logger.info(tag, "OkHttp3请求: " + method + " " + url);
                                console.log("\n[+] OkHttp3请求: " + method + " " + url);
                                return request;
                            };
                            
                            logger.info(tag, "已Hook OkHttp3");
                        } catch (e) {
                            logger.debug(tag, "未检测到OkHttp3: " + e);
                            
                            // 尝试监控OkHttp2
                            try {
                                OkHttpClient = Java.use("com.squareup.okhttp.OkHttpClient");
                                logger.info(tag, "检测到OkHttp2");
                                
                                var Request = Java.use("com.squareup.okhttp.Request");
                                var Request$Builder = Java.use("com.squareup.okhttp.Request$Builder");
                                
                                Request$Builder.build.implementation = function() {
                                    var request = this.build();
                                    var url = request.urlString();
                                    var method = request.method();
                                    logger.info(tag, "OkHttp2请求: " + method + " " + url);
                                    console.log("\n[+] OkHttp2请求: " + method + " " + url);
                                    return request;
                                };
                                
                                logger.info(tag, "已Hook OkHttp2");
                            } catch (e2) {
                                logger.debug(tag, "未检测到OkHttp2: " + e2);
                            }
                        }
                    } catch (e) {
                        logger.debug(tag, "OkHttp监控失败: " + e);
                    }
                    
                    logger.info(tag, "已Hook网络相关类");
                } catch (e) {
                    logger.error(tag, "网络监控Hook失败: " + e);
                }
            });
        } else {
            logger.warn(tag, "Java环境不可用，跳过网络监控");
        }
        
        logger.info(tag, "网络监控模块加载完成");
        return {};
    },
    
    // 敏感API监控模块
    sensitive_api: function(config, logger, utils) {
        var tag = "SENSITIVE";
        logger.info(tag, "敏感API监控模块初始化");
        
        if (Java.available) {
            Java.perform(function() {
                try {
                    // 监控定位API
                    var LocationManager = Java.use("android.location.LocationManager");
                    LocationManager.getLastKnownLocation.implementation = function(provider) {
                        logger.info(tag, "获取位置: getLastKnownLocation(" + provider + ")");
                        console.log("\n[+] 获取位置: getLastKnownLocation(" + provider + ")");
                        return this.getLastKnownLocation(provider);
                    };
                    
                    // 监控相机API
                    try {
                        var Camera = Java.use("android.hardware.Camera");
                        Camera.open.overload('int').implementation = function(cameraId) {
                            logger.info(tag, "相机打开: Camera.open(" + cameraId + ")");
                            console.log("\n[+] 相机打开: Camera.open(" + cameraId + ")");
                            return this.open(cameraId);
                        };
                        
                        // 尝试监控无参数的open方法
                        try {
                            Camera.open.overload().implementation = function() {
                                logger.info(tag, "相机打开: Camera.open()");
                                console.log("\n[+] 相机打开: Camera.open()");
                                return this.open();
                            };
                        } catch (e) {
                            logger.debug(tag, "Camera.open()重载不存在: " + e);
                        }
                    } catch (e) {
                        logger.debug(tag, "相机Hook失败: " + e);
                        
                        // 尝试监控Camera2 API (Android 5.0+)
                        try {
                            var CameraManager = Java.use("android.hardware.camera2.CameraManager");
                            CameraManager.openCamera.overload('java.lang.String', 'android.hardware.camera2.CameraDevice$StateCallback', 'android.os.Handler').implementation = function(cameraId, callback, handler) {
                                logger.info(tag, "相机2打开: CameraManager.openCamera(" + cameraId + ")");
                                console.log("\n[+] 相机2打开: CameraManager.openCamera(" + cameraId + ")");
                                return this.openCamera(cameraId, callback, handler);
                            };
                        } catch (e2) {
                            logger.debug(tag, "Camera2 API Hook失败: " + e2);
                        }
                    }
                    
                    // 监控联系人API - 修复重载问题
                    try {
                        var ContentResolver = Java.use("android.content.ContentResolver");
                        
                        // 获取ContentResolver的所有query重载
                        var queryOverloads = ContentResolver.query.overloads;
                        
                        // 遍历并Hook所有重载
                        queryOverloads.forEach(function(overload) {
                            overload.implementation = function() {
                                var uri = arguments[0];
                                var uriStr = uri.toString();
                                
                                // 检查是否是敏感URI
                                if (uriStr.indexOf("contacts") >= 0 || 
                                    uriStr.indexOf("call_log") >= 0 || 
                                    uriStr.indexOf("sms") >= 0 || 
                                    uriStr.indexOf("mms") >= 0) {
                                    
                                    logger.info(tag, "敏感数据查询: " + uriStr);
                                    console.log("\n[+] 敏感数据查询: " + uriStr);
                                    
                                    // 尝试获取查询条件
                                    try {
                                        var selection = null;
                                        // 大多数重载在第3个参数有selection
                                        if (arguments.length > 2) {
                                            selection = arguments[2];
                                            if (selection) {
                                                logger.info(tag, "查询条件: " + selection);
                                                console.log("[+] 查询条件: " + selection);
                                            }
                                        }
                                    } catch (e) {
                                        logger.debug(tag, "获取查询条件失败: " + e);
                                    }
                                }
                                
                                // 调用原始方法
                                return this.query.apply(this, arguments);
                            };
                        });
                        
                        logger.info(tag, "已Hook ContentResolver.query的所有重载");
                    } catch (e) {
                        logger.error(tag, "ContentResolver Hook失败: " + e);
                    }
                    
                    // 监控麦克风
                    try {
                        var AudioRecord = Java.use("android.media.AudioRecord");
                        AudioRecord.startRecording.implementation = function() {
                            logger.info(tag, "麦克风录音: AudioRecord.startRecording()");
                            console.log("\n[+] 麦克风录音: AudioRecord.startRecording()");
                            return this.startRecording();
                        };
                    } catch (e) {
                        logger.debug(tag, "麦克风Hook失败: " + e);
                    }
                    
                    // 监控电话号码
                    try {
                        var TelephonyManager = Java.use("android.telephony.TelephonyManager");
                        
                        // 监控获取手机号
                        TelephonyManager.getLine1Number.implementation = function() {
                            var result = this.getLine1Number();
                            logger.info(tag, "获取手机号: " + result);
                            console.log("\n[+] 获取手机号: " + result);
                            return result;
                        };
                        
                        // 监控获取设备ID
                        TelephonyManager.getDeviceId.overload().implementation = function() {
                            var result = this.getDeviceId();
                            logger.info(tag, "获取设备ID: " + result);
                            console.log("\n[+] 获取设备ID: " + result);
                            return result;
                        };
                        
                        // 监控获取IMEI
                        try {
                            TelephonyManager.getImei.overload().implementation = function() {
                                var result = this.getImei();
                                logger.info(tag, "获取IMEI: " + result);
                                console.log("\n[+] 获取IMEI: " + result);
                                return result;
                            };
                        } catch (e) {
                            logger.debug(tag, "getImei()方法不存在: " + e);
                        }
                    } catch (e) {
                        logger.debug(tag, "电话信息Hook失败: " + e);
                    }
                    
                    logger.info(tag, "已Hook敏感API相关类");
                } catch (e) {
                    logger.error(tag, "敏感API监控Hook失败: " + e);
                }
            });
        } else {
            logger.warn(tag, "Java环境不可用，跳过敏感API监控");
        }
        
        logger.info(tag, "敏感API监控模块加载完成");
        return {};
    },
    
    // 自动提取器模块
    auto_extractor: function(config, logger, utils) {
        var tag = "EXTRACTOR";
        logger.info(tag, "自动提取器模块初始化");
        
        // 自动提取功能仅在启用时执行
        if (!config.autoExtractKeys) {
            logger.info(tag, "自动提取功能未开启，跳过");
            return {};
        }
        
        logger.info(tag, "自动提取器模块加载完成");
        return {};
    },
    
    // 系统API监控模块
    system_api_monitor: function(config, logger, utils) {
        var tag = "SYSTEM_API";
        logger.info(tag, "系统API监控模块初始化");
        
        if (Java.available) {
            Java.perform(function() {
                try {
                    // 监控剪贴板
                    var ClipboardManager = Java.use("android.content.ClipboardManager");
                    ClipboardManager.setPrimaryClip.implementation = function(clip) {
                        try {
                            var clipText = clip.getItemAt(0).getText();
                            logger.info(tag, "剪贴板写入: " + clipText);
                        } catch (e) {
                            logger.debug(tag, "读取剪贴板内容失败: " + e);
                        }
                        return this.setPrimaryClip(clip);
                    };
                    
                    // 监控SharedPreferences
                    var SharedPreferencesEditor = Java.use("android.app.SharedPreferencesImpl$EditorImpl");
                    SharedPreferencesEditor.putString.implementation = function(key, value) {
                        logger.info(tag, "SharedPreferences写入: " + key + " = " + value);
                        return this.putString(key, value);
                    };
                    
                    logger.info(tag, "已Hook系统API相关类");
                } catch (e) {
                    logger.error(tag, "系统API监控Hook失败: " + e);
                }
            });
        } else {
            logger.warn(tag, "Java环境不可用，跳过系统API监控");
        }
        
        logger.info(tag, "系统API监控模块加载完成");
        return {};
    },
    
    // DEX脱壳模块
    dex_dumper: function(config, logger, utils) {
        var tag = "DEX_DUMPER";
        logger.info(tag, "DEX脱壳模块初始化");
        
        if (Java.available) {
            Java.perform(function() {
                try {
                    // 监控DEX加载
                    var DexClassLoader = Java.use("dalvik.system.DexClassLoader");
                    DexClassLoader.$init.implementation = function(dexPath, optimizedDirectory, librarySearchPath, parent) {
                        logger.info(tag, "DEX加载: " + dexPath);
                        logger.info(tag, "优化目录: " + optimizedDirectory);
                        return this.$init(dexPath, optimizedDirectory, librarySearchPath, parent);
                    };
                    
                    logger.info(tag, "已Hook DEX相关类");
                } catch (e) {
                    logger.error(tag, "DEX脱壳模块Hook失败: " + e);
                }
            });
        } else {
            logger.warn(tag, "Java环境不可用，跳过DEX脱壳");
        }
        
        logger.info(tag, "DEX脱壳模块加载完成");
        return {};
    }
};

// 模块加载函数
function loadModules() {
    try {
        logger.info('SYSTEM', '直接加载内联模块...');
        
        // 加载反调试绕过模块
        if (config.bypassAllDetection) {
            modules.anti_debug(config, logger, utils);
        }
        
        // 加载加密监控模块
        modules.crypto_monitor(config, logger, utils);
        
        // 加载网络监控模块
        modules.network_monitor(config, logger, utils);
        
        // 加载敏感API监控模块
        modules.sensitive_api(config, logger, utils);
        
        // 加载自动提取器模块
        if (config.autoExtractKeys) {
            modules.auto_extractor(config, logger, utils);
        }
        
        // 加载系统API监控模块
        modules.system_api_monitor(config, logger, utils);
        
        // 加载DEX脱壳模块
        modules.dex_dumper(config, logger, utils);
        
        logger.info('SYSTEM', '所有模块加载完成');
    } catch (e) {
        logger.error('SYSTEM', '加载模块时出错: ' + e);
    }
}

// 主函数
function main() {
    console.log('[*] Frida全功能Hook框架启动中...');
    
    // 检查Frida版本
    checkFridaVersion();
    
    // 创建日志文件
    if (config.fileLogging) {
        if (!createLogFile()) {
            console.log('[*] 日志文件创建失败，已禁用文件日志');
        }
    }
    
    // 显示启动信息
    console.log('[*] Frida全功能Hook框架初始化完成');
    console.log('[*] 日志级别: ' + config.logLevel);
    console.log('[*] 绕过检测: ' + (config.bypassAllDetection ? '启用' : '禁用'));
    console.log('[*] Frida版本: ' + (config.fridaVersion || '未知'));
    console.log('[*] 兼容模式: ' + (config.fridaCompatMode ? '启用' : '禁用'));
    
    // 延迟加载模块，确保应用有足够时间初始化
    setTimeout(function() {
        try {
            // 检查Java环境
            if (Java.available) {
                console.log('[*] Java环境可用，开始初始化...');
                
                // 使用try-catch包装Java.perform以捕获可能的异常
        try {
            Java.perform(function() {
                        console.log('[*] Java环境准备就绪');
                        
                        // 捕获Java环境中的未处理异常
                        try {
                            var Thread = Java.use('java.lang.Thread');
                            var uncaughtExceptionHandler = Java.registerClass({
                                name: 'com.frida.UncaughtExceptionHandler',
                                implements: [Java.use('java.lang.Thread$UncaughtExceptionHandler')],
                                methods: {
                                    uncaughtException: function(thread, exception) {
                                        console.log('[!] 未捕获异常: ' + exception.toString());
                                        console.log('[!] 异常堆栈: ' + Java.use('android.util.Log').getStackTraceString(exception));
                                    }
                                }
                            });
                            Thread.setDefaultUncaughtExceptionHandler(uncaughtExceptionHandler.$new());
                            console.log('[*] 已设置全局异常处理器');
                        } catch (e) {
                            console.log('[!] 设置异常处理器失败: ' + e);
                        }
                        
                        // 加载所有模块
                loadModules();
            });
        } catch (e) {
                    console.log('[!] Java.perform执行失败: ' + e);
                    
            // 尝试使用兼容性更强的方式
            if (!config.fridaCompatMode) {
                        console.log('[*] 切换到兼容模式并重试...');
                config.fridaCompatMode = true;
                        try {
                Java.perform(loadModules);
                        } catch (e2) {
                            console.log('[!] 兼容模式下Java.perform执行失败: ' + e2);
                            // 如果仍然失败，尝试直接加载模块
                            loadModules();
                        }
                    } else {
                        // 如果已经在兼容模式下，尝试直接加载模块
                        console.log('[*] 尝试在不使用Java环境的情况下加载模块...');
                        loadModules();
                    }
                }
            } else {
                console.log('[!] Java环境不可用，可能是Native应用或Frida版本问题');
                console.log('[*] 尝试加载适用于Native环境的模块...');
                
                // 加载不依赖Java环境的模块
                loadModules();
            }
        } catch (e) {
            console.log('[!] 框架初始化失败: ' + e);
        }
    }, 1000);
    
    // 设置全局错误处理
    try {
        Process.setExceptionHandler(function(details) {
            console.log('[!] 进程异常: ' + JSON.stringify(details));
            return true; // 继续执行
        });
    } catch (e) {
        console.log('[!] 设置进程异常处理器失败: ' + e);
    }
}

// 启动框架
try {
main(); 
    console.log('[*] 框架启动成功');
} catch (e) {
    console.log('[!] 框架启动失败: ' + e);
} 
