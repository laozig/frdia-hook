/*
 * 脚本名称：监控消息摘要算法.js
 * 功能：全面监控Android应用中的哈希/摘要算法调用，获取输入数据和计算结果
 * 适用场景：
 *   - 分析应用签名校验逻辑
 *   - 逆向密码哈希算法
 *   - 识别数据完整性校验流程
 *   - 分析加密参数生成过程
 * 使用方法：
 *   1. frida -U -f 包名 -l 监控消息摘要算法.js --no-pause
 *   2. 查看控制台输出，分析哈希算法的输入和输出
 * 启动方式说明：
 *   - -U 代表使用USB连接的设备
 *   - -f 代表以spawn方式启动目标应用
 *   - --no-pause 指示Frida不要暂停应用执行
 * 支持特性：
 *   - 监控各种哈希算法(MD5/SHA1/SHA256等)
 *   - 监控HMAC算法
 *   - 参数和结果的多种格式显示(HEX/Base64/文本)
 *   - 调用堆栈追踪
 *   - 使用频率统计
 *   - 密钥识别
 *   - 数据关联分析
 */

(function() {
    // 全局配置
    var config = {
        logLevel: 2,                // 0:关闭 1:错误 2:基本信息 3:详细
        printStack: true,           // 是否打印调用堆栈
        maxStackDepth: 5,           // 最大堆栈深度
        showInputData: true,        // 是否显示输入数据
        maxDataSize: 1024,          // 最大显示数据长度
        showMultipleFormats: true,  // 是否以多种格式显示结果
        detectSensitiveData: true,  // 检测敏感数据
        monitorNative: false        // 是否监控Native层哈希函数(可能会影响性能)
    };
    
    // 统计信息
    var stats = {
        totalCalls: 0,
        byAlgorithm: {}
    };
    
    // 最近哈希记录，用于检测重复调用
    var recentHashes = [];
    var maxRecentHashes = 20;
    
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
                
                // 过滤掉框架类
                if (className.indexOf("java.security.") === 0 && i > 0) continue;
                
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
    
    // 辅助函数：字节数组转十六进制字符串
    function bytesToHex(bytes) {
        if (!bytes) return "<null>";
        
        try {
            var len = bytes.length;
            if (len > config.maxDataSize) {
                len = config.maxDataSize;
            }
            
            var hexString = "";
            for (var i = 0; i < len; i++) {
                var byteValue = bytes[i] & 0xFF;
                var hexChar = byteValue.toString(16).padStart(2, '0');
                hexString += hexChar;
                if (i % 16 === 15 && i < len - 1) hexString += "\n                   ";
            }
            
            if (bytes.length > config.maxDataSize) {
                hexString += "... (总共" + bytes.length + "字节)";
            }
            
            return hexString;
        } catch (e) {
            return "<转换失败: " + e + ">";
        }
    }
    
    // 辅助函数：尝试将字节数组转为字符串
    function tryBytesToString(bytes) {
        if (!bytes) return "<null>";
        
        try {
            var result = Java.use("java.lang.String").$new(bytes);
            if (result.length() > config.maxDataSize) {
                result = result.substring(0, config.maxDataSize) + "... (总长度: " + result.length() + ")";
            }
            return result;
        } catch (e) {
            return "<二进制数据>";
        }
    }
    
    // 辅助函数：检测是否为敏感数据
    function detectSensitiveData(data) {
        if (!config.detectSensitiveData || !data) return null;
        
        var str = tryBytesToString(data);
        if (str === "<二进制数据>") return null;
        
        // 检测常见敏感数据格式
        var patterns = {
            "信用卡号": /\b(?:\d[ -]*?){13,16}\b/,
            "email": /[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+/,
            "手机号": /\b(?:\+?(\d{1,3}))?[-. (]*(\d{3})[-. )]*(\d{3})[-. ]*(\d{4})\b/,
            "身份证号": /\b\d{17}[\dXx]\b/,
            "密码格式": /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/,
            "API密钥格式": /[A-Za-z0-9]{32,}/
        };
        
        for (var key in patterns) {
            if (patterns[key].test(str)) {
                return key;
            }
        }
        
        return null;
    }
    
    // 辅助函数：检测是否近期有相似哈希调用
    function checkRecentHashes(algorithm, input, result) {
        for (var i = 0; i < recentHashes.length; i++) {
            var hash = recentHashes[i];
            if (hash.algorithm === algorithm && 
                ((hash.input && input && hash.input.length === input.length) || 
                 (hash.result && result && hash.result === result))) {
                return true;
            }
        }
        
        // 添加到最近哈希记录
        recentHashes.push({
            algorithm: algorithm,
            input: input,
            result: result,
            time: new Date()
        });
        
        // 保持队列长度
        if (recentHashes.length > maxRecentHashes) {
            recentHashes.shift();
        }
        
        return false;
    }
    
    // 辅助函数：识别哈希算法用途
    function identifyUsage(algorithm, input, result) {
        // 这里可以添加一些启发式规则来猜测哈希的用途
        if (input && input.length <= 32 && algorithm.indexOf("SHA") !== -1) {
            return "可能是密码哈希";
        }
        
        if (algorithm === "MD5" && input && input.length > 100) {
            return "可能是文件校验";
        }
        
        if (algorithm.indexOf("MAC") !== -1) {
            return "可能用于消息认证";
        }
        
        return null;
    }
    
    Java.perform(function() {
        // 1. 监控 MessageDigest (常见哈希算法如MD5、SHA-1、SHA-256等)
        var MessageDigest = Java.use("java.security.MessageDigest");
        
        // 监控算法的初始化
        MessageDigest.getInstance.overload('java.lang.String').implementation = function(algorithm) {
            var md = this.getInstance(algorithm);
            log(3, "初始化哈希算法: " + algorithm);
            
            // 更新统计
            stats.totalCalls++;
            if (!stats.byAlgorithm[algorithm]) {
                stats.byAlgorithm[algorithm] = 0;
            }
            stats.byAlgorithm[algorithm]++;
            
            return md;
        };
        
        // 监控输入数据
        MessageDigest.update.overload('[B').implementation = function(input) {
            var algorithm = this.getAlgorithm();
            
            if (config.showInputData) {
                log(2, "MessageDigest(" + algorithm + ").update");
                if (input) {
                    var sensitive = detectSensitiveData(input);
                    
                    if (sensitive) {
                        log(1, "    输入数据包含敏感信息: " + sensitive);
                    }
                    
                    if (config.showMultipleFormats) {
                        log(2, "    输入数据(HEX): " + bytesToHex(input));
                        log(2, "    输入数据(文本): " + tryBytesToString(input));
                    } else {
                        log(2, "    输入数据: " + bytesToHex(input));
                    }
                }
            }
            
            this.update(input);
            return;
        };
        
        // 重载版本：带offset和len参数
        MessageDigest.update.overload('[B', 'int', 'int').implementation = function(input, offset, len) {
            var algorithm = this.getAlgorithm();
            
            if (config.showInputData) {
                log(2, "MessageDigest(" + algorithm + ").update(带offset/len)");
                if (input) {
                    var data = Java.array('byte', input);
                    var inputSlice = new Array(len);
                    for (var i = 0; i < len; i++) {
                        inputSlice[i] = data[offset + i];
                    }
                    
                    if (config.showMultipleFormats) {
                        log(2, "    输入数据(HEX): " + bytesToHex(inputSlice));
                        log(2, "    输入数据(文本): " + tryBytesToString(inputSlice));
                    } else {
                        log(2, "    输入数据: " + bytesToHex(inputSlice));
                    }
                }
            }
            
            this.update(input, offset, len);
            return;
        };
        
        // 监控摘要计算结果
        MessageDigest.digest.overload().implementation = function() {
            var algorithm = this.getAlgorithm();
            var result = this.digest();
            
            log(2, "MessageDigest(" + algorithm + ").digest 计算完成");
            
            var resultHex = bytesToHex(result);
            if (config.showMultipleFormats) {
                // 创建Base64工具
                var Base64 = Java.use("android.util.Base64");
                var resultBase64 = Base64.encodeToString(result, Base64.DEFAULT);
                
                log(2, "    结果(HEX): " + resultHex);
                log(2, "    结果(Base64): " + resultBase64);
            } else {
                log(2, "    结果: " + resultHex);
            }
            
            // 检查是否为常见的哈希值
            if (resultHex === "d41d8cd98f00b204e9800998ecf8427e") {
                log(2, "    注意: 这是空字符串的MD5哈希值");
            }
            
            // 识别可能的用途
            var usage = identifyUsage(algorithm, null, resultHex);
            if (usage) {
                log(2, "    可能的用途: " + usage);
            }
            
            // 检查是否为重复调用
            var isRepeat = checkRecentHashes(algorithm, null, resultHex);
            if (isRepeat) {
                log(3, "    注意: 此哈希调用与近期的调用相似");
            }
            
            if (config.printStack) {
                log(3, getStackTrace());
            }
            
            return result;
        };
        
        // 重载版本：带输入参数的digest
        MessageDigest.digest.overload('[B').implementation = function(input) {
            var algorithm = this.getAlgorithm();
            
            if (config.showInputData) {
                log(2, "MessageDigest(" + algorithm + ").digest(带输入)");
                if (input) {
                    var sensitive = detectSensitiveData(input);
                    
                    if (sensitive) {
                        log(1, "    输入数据包含敏感信息: " + sensitive);
                    }
                    
                    if (config.showMultipleFormats) {
                        log(2, "    输入数据(HEX): " + bytesToHex(input));
                        log(2, "    输入数据(文本): " + tryBytesToString(input));
                    } else {
                        log(2, "    输入数据: " + bytesToHex(input));
                    }
                }
            }
            
            var result = this.digest(input);
            
            var resultHex = bytesToHex(result);
            if (config.showMultipleFormats) {
                var Base64 = Java.use("android.util.Base64");
                var resultBase64 = Base64.encodeToString(result, Base64.DEFAULT);
                
                log(2, "    结果(HEX): " + resultHex);
                log(2, "    结果(Base64): " + resultBase64);
            } else {
                log(2, "    结果: " + resultHex);
            }
            
            // 识别可能的用途
            var usage = identifyUsage(algorithm, input, resultHex);
            if (usage) {
                log(2, "    可能的用途: " + usage);
            }
            
            // 检查是否为重复调用
            var isRepeat = checkRecentHashes(algorithm, input, resultHex);
            if (isRepeat) {
                log(3, "    注意: 此哈希调用与近期的调用相似");
            }
            
            if (config.printStack) {
                log(3, getStackTrace());
            }
            
            return result;
        };
        
        // 2. 监控 Mac (消息认证码，如HMAC-SHA256等)
        var Mac = Java.use("javax.crypto.Mac");
        
        // 监控Mac初始化
        Mac.getInstance.overload('java.lang.String').implementation = function(algorithm) {
            var mac = this.getInstance(algorithm);
            log(3, "初始化MAC算法: " + algorithm);
            
            // 更新统计
            stats.totalCalls++;
            if (!stats.byAlgorithm[algorithm]) {
                stats.byAlgorithm[algorithm] = 0;
            }
            stats.byAlgorithm[algorithm]++;
            
            return mac;
        };
        
        // 监控Mac密钥设置
        Mac.init.overload('java.security.Key').implementation = function(key) {
            var algorithm = this.getAlgorithm();
            log(2, "Mac(" + algorithm + ").init");
            
            // 尝试显示密钥信息
            try {
                var keyBytes = key.getEncoded();
                if (keyBytes) {
                    log(2, "    密钥(HEX): " + bytesToHex(keyBytes));
                    log(2, "    密钥(文本): " + tryBytesToString(keyBytes));
                }
            } catch (e) {
                log(3, "    无法获取密钥数据: " + e);
            }
            
            this.init(key);
            return;
        };
        
        // 监控Mac数据输入
        Mac.update.overload('[B').implementation = function(input) {
            var algorithm = this.getAlgorithm();
            
            if (config.showInputData) {
                log(2, "Mac(" + algorithm + ").update");
                if (input) {
                    var sensitive = detectSensitiveData(input);
                    
                    if (sensitive) {
                        log(1, "    输入数据包含敏感信息: " + sensitive);
                    }
                    
                    if (config.showMultipleFormats) {
                        log(2, "    输入数据(HEX): " + bytesToHex(input));
                        log(2, "    输入数据(文本): " + tryBytesToString(input));
                    } else {
                        log(2, "    输入数据: " + bytesToHex(input));
                    }
                }
            }
            
            this.update(input);
            return;
        };
        
        // 重载版本：带offset和len参数
        Mac.update.overload('[B', 'int', 'int').implementation = function(input, offset, len) {
            var algorithm = this.getAlgorithm();
            
            if (config.showInputData) {
                log(2, "Mac(" + algorithm + ").update(带offset/len)");
                if (input) {
                    var data = Java.array('byte', input);
                    var inputSlice = new Array(len);
                    for (var i = 0; i < len; i++) {
                        inputSlice[i] = data[offset + i];
                    }
                    
                    if (config.showMultipleFormats) {
                        log(2, "    输入数据(HEX): " + bytesToHex(inputSlice));
                        log(2, "    输入数据(文本): " + tryBytesToString(inputSlice));
                    } else {
                        log(2, "    输入数据: " + bytesToHex(inputSlice));
                    }
                }
            }
            
            this.update(input, offset, len);
            return;
        };
        
        // 监控Mac计算结果
        Mac.doFinal.overload().implementation = function() {
            var algorithm = this.getAlgorithm();
            var result = this.doFinal();
            
            log(2, "Mac(" + algorithm + ").doFinal 计算完成");
            
            var resultHex = bytesToHex(result);
            if (config.showMultipleFormats) {
                var Base64 = Java.use("android.util.Base64");
                var resultBase64 = Base64.encodeToString(result, Base64.DEFAULT);
                
                log(2, "    结果(HEX): " + resultHex);
                log(2, "    结果(Base64): " + resultBase64);
            } else {
                log(2, "    结果: " + resultHex);
            }
            
            if (config.printStack) {
                log(3, getStackTrace());
            }
            
            return result;
        };
        
        // 重载版本：带输入参数的doFinal
        Mac.doFinal.overload('[B').implementation = function(input) {
            var algorithm = this.getAlgorithm();
            
            if (config.showInputData) {
                log(2, "Mac(" + algorithm + ").doFinal(带输入)");
                if (input) {
                    var sensitive = detectSensitiveData(input);
                    
                    if (sensitive) {
                        log(1, "    输入数据包含敏感信息: " + sensitive);
                    }
                    
                    if (config.showMultipleFormats) {
                        log(2, "    输入数据(HEX): " + bytesToHex(input));
                        log(2, "    输入数据(文本): " + tryBytesToString(input));
                    } else {
                        log(2, "    输入数据: " + bytesToHex(input));
                    }
                }
            }
            
            var result = this.doFinal(input);
            
            var resultHex = bytesToHex(result);
            if (config.showMultipleFormats) {
                var Base64 = Java.use("android.util.Base64");
                var resultBase64 = Base64.encodeToString(result, Base64.DEFAULT);
                
                log(2, "    结果(HEX): " + resultHex);
                log(2, "    结果(Base64): " + resultBase64);
            } else {
                log(2, "    结果: " + resultHex);
            }
            
            if (config.printStack) {
                log(3, getStackTrace());
            }
            
            return result;
        };
        
        // 3. 监控Native层哈希函数（如果启用）
        if (config.monitorNative) {
            try {
                // 以下是一些OpenSSL中常见的哈希函数
                var hashFuncs = [
                    "MD5", 
                    "SHA1", 
                    "SHA256", 
                    "SHA512",
                    "HMAC"
                ];
                
                hashFuncs.forEach(function(func) {
                    // 尝试查找多个可能的函数名
                    var variants = [
                        func,
                        func.toLowerCase(),
                        func + "_Init",
                        func + "_Final",
                        func + "_Update"
                    ];
                    
                    variants.forEach(function(variant) {
                        var addr = Module.findExportByName(null, variant);
                        if (addr) {
                            log(3, "找到并Hook Native函数: " + variant + " @ " + addr);
                            
                            Interceptor.attach(addr, {
                                onEnter: function(args) {
                                    log(2, "调用Native哈希函数: " + variant);
                                    
                                    // 尝试解析参数
                                    try {
                                        if (variant.indexOf("Update") !== -1 && args[1]) {
                                            var data = args[1].readByteArray(32);
                                            if (data) {
                                                log(3, "    输入数据(前32字节): " + bytesToHex(data));
                                            }
                                        }
                                    } catch (e) {
                                        // 忽略参数解析错误
                                    }
                                },
                                onLeave: function(retval) {
                                    // 针对特定函数提取返回值
                                    if (variant.indexOf("Final") !== -1) {
                                        log(3, "    函数返回值: " + retval);
                                    }
                                }
                            });
                        }
                    });
                });
                
                log(2, "Native层哈希函数监控已启动");
            } catch (e) {
                log(1, "监控Native层哈希函数失败: " + e);
            }
        }
        
        // 4. 其他常用哈希工具类
        
        // 监控Apache Commons Codec的DigestUtils
        try {
            var DigestUtils = Java.use("org.apache.commons.codec.digest.DigestUtils");
            
            // MD5相关方法
            if (DigestUtils.md5) {
                DigestUtils.md5.overload('[B').implementation = function(data) {
                    log(2, "DigestUtils.md5调用");
                    
                    if (config.showInputData && data) {
                        var sensitive = detectSensitiveData(data);
                        
                        if (sensitive) {
                            log(1, "    输入数据包含敏感信息: " + sensitive);
                        }
                        
                        log(2, "    输入数据(HEX): " + bytesToHex(data));
                        log(2, "    输入数据(文本): " + tryBytesToString(data));
                    }
                    
                    var result = this.md5(data);
                    log(2, "    结果(HEX): " + bytesToHex(result));
                    
                    if (config.printStack) {
                        log(3, getStackTrace());
                    }
                    
                    return result;
                };
            }
            
            // MD5Hex方法
            if (DigestUtils.md5Hex) {
                DigestUtils.md5Hex.overload('[B').implementation = function(data) {
                    log(2, "DigestUtils.md5Hex调用");
                    
                    if (config.showInputData && data) {
                        var sensitive = detectSensitiveData(data);
                        
                        if (sensitive) {
                            log(1, "    输入数据包含敏感信息: " + sensitive);
                        }
                        
                        log(2, "    输入数据(HEX): " + bytesToHex(data));
                        log(2, "    输入数据(文本): " + tryBytesToString(data));
                    }
                    
                    var result = this.md5Hex(data);
                    log(2, "    结果: " + result);
                    
                    if (config.printStack) {
                        log(3, getStackTrace());
                    }
                    
                    return result;
                };
            }
            
            log(2, "Apache Commons DigestUtils监控已启动");
        } catch (e) {
            // DigestUtils可能不存在，忽略错误
        }
        
        // 定期输出统计信息
        setInterval(function() {
            if (stats.totalCalls > 0) {
                log(2, "哈希算法调用统计: 总共 " + stats.totalCalls + " 次调用");
                
                var algInfo = "";
                for (var alg in stats.byAlgorithm) {
                    algInfo += "\n    " + alg + ": " + stats.byAlgorithm[alg] + "次";
                }
                
                if (algInfo) {
                    log(2, "按算法类型统计:" + algInfo);
                }
            }
        }, 10000); // 每10秒输出一次
    });
    
    log(2, "消息摘要/哈希算法监控已启动");
})(); 