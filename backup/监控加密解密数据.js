/*
 * 脚本名称：监控加密解密数据.js
 * 功能：全面监控Android应用中的加密解密操作，支持多种算法和接口
 * 适用场景：
 *   - 获取加密前的明文数据和加密后的密文
 *   - 分析应用的加密算法和密钥
 *   - 逆向分析加密协议
 *   - 安全审计和隐私分析
 * 使用方法：
 *   1. frida -U -f 包名 -l 监控加密解密数据.js --no-pause
 *   2. 查看控制台输出，分析加密解密操作
 * 启动方式说明：
 *   - -U 代表使用USB连接的设备
 *   - -f 代表以spawn方式启动目标应用
 *   - --no-pause 指示Frida不要暂停应用执行
 * 支持特性：
 *   - 监控Java层常见加密API
 *   - 监控Native层OpenSSL/BoringSSL接口
 *   - 自动识别密钥和算法参数
 *   - 支持二进制数据的十六进制显示
 *   - 调用堆栈追踪
 *   - 加密模式和填充方式识别
 */

Java.perform(function() {
    // 全局配置
    var config = {
        logLevel: 2,               // 0:关闭 1:错误 2:基本信息 3:详细
        printStack: true,          // 是否打印调用堆栈
        maxStackDepth: 5,          // 最大堆栈深度
        maxDataSize: 512,          // 最大数据显示长度
        showBinaryData: true,      // 是否显示二进制数据的十六进制表示
        detectSensitiveData: true, // 检测敏感数据
        filterSystemCalls: true,   // 是否过滤系统调用
        monitorNative: true        // 是否监控Native层加密
    };

    // 统计信息
    var stats = {
        encrypt: 0,
        decrypt: 0,
        byAlgorithm: {}
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
                // 如果过滤系统调用，跳过Android系统相关的堆栈
                if (config.filterSystemCalls && 
                    (className.indexOf("android.") === 0 || 
                     className.indexOf("java.") === 0 ||
                     className.indexOf("javax.crypto") === 0)) {
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

    // 辅助函数：字节数组转十六进制字符串
    function bytesToHex(bytes) {
        if (!bytes) return "<null>";
        
        try {
            // 获取字节数组长度
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
            return Java.use("java.lang.String").$new(bytes);
        } catch (e) {
            return "<二进制数据>";
        }
    }

    // 1. 监控 javax.crypto.Cipher
    var Cipher = Java.use("javax.crypto.Cipher");
    
    // 监控Cipher初始化
    Cipher.init.overload('int', 'java.security.Key').implementation = function(opmode, key) {
        var operation = opmode === 1 ? "加密" : opmode === 2 ? "解密" : "未知操作(" + opmode + ")";
        var algorithm = this.getAlgorithm();
        
        log(2, "Cipher初始化 - " + operation + " - 算法: " + algorithm);
        log(2, "    密钥: " + bytesToHex(key.getEncoded()));
        
        // 更新统计信息
        if (!stats.byAlgorithm[algorithm]) {
            stats.byAlgorithm[algorithm] = { encrypt: 0, decrypt: 0 };
        }
        
        // 调用原始方法
        return this.init(opmode, key);
    };
    
    // 带参数的Cipher初始化
    Cipher.init.overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec').implementation = function(opmode, key, params) {
        var operation = opmode === 1 ? "加密" : opmode === 2 ? "解密" : "未知操作(" + opmode + ")";
        var algorithm = this.getAlgorithm();
        
        log(2, "Cipher初始化(带参数) - " + operation + " - 算法: " + algorithm);
        log(2, "    密钥: " + bytesToHex(key.getEncoded()));
        
        // 尝试获取IV向量（针对CBC模式）
        try {
            if (params && params.getClass().getName().indexOf("IvParameterSpec") !== -1) {
                var ivSpec = Java.cast(params, Java.use("javax.crypto.spec.IvParameterSpec"));
                log(2, "    IV向量: " + bytesToHex(ivSpec.getIV()));
            }
        } catch (e) {
            log(3, "    无法获取IV: " + e);
        }
        
        if (config.printStack) {
            log(3, getStackTrace());
        }
        
        // 更新统计信息
        if (!stats.byAlgorithm[algorithm]) {
            stats.byAlgorithm[algorithm] = { encrypt: 0, decrypt: 0 };
        }
        
        // 调用原始方法
        return this.init(opmode, key, params);
    };

    // 监控加密操作
    Cipher.doFinal.overload('[B').implementation = function(input) {
        var algorithm = this.getAlgorithm();
        var isEncrypt = this.getClass().getDeclaredField("opmode").get(this) === 1;
        var operation = isEncrypt ? "加密" : "解密";
        
        // 更新统计信息
        if (isEncrypt) {
            stats.encrypt++;
            if (stats.byAlgorithm[algorithm]) stats.byAlgorithm[algorithm].encrypt++;
        } else {
            stats.decrypt++;
            if (stats.byAlgorithm[algorithm]) stats.byAlgorithm[algorithm].decrypt++;
        }
        
        log(2, "Cipher." + operation + " - 算法: " + algorithm);
        
        // 显示输入数据
        if (config.showBinaryData) {
            log(2, "    输入数据(HEX): " + bytesToHex(input));
        }
        log(2, "    输入数据(文本): " + tryBytesToString(input));
        
        // 执行原始方法
        var result = this.doFinal(input);
        
        // 显示输出数据
        if (config.showBinaryData) {
            log(2, "    输出数据(HEX): " + bytesToHex(result));
        }
        log(2, "    输出数据(文本): " + tryBytesToString(result));
        
        if (config.printStack) {
            log(3, getStackTrace());
        }
        
        return result;
    };

    // 2. 监控 MessageDigest (哈希算法)
    var MessageDigest = Java.use("java.security.MessageDigest");
    
    MessageDigest.update.overload('[B').implementation = function(input) {
        var algorithm = this.getAlgorithm();
        log(2, "MessageDigest.update - 算法: " + algorithm);
        
        if (config.showBinaryData) {
            log(2, "    输入数据(HEX): " + bytesToHex(input));
        }
        log(2, "    输入数据(文本): " + tryBytesToString(input));
        
        if (config.printStack) {
            log(3, getStackTrace());
        }
        
        return this.update(input);
    };
    
    MessageDigest.digest.overload().implementation = function() {
        var algorithm = this.getAlgorithm();
        log(2, "MessageDigest.digest - 算法: " + algorithm);
        
        var result = this.digest();
        log(2, "    摘要结果(HEX): " + bytesToHex(result));
        
        return result;
    };

    // 3. 监控 Mac (消息认证码)
    var Mac = Java.use("javax.crypto.Mac");
    
    Mac.init.implementation = function(key) {
        var algorithm = this.getAlgorithm();
        log(2, "Mac.init - 算法: " + algorithm);
        log(2, "    密钥: " + bytesToHex(key.getEncoded()));
        
        return this.init(key);
    };
    
    Mac.doFinal.implementation = function(input) {
        var algorithm = this.getAlgorithm();
        log(2, "Mac.doFinal - 算法: " + algorithm);
        
        if (config.showBinaryData) {
            log(2, "    输入数据(HEX): " + bytesToHex(input));
        }
        log(2, "    输入数据(文本): " + tryBytesToString(input));
        
        var result = this.doFinal(input);
        log(2, "    MAC结果(HEX): " + bytesToHex(result));
        
        if (config.printStack) {
            log(3, getStackTrace());
        }
        
        return result;
    };

    // 4. 监控 KeyGenerator (密钥生成)
    var KeyGenerator = Java.use("javax.crypto.KeyGenerator");
    
    KeyGenerator.getInstance.overload('java.lang.String').implementation = function(algorithm) {
        log(2, "KeyGenerator.getInstance - 算法: " + algorithm);
        
        if (config.printStack) {
            log(3, getStackTrace());
        }
        
        return this.getInstance(algorithm);
    };
    
    var KeyGenerator_init = [
        KeyGenerator.init.overload('int'),
        KeyGenerator.init.overload('int', 'java.security.SecureRandom')
    ];
    
    KeyGenerator_init[0].implementation = function(keysize) {
        log(2, "KeyGenerator.init - 密钥长度: " + keysize + " 位");
        return this.init(keysize);
    };
    
    KeyGenerator_init[1].implementation = function(keysize, random) {
        log(2, "KeyGenerator.init - 密钥长度: " + keysize + " 位 (带随机数)");
        return this.init(keysize, random);
    };

    // 5. 监控 SecretKeySpec (密钥规范)
    var SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
    
    SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function(key, algorithm) {
        log(2, "创建SecretKeySpec - 算法: " + algorithm);
        log(2, "    密钥数据(HEX): " + bytesToHex(key));
        
        if (config.printStack) {
            log(3, getStackTrace());
        }
        
        return this.$init(key, algorithm);
    };

    // 6. 如果启用，监控Native层OpenSSL
    if (config.monitorNative) {
        try {
            // OpenSSL/BoringSSL 加密函数
            var openssl_encrypt_sym = Module.findExportByName(null, "EVP_EncryptFinal_ex");
            if (openssl_encrypt_sym) {
                Interceptor.attach(openssl_encrypt_sym, {
                    onEnter: function(args) {
                        log(2, "Native层加密操作: EVP_EncryptFinal_ex");
                    }
                });
            }
            
            // OpenSSL/BoringSSL 解密函数
            var openssl_decrypt_sym = Module.findExportByName(null, "EVP_DecryptFinal_ex");
            if (openssl_decrypt_sym) {
                Interceptor.attach(openssl_decrypt_sym, {
                    onEnter: function(args) {
                        log(2, "Native层解密操作: EVP_DecryptFinal_ex");
                    }
                });
            }
            
            // 可以添加更多Native层加密函数的Hook
        } catch (e) {
            log(1, "Native层加密监控失败: " + e);
        }
    }

    // 定期输出统计信息
    setInterval(function() {
        if (stats.encrypt > 0 || stats.decrypt > 0) {
            log(2, "加密统计: 加密操作(" + stats.encrypt + "), 解密操作(" + stats.decrypt + ")");
            
            var algInfo = "";
            for (var alg in stats.byAlgorithm) {
                algInfo += "\n    " + alg + ": 加密(" + stats.byAlgorithm[alg].encrypt + 
                          "), 解密(" + stats.byAlgorithm[alg].decrypt + ")";
            }
            if (algInfo) log(2, "算法统计:" + algInfo);
        }
    }, 10000); // 每10秒输出一次
    
    log(2, "加密解密监控已启动，正在监控Java加密API" + 
        (config.monitorNative ? "和Native层加密函数" : ""));
});
