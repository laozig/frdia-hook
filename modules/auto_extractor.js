/*
 * 自动提取密钥模块
 * 功能：自动识别、提取和保存应用中的加密密钥、令牌和配置信息
 * 支持：自动保存密钥到文件，识别常见密钥模式，监控密钥生命周期
 */

module.exports = function(config, logger, utils) {
    var tag = "EXTRACTOR";
    logger.info(tag, "自动提取密钥模块初始化");
    
    // 如果未开启自动提取功能，则直接返回
    if (!config.autoExtractKeys) {
        logger.info(tag, "自动提取密钥功能未开启，跳过");
        return;
    }
    
    // 提取的密钥存储
    var extractedData = {
        count: 0,
        items: {},
        
        // 添加提取到的数据
        addItem: function(type, name, value, source) {
            this.count++;
            var id = this.generateId(type, name);
            
            // 检查是否已存在
            if (this.items[id] && this.items[id].value === value) {
                return; // 已存在相同数据，跳过
            }
            
            this.items[id] = {
                id: id,
                type: type,
                name: name,
                value: value,
                source: source,
                timestamp: new Date(),
                usageCount: 1
            };
            
            // 记录日志
            logger.info(tag, "提取到" + type + ": " + name);
            logger.debug(tag, "值: " + value);
            logger.debug(tag, "来源: " + source);
            
            // 保存到文件
            this.saveToFile();
        },
        
        // 更新使用计数
        updateUsage: function(id) {
            if (this.items[id]) {
                this.items[id].usageCount++;
                this.items[id].lastUsed = new Date();
            }
        },
        
        // 生成ID
        generateId: function(type, name) {
            return type + "_" + name;
        },
        
        // 保存到文件
        saveToFile: function() {
            try {
                // 转换为JSON格式
                var jsonData = JSON.stringify({
                    timestamp: new Date(),
                    count: this.count,
                    items: this.items
                }, null, 2);
                
                // 保存到文件
                var filePath = "/sdcard/frida_extracted_keys.json";
                var file = new File(filePath, "w");
                file.write(jsonData);
                file.flush();
                file.close();
                
                logger.debug(tag, "已保存提取的数据到: " + filePath);
            } catch (e) {
                logger.error(tag, "保存提取数据失败: " + e);
            }
        }
    };
    
    // 开始提取密钥
    Java.perform(function() {
        // 1. 提取字符串常量中的密钥
        extractStringConstants();
        
        // 2. 监控配置文件读取
        monitorConfigFiles();
        
        // 3. 监控网络请求中的密钥
        monitorNetworkKeys();
        
        // 4. 监控SharedPreferences中的密钥
        monitorSharedPreferences();
        
        // 5. 监控常见密钥生成函数
        monitorKeyGeneration();
        
        // 6. 监控自定义加密函数
        monitorCustomEncryption();
    });
    
    // 提取字符串常量中的密钥
    function extractStringConstants() {
        try {
            // 搜索类加载器中的所有类
            Java.enumerateClassLoaders({
                onMatch: function(loader) {
                    // 设置当前类加载器
                    Java.classFactory.loader = loader;
                    
                    try {
                        // 搜索可能包含密钥的类
                        var keywordClasses = [
                            "Config", "Constants", "Security", "Crypto", 
                            "Keys", "Auth", "Token", "Secret", "ApiKey"
                        ];
                        
                        keywordClasses.forEach(function(keyword) {
                            try {
                                Java.enumerateLoadedClasses({
                                    onMatch: function(className) {
                                        if (className.indexOf(keyword) !== -1) {
                                            inspectClass(className);
                                        }
                                    },
                                    onComplete: function() {}
                                });
                            } catch (e) {
                                // 忽略错误继续搜索
                            }
                        });
                    } catch (e) {
                        logger.debug(tag, "搜索类错误: " + e);
                    }
                },
                onComplete: function() {}
            });
            
            logger.info(tag, "字符串常量提取完成");
        } catch (e) {
            logger.error(tag, "提取字符串常量失败: " + e);
        }
    }
    
    // 检查类中的字段
    function inspectClass(className) {
        try {
            var jClass = Java.use(className);
            var fields = jClass.class.getDeclaredFields();
            
            for (var i = 0; i < fields.length; i++) {
                var field = fields[i];
                field.setAccessible(true);
                
                try {
                    var fieldName = field.getName();
                    var fieldTypeName = field.getType().getName();
                    
                    // 字符串类型的静态字段可能包含密钥
                    if (fieldTypeName === "java.lang.String" && java.lang.reflect.Modifier.isStatic(field.getModifiers())) {
                        try {
                            var value = field.get(null);
                            if (value && isPossibleKey(fieldName, value)) {
                                extractedData.addItem("静态字段", className + "." + fieldName, value, "类字段");
                            }
                        } catch (e) {
                            // 忽略访问错误
                        }
                    }
                } catch (e) {
                    // 忽略访问错误
                }
            }
        } catch (e) {
            logger.debug(tag, "检查类 " + className + " 失败: " + e);
        }
    }
    
    // 判断是否可能是密钥
    function isPossibleKey(name, value) {
        if (typeof value !== "string") return false;
        if (value.length < 8) return false; // 太短可能不是密钥
        
        // 检查字段名称是否包含关键词
        var keywordNames = ["key", "token", "secret", "password", "pwd", "auth", 
                           "apikey", "api_key", "access", "appkey", "app_id", "appid", 
                           "clientid", "client_id", "aes", "rsa", "des", "md5", "sha"];
        
        var lowerName = name.toLowerCase();
        for (var i = 0; i < keywordNames.length; i++) {
            if (lowerName.indexOf(keywordNames[i]) !== -1) {
                return true;
            }
        }
        
        // 检查值格式，是否符合密钥模式
        
        // Base64格式
        if (/^[A-Za-z0-9+/=]{24,}$/.test(value)) {
            return true;
        }
        
        // 十六进制格式
        if (/^[A-Fa-f0-9]{16,}$/.test(value)) {
            return true;
        }
        
        // JWT格式
        if (/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(value)) {
            return true;
        }
        
        // OAuth Token格式
        if (/^[a-zA-Z0-9]{32,}$/.test(value)) {
            return true;
        }
        
        return false;
    }
    
    // 监控配置文件读取
    function monitorConfigFiles() {
        try {
            // 监控各种配置文件读取
            var FileInputStream = Java.use("java.io.FileInputStream");
            var BufferedReader = Java.use("java.io.BufferedReader");
            var InputStreamReader = Java.use("java.io.InputStreamReader");
            
            // Hook读取方法
            BufferedReader.readLine.implementation = function() {
                var line = this.readLine();
                
                if (line) {
                    // 检查是否是配置行
                    if (line.indexOf("=") !== -1 || line.indexOf(":") !== -1) {
                        var parts = line.split(/[=:]/);
                        if (parts.length >= 2) {
                            var key = parts[0].trim();
                            var value = parts[1].trim();
                            
                            if (isPossibleKey(key, value)) {
                                extractedData.addItem("配置文件", key, value, "文件读取");
                            }
                        }
                    }
                }
                
                return line;
            };
            
            logger.info(tag, "配置文件监控已设置");
        } catch (e) {
            logger.error(tag, "监控配置文件失败: " + e);
        }
    }
    
    // 监控网络请求中的密钥
    function monitorNetworkKeys() {
        try {
            // 监控请求头中的密钥
            var HttpURLConnection = Java.use("java.net.HttpURLConnection");
            HttpURLConnection.setRequestProperty.implementation = function(key, value) {
                // 检查请求头是否包含敏感信息
                var lowerKey = key.toLowerCase();
                if (lowerKey.indexOf("auth") !== -1 || 
                    lowerKey.indexOf("token") !== -1 || 
                    lowerKey.indexOf("key") !== -1 || 
                    lowerKey.indexOf("secret") !== -1 || 
                    lowerKey.indexOf("apikey") !== -1 || 
                    lowerKey.indexOf("api-key") !== -1) {
                    
                    extractedData.addItem("请求头", key, value, "HTTP请求");
                }
                
                return this.setRequestProperty(key, value);
            };
            
            // 尝试Hook OkHttp
            try {
                var Request = Java.use("okhttp3.Request");
                var Request$Builder = Java.use("okhttp3.Request$Builder");
                
                Request$Builder.addHeader.implementation = function(name, value) {
                    // 检查请求头是否包含敏感信息
                    var lowerName = name.toLowerCase();
                    if (lowerName.indexOf("auth") !== -1 || 
                        lowerName.indexOf("token") !== -1 || 
                        lowerName.indexOf("key") !== -1 || 
                        lowerName.indexOf("secret") !== -1 || 
                        lowerName.indexOf("apikey") !== -1 || 
                        lowerName.indexOf("api-key") !== -1) {
                        
                        extractedData.addItem("OkHttp请求头", name, value, "OkHttp请求");
                    }
                    
                    return this.addHeader(name, value);
                };
            } catch (e) {
                logger.debug(tag, "OkHttp Hook失败: " + e);
            }
            
            logger.info(tag, "网络请求密钥监控已设置");
        } catch (e) {
            logger.error(tag, "监控网络请求密钥失败: " + e);
        }
    }
    
    // 监控SharedPreferences中的密钥
    function monitorSharedPreferences() {
        try {
            var SharedPreferencesEditor = Java.use("android.content.SharedPreferences$Editor");
            
            // 监控写入操作
            SharedPreferencesEditor.putString.implementation = function(key, value) {
                if (isPossibleKey(key, value)) {
                    extractedData.addItem("SharedPreferences", key, value, "应用设置");
                }
                
                return this.putString(key, value);
            };
            
            // 监控读取操作
            var SharedPreferences = Java.use("android.content.SharedPreferences");
            SharedPreferences.getString.implementation = function(key, defValue) {
                var value = this.getString(key, defValue);
                
                if (isPossibleKey(key, value)) {
                    extractedData.addItem("SharedPreferences", key, value, "应用设置");
                }
                
                return value;
            };
            
            logger.info(tag, "SharedPreferences监控已设置");
        } catch (e) {
            logger.error(tag, "监控SharedPreferences失败: " + e);
        }
    }
    
    // 监控密钥生成函数
    function monitorKeyGeneration() {
        try {
            // KeyGenerator
            var KeyGenerator = Java.use("javax.crypto.KeyGenerator");
            KeyGenerator.generateKey.implementation = function() {
                var key = this.generateKey();
                
                try {
                    var algorithm = this.getAlgorithm();
                    var keyEncoded = key.getEncoded();
                    var keyHex = bytesToHex(keyEncoded);
                    
                    extractedData.addItem("生成密钥", algorithm, keyHex, "KeyGenerator");
                } catch (e) {
                    logger.debug(tag, "提取生成的密钥失败: " + e);
                }
                
                return key;
            };
            
            // SecretKeySpec
            var SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
            SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function(keyBytes, algorithm) {
                var key = this.$init(keyBytes, algorithm);
                
                try {
                    var keyHex = bytesToHex(keyBytes);
                    extractedData.addItem("密钥规范", algorithm, keyHex, "SecretKeySpec");
                } catch (e) {
                    logger.debug(tag, "提取SecretKeySpec失败: " + e);
                }
                
                return key;
            };
            
            // KeyPairGenerator (RSA等)
            var KeyPairGenerator = Java.use("java.security.KeyPairGenerator");
            KeyPairGenerator.generateKeyPair.implementation = function() {
                var keyPair = this.generateKeyPair();
                
                try {
                    var algorithm = this.getAlgorithm();
                    
                    // 公钥
                    var publicKey = keyPair.getPublic();
                    var publicKeyEncoded = publicKey.getEncoded();
                    var publicKeyHex = bytesToHex(publicKeyEncoded);
                    
                    // 私钥
                    var privateKey = keyPair.getPrivate();
                    var privateKeyEncoded = privateKey.getEncoded();
                    var privateKeyHex = bytesToHex(privateKeyEncoded);
                    
                    extractedData.addItem("公钥", algorithm, publicKeyHex, "KeyPairGenerator");
                    extractedData.addItem("私钥", algorithm, privateKeyHex, "KeyPairGenerator");
                } catch (e) {
                    logger.debug(tag, "提取生成的密钥对失败: " + e);
                }
                
                return keyPair;
            };
            
            logger.info(tag, "密钥生成函数监控已设置");
        } catch (e) {
            logger.error(tag, "监控密钥生成函数失败: " + e);
        }
    }
    
    // 监控自定义加密函数
    function monitorCustomEncryption() {
        try {
            // 搜索加密相关的类和方法
            Java.enumerateLoadedClasses({
                onMatch: function(className) {
                    // 检查类名是否与加密相关
                    if (className.toLowerCase().indexOf("crypt") !== -1 || 
                        className.toLowerCase().indexOf("cipher") !== -1 || 
                        className.toLowerCase().indexOf("secure") !== -1 || 
                        className.toLowerCase().indexOf("encode") !== -1 ||
                        className.toLowerCase().indexOf("decode") !== -1) {
                        
                        try {
                            var jClass = Java.use(className);
                            var methods = jClass.class.getDeclaredMethods();
                            
                            for (var i = 0; i < methods.length; i++) {
                                var method = methods[i];
                                var methodName = method.getName();
                                
                                // 检查方法名是否与加密相关
                                if (methodName.toLowerCase().indexOf("encrypt") !== -1 || 
                                    methodName.toLowerCase().indexOf("decrypt") !== -1 || 
                                    methodName.toLowerCase().indexOf("encode") !== -1 || 
                                    methodName.toLowerCase().indexOf("decode") !== -1 ||
                                    methodName.toLowerCase().indexOf("hash") !== -1) {
                                    
                                    // 尝试Hook方法
                                    try {
                                        hookMethod(jClass, methodName);
                                    } catch (e) {
                                        // 某些方法可能无法hook，忽略错误
                                    }
                                }
                            }
                        } catch (e) {
                            // 某些类可能无法访问，忽略错误
                        }
                    }
                },
                onComplete: function() {}
            });
            
            logger.info(tag, "自定义加密函数监控已设置");
        } catch (e) {
            logger.error(tag, "监控自定义加密函数失败: " + e);
        }
    }
    
    // Hook方法
    function hookMethod(jClass, methodName) {
        try {
            var overloads = jClass[methodName].overloads;
            if (overloads.length > 0) {
                for (var i = 0; i < overloads.length; i++) {
                    overloads[i].implementation = function() {
                        // 获取参数
                        var params = [];
                        for (var j = 0; j < arguments.length; j++) {
                            try {
                                if (arguments[j] === null) {
                                    params.push("null");
                                } else if (arguments[j] instanceof Array) {
                                    params.push(bytesToHex(arguments[j]));
                                } else {
                                    params.push(String(arguments[j]));
                                }
                            } catch (e) {
                                params.push("<无法转换的参数>");
                            }
                        }
                        
                        var result = this[methodName].apply(this, arguments);
                        
                        // 提取结果
                        var resultValue = "";
                        try {
                            if (result === null) {
                                resultValue = "null";
                            } else if (result instanceof Array) {
                                resultValue = bytesToHex(result);
                            } else {
                                resultValue = String(result);
                            }
                        } catch (e) {
                            resultValue = "<无法转换的结果>";
                        }
                        
                        // 仅记录可能是密钥相关的调用
                        if (params.some(function(param) { 
                            return isPossibleKey("param", param); 
                        }) || isPossibleKey("result", resultValue)) {
                            extractedData.addItem("自定义加密", 
                                jClass.class.getName() + "." + methodName, 
                                "参数: " + params.join(", ") + ", 结果: " + resultValue,
                                "函数调用");
                        }
                        
                        return result;
                    };
                }
            }
        } catch (e) {
            // 某些方法可能无法hook，忽略错误
        }
    }
    
    // 十六进制转换辅助函数
    function bytesToHex(bytes) {
        var hex = '';
        for (var i = 0; i < bytes.length; i++) {
            hex += ('0' + (bytes[i] & 0xFF).toString(16)).slice(-2);
        }
        return hex;
    }
    
    logger.info(tag, "自动提取密钥模块加载完成");
    return {
        extractedData: extractedData
    };
}; 