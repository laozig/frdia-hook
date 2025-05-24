/**
 * 加密解密函数Hook脚本
 * 
 * 功能：拦截Android应用中常见的加密解密函数
 * 作用：获取加密前的明文和解密后的明文数据
 * 适用：分析使用加密通信或数据存储的应用
 */

// 等待Java虚拟机加载完成
Java.perform(function() {
    console.log("[*] 加密解密函数Hook脚本已启动");

    // 全局配置
    var config = {
        // 是否显示详细日志
        verbose: true,
        // 是否打印调用堆栈
        printStack: true,
        // 最大打印长度
        maxPrintLength: 1024
    };

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
     * 数据转换和显示函数
     */
    // 尝试获取ByteString类，用于数据转换
    var ByteString = null;
    try {
        ByteString = Java.use("com.android.okhttp.okio.ByteString");
    } catch (e) {
        try {
            ByteString = Java.use("okio.ByteString");
        } catch (e2) {
            console.log("[-] 无法加载ByteString类，将使用内置转换函数");
        }
    }

    // 转换为Base64
    function toBase64(tag, data) {
        if (ByteString !== null) {
            try {
                console.log(tag + " Base64: " + ByteString.of(data).base64());
                return;
            } catch (e) {
                // 失败时使用内置方法
            }
        }
        
        try {
            var Base64 = Java.use("android.util.Base64");
            var base64 = Base64.encodeToString(data, Base64.NO_WRAP.value);
            console.log(tag + " Base64: " + base64);
        } catch (e) {
            console.log(tag + " Base64转换失败: " + e);
        }
    }

    // 转换为十六进制
    function toHex(tag, data) {
        if (ByteString !== null) {
            try {
                console.log(tag + " Hex: " + ByteString.of(data).hex());
                return;
            } catch (e) {
                // 失败时使用内置方法
            }
        }
        
        try {
            var hex = "";
            for (var i = 0; i < data.length; i++) {
                var value = (data[i] & 0xFF).toString(16);
                if (value.length === 1) value = "0" + value;
                hex += value;
                // 每4个字节添加一个空格
                if ((i + 1) % 4 === 0) hex += " ";
            }
            console.log(tag + " Hex: " + hex);
        } catch (e) {
            console.log(tag + " Hex转换失败: " + e);
        }
    }

    // 转换为UTF8字符串
    function toUtf8(tag, data) {
        if (ByteString !== null) {
            try {
                console.log(tag + " UTF8: " + ByteString.of(data).utf8());
                return;
            } catch (e) {
                // 失败时使用内置方法
            }
        }
        
        try {
            var String = Java.use("java.lang.String");
            var encodings = ["UTF-8", "GBK", "GB2312", "ISO-8859-1", "ASCII"];
            
            for (var i = 0; i < encodings.length; i++) {
                try {
                    var encoding = encodings[i];
                    var str = String.$new(data, encoding);
                    
                    // 检查是否为可打印字符串
                    var isPrintable = true;
                    for (var j = 0; j < Math.min(str.length(), 10); j++) {
                        var code = str.charAt(j).charCodeAt(0);
                        if (code < 32 && code !== 9 && code !== 10 && code !== 13) {
                            isPrintable = false;
                            break;
                        }
                    }
                    
                    if (isPrintable) {
                        console.log(tag + " " + encoding + ": " + str);
                        return; // 找到可打印编码就返回
                    }
                } catch (e) {
                    // 忽略转换错误
                }
            }
            
            // 如果所有编码都失败，显示ASCII表示
            var ascii = "";
            for (var i = 0; i < Math.min(data.length, 32); i++) {
                var code = data[i] & 0xFF;
                if (code >= 32 && code <= 126) {
                    ascii += String.fromCharCode(code);
                } else {
                    ascii += ".";
                }
            }
            if (data.length > 32) ascii += "...";
            console.log(tag + " ASCII: " + ascii);
            
        } catch (e) {
            console.log(tag + " UTF8转换失败: " + e);
        }
    }

    /**
     * 一、Hook Java标准加密库
     */
    try {
        // 1. 拦截MessageDigest (哈希函数)
        var MessageDigest = Java.use("java.security.MessageDigest");
        
        // 拦截update方法
        MessageDigest.update.overload("[B").implementation = function(input) {
            if (config.verbose) {
                var algorithm = this.getAlgorithm();
                console.log("\n[+] " + algorithm + " update data");
                toUtf8("Input", input);
                toHex("Input", input);
                toBase64("Input", input);
                console.log("=======================================================");
                
                if (config.printStack) {
                    console.log("    调用堆栈:\n    " + getStackTrace());
                }
            }
            
            return this.update(input);
        };
        
        // 拦截digest方法
        MessageDigest.digest.overload().implementation = function() {
            var result = this.digest();
            var algorithm = this.getAlgorithm();
            
            if (config.verbose) {
                console.log("\n[+] " + algorithm + " digest result");
                toHex("Output", result);
                toBase64("Output", result);
                console.log("=======================================================");
                
                if (config.printStack) {
                    console.log("    调用堆栈:\n    " + getStackTrace());
                }
            }
            
            return result;
        };
        
        // 2. 拦截Cipher (加密解密)
        var Cipher = Java.use("javax.crypto.Cipher");
        
        // 拦截init方法
        Cipher.init.overload("int", "java.security.Key").implementation = function(opmode, key) {
            var operation = opmode === 1 ? "加密" : "解密";
            var algorithm = this.getAlgorithm();
            
            if (config.verbose) {
                console.log("\n[+] " + algorithm + " init (" + operation + ")");
                console.log("算法: " + algorithm);
                var keyBytes = key.getEncoded();
                toUtf8("Key", keyBytes);
                toHex("Key", keyBytes);
                toBase64("Key", keyBytes);
                console.log("=======================================================");
                
                if (config.printStack) {
                    console.log("    调用堆栈:\n    " + getStackTrace());
                }
            }
            
            return this.init(opmode, key);
        };
        
        // 拦截带IV的init方法
        Cipher.init.overload("int", "java.security.Key", "java.security.spec.AlgorithmParameterSpec").implementation = function(opmode, key, spec) {
            var operation = opmode === 1 ? "加密" : "解密";
            var algorithm = this.getAlgorithm();
            
            if (config.verbose) {
                console.log("\n[+] " + algorithm + " init (" + operation + ")");
                console.log("算法: " + algorithm);
                var keyBytes = key.getEncoded();
                toUtf8("Key", keyBytes);
                toHex("Key", keyBytes);
                toBase64("Key", keyBytes);
                
                // 尝试获取IV
                if (spec.$className === "javax.crypto.spec.IvParameterSpec") {
                    try {
                        var IvParameterSpec = Java.use("javax.crypto.spec.IvParameterSpec");
                        var iv = Java.cast(spec, IvParameterSpec).getIV();
                        toUtf8("IV", iv);
                        toHex("IV", iv);
                        toBase64("IV", iv);
                    } catch (e) {
                        console.log("无法获取IV: " + e);
                    }
                }
                
                console.log("=======================================================");
                
                if (config.printStack) {
                    console.log("    调用堆栈:\n    " + getStackTrace());
                }
            }
            
            return this.init(opmode, key, spec);
        };
        
        // 拦截doFinal方法
        Cipher.doFinal.overload("[B").implementation = function(input) {
            var algorithm = this.getAlgorithm();
            var operation = "未知";
            
            // 正确获取操作模式
            try {
                // 使用反射获取opmode字段
                var cipherObj = this;
                var cipherClass = Java.use("javax.crypto.Cipher");
                
                // 常量定义
                var ENCRYPT_MODE = cipherClass.ENCRYPT_MODE.value;
                var DECRYPT_MODE = cipherClass.DECRYPT_MODE.value;
                
                // 通过比较当前对象的实例与常量判断模式
                Java.perform(function() {
                    try {
                        var cipherField = Java.cast(cipherObj, cipherClass).class.getDeclaredField("mode");
                        cipherField.setAccessible(true);
                        var modeValue = cipherField.getInt(cipherObj);
                        
                        if (modeValue === ENCRYPT_MODE) {
                            operation = "加密";
                        } else if (modeValue === DECRYPT_MODE) {
                            operation = "解密";
                        }
                    } catch (e) {
                        // 如果反射失败，使用算法名称推断
                        if (algorithm.indexOf("/ECB") !== -1 || 
                            algorithm.indexOf("/CBC") !== -1 || 
                            algorithm.indexOf("AES") !== -1 || 
                            algorithm.indexOf("DES") !== -1) {
                            // 根据输入和输出数据长度推断
                            operation = "加密/解密";
                        }
                    }
                });
            } catch (e) {
                console.log("[-] 无法确定操作模式: " + e);
            }
            
            if (config.verbose) {
                console.log("\n[+] " + algorithm + " doFinal (" + operation + ")");
                toUtf8("Input", input);
                toHex("Input", input);
                toBase64("Input", input);
            }
            
            var result = this.doFinal(input);
            
            if (config.verbose) {
                toUtf8("Output", result);
                toHex("Output", result);
                toBase64("Output", result);
                console.log("=======================================================");
                
                if (config.printStack) {
                    console.log("    调用堆栈:\n    " + getStackTrace());
                }
            }
            
            return result;
        };
        
        // 3. 拦截Mac (消息认证码)
        var Mac = Java.use("javax.crypto.Mac");
        
        // 拦截init方法
        Mac.init.overload("java.security.Key").implementation = function(key) {
            var algorithm = this.getAlgorithm();
            
            if (config.verbose) {
                console.log("\n[+] " + algorithm + " init");
                var keyBytes = key.getEncoded();
                toUtf8("Key", keyBytes);
                toHex("Key", keyBytes);
                toBase64("Key", keyBytes);
                console.log("=======================================================");
                
                if (config.printStack) {
                    console.log("    调用堆栈:\n    " + getStackTrace());
                }
            }
            
            return this.init(key);
        };
        
        // 拦截doFinal方法
        Mac.doFinal.overload("[B").implementation = function(input) {
            var algorithm = this.getAlgorithm();
            
            if (config.verbose) {
                console.log("\n[+] " + algorithm + " doFinal");
                toUtf8("Input", input);
                toHex("Input", input);
                toBase64("Input", input);
            }
            
            var result = this.doFinal(input);
            
            if (config.verbose) {
                toHex("Output", result);
                toBase64("Output", result);
                console.log("=======================================================");
                
                if (config.printStack) {
                    console.log("    调用堆栈:\n    " + getStackTrace());
                }
            }
            
            return result;
        };
        
        console.log("[+] Java标准加密库Hook设置完成");
    } catch (e) {
        console.log("[-] Java标准加密库Hook设置失败: " + e);
    }

    /**
     * 二、Hook Base64编解码
     */
    try {
        var Base64 = Java.use("android.util.Base64");
        
        // 拦截encode方法
        Base64.encode.overload("[B", "int").implementation = function(input, flags) {
            if (config.verbose) {
                console.log("\n[+] Base64.encode");
                toUtf8("Input", input);
                toHex("Input", input);
            }
            
            var result = this.encode(input, flags);
            
            if (config.verbose) {
                toUtf8("Output", result);
                toHex("Output", result);
                toBase64("Output", result);
                console.log("=======================================================");
                
                if (config.printStack) {
                    console.log("    调用堆栈:\n    " + getStackTrace());
                }
            }
            
            return result;
        };
        
        // 拦截decode方法
        Base64.decode.overload("[B", "int").implementation = function(input, flags) {
            if (config.verbose) {
                console.log("\n[+] Base64.decode");
                toUtf8("Input", input);
                toHex("Input", input);
            }
            
            var result = this.decode(input, flags);
            
            if (config.verbose) {
                toUtf8("Output", result);
                toHex("Output", result);
                toBase64("Output", result);
                console.log("=======================================================");
                
                if (config.printStack) {
                    console.log("    调用堆栈:\n    " + getStackTrace());
                }
            }
            
            return result;
        };
        
        console.log("[+] Base64编解码Hook设置完成");
    } catch (e) {
        console.log("[-] Base64编解码Hook设置失败: " + e);
    }

    /**
     * 修改配置的函数
     */
    global.setCryptoConfig = function(newConfig) {
        for (var key in newConfig) {
            if (config.hasOwnProperty(key)) {
                config[key] = newConfig[key];
                console.log("[+] 加密配置已更新: " + key + " = " + newConfig[key]);
            }
        }
    };

    console.log("[*] 加密解密函数Hook脚本已加载");
    console.log("[*] 使用方法:");
    console.log("    setCryptoConfig({key: value}) - 修改配置");
    console.log("    例如: setCryptoConfig({verbose: false}) - 关闭详细日志");
    console.log("    例如: setCryptoConfig({printStack: true}) - 显示调用堆栈");
}); 