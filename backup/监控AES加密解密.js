/*
 * 脚本名称：监控AES加密解密.js
 * 功能：自动监控应用中的AES加密解密操作，输出密钥、IV、模式、填充方式以及明文密文
 * 适用场景：密码学分析、协议分析、数据加密分析、安全评估
 * 使用方法：
 *   1. frida -U -f 包名 -l 监控AES加密解密.js --no-pause
 *   2. 查看控制台输出，获取AES加解密信息
 * 启动方式说明：
 *   - -U 代表使用USB连接的设备
 *   - -f 代表以spawn方式启动目标应用（推荐，可以捕获启动阶段的加密操作）
 *   - --no-pause 指示Frida不要暂停应用执行，保证App正常运行
 *   - 也可使用 -F 以attach方式附加到已运行的进程
 * 参数说明：
 *   - 包名：目标应用的包名，如com.example.app
 * 监控函数说明：
 *   - Cipher.getInstance: 捕获加密算法、模式和填充方式
 *   - Cipher.init: 捕获密钥、IV和操作模式(加密/解密)
 *   - Cipher.doFinal: 捕获明文和密文内容
 *   - SecretKeySpec: 捕获AES密钥创建
 *   - IvParameterSpec: 捕获初始化向量设置
 * AES算法说明：
 *   - 常见模式: ECB(无IV), CBC(需要IV), CTR, GCM等
 *   - 常见填充: PKCS5Padding, NoPadding等
 *   - 密钥长度: 通常为128位(16字节)、192位(24字节)或256位(32字节)
 *   - IV长度: 通常为16字节(128位)
 * 输出内容：
 *   - 算法详情: 显示AES的工作模式和填充方式
 *   - 操作模式: 加密或解密
 *   - 密钥数据: 以十六进制和Base64格式展示
 *   - IV数据: 以十六进制和Base64格式展示(如果适用)
 *   - 输入数据: 加密前的明文或解密前的密文
 *   - 输出数据: 加密后的密文或解密后的明文
 *   - 调用位置: 调用加密API的代码位置
 * 实际应用场景：
 *   - 分析app内部加密算法和参数
 *   - 提取通讯协议中的加密密钥
 *   - 了解敏感数据的保护机制
 *   - 辅助安全评估和渗透测试
 * 注意事项：
 *   - 某些加固应用需配合反检测脚本
 *   - 输出包含敏感信息，请在安全环境使用
 *   - 本脚本仅监控Java层AES实现，Native层需使用其他方法
 */

// 监控AES加密解密
Java.perform(function () {
    // 辅助函数：将字节数组转换为十六进制字符串
    function bytesToHex(bytes) {
        var hex = '';
        for (var i = 0; i < bytes.length; i++) {
            var b = (bytes[i] & 0xFF).toString(16);
            if (b.length == 1) hex += '0';
            hex += b;
        }
        return hex;
    }
    
    // 辅助函数：智能地将输入数据转换为可读格式
    function formatData(bytes) {
        if (!bytes) return "<null>";
        
        try {
            // 检查是否为可见字符串
            var isPrintable = true;
            for (var i = 0; i < Math.min(bytes.length, 100); i++) {
                if (bytes[i] < 32 || bytes[i] > 126) {
                    isPrintable = false;
                    break;
                }
            }
            
            // 尝试展示为可打印字符串
            if (isPrintable) {
                return "字符串: " + Java.use('java.lang.String').$new(bytes);
            }
            
            // 显示为十六进制和Base64格式
            var hexStr = bytesToHex(bytes);
            var base64 = Java.use('android.util.Base64').encodeToString(bytes, 0);
            
            if (bytes.length <= 32) {
                return "HEX: " + hexStr + "\nBase64: " + base64;
            } else {
                return "HEX: " + hexStr.substring(0, 64) + "... (总长度: " + bytes.length + "字节)\n" +
                       "Base64: " + base64.substring(0, 64) + "... (总长度: " + base64.length + "字符)";
            }
        } catch (e) {
            return "<数据解析错误: " + e + ">";
        }
    }
    
    // 辅助函数：获取简短调用堆栈
    function getStackShort() {
        return Java.use("android.util.Log").getStackTraceString(
            Java.use("java.lang.Exception").$new()).split('\n').slice(2, 5).join('\n    ');
    }
    
    // 保存Cipher对象的算法信息，用于关联init和doFinal调用
    var cipherInfo = {};
    
    //===== 监控Cipher类相关方法 =====
    var Cipher = Java.use('javax.crypto.Cipher');
    
    // 监控Cipher.getInstance方法，捕获加密算法、模式和填充方式
    Cipher.getInstance.overload('java.lang.String').implementation = function (transformation) {
        var cipher = this.getInstance(transformation);
        
        // 只记录AES相关算法
        if (transformation && transformation.toUpperCase().indexOf('AES') !== -1) {
            console.log('\n[*] AES Cipher.getInstance: ' + transformation);
            
            // 解析AES的模式和填充
            var mode = "ECB"; // 默认模式
            var padding = "PKCS5Padding"; // 默认填充
            
            var parts = transformation.split('/');
            if (parts.length > 1) {
                mode = parts[1];
            }
            if (parts.length > 2) {
                padding = parts[2];
            }
            
            console.log('    算法: AES');
            console.log('    模式: ' + mode);
            console.log('    填充: ' + padding);
            
            // 关联算法信息到Cipher对象
            cipherInfo[cipher.$handle] = {
                algorithm: "AES",
                mode: mode,
                padding: padding,
                opMode: null,
                key: null,
                iv: null
            };
            
            // 打印调用堆栈
            console.log('    调用堆栈: \n    ' + getStackShort());
        }
        
        return cipher;
    };
    
    // 监控带Provider的getInstance版本
    Cipher.getInstance.overload('java.lang.String', 'java.lang.String').implementation = function (transformation, provider) {
        var cipher = this.getInstance(transformation, provider);
        
        if (transformation && transformation.toUpperCase().indexOf('AES') !== -1) {
            console.log('\n[*] AES Cipher.getInstance: ' + transformation + ' (Provider: ' + provider + ')');
            
            // 解析AES的模式和填充
            var mode = "ECB"; // 默认模式
            var padding = "PKCS5Padding"; // 默认填充
            
            var parts = transformation.split('/');
            if (parts.length > 1) {
                mode = parts[1];
            }
            if (parts.length > 2) {
                padding = parts[2];
            }
            
            console.log('    算法: AES');
            console.log('    模式: ' + mode);
            console.log('    填充: ' + padding);
            console.log('    提供者: ' + provider);
            
            // 关联算法信息到Cipher对象
            cipherInfo[cipher.$handle] = {
                algorithm: "AES",
                mode: mode,
                padding: padding,
                provider: provider,
                opMode: null,
                key: null,
                iv: null
            };
            
            console.log('    调用堆栈: \n    ' + getStackShort());
        }
        
        return cipher;
    };
    
    // 监控Cipher.init方法，捕获密钥、IV和操作模式(加密/解密)
    // 初始化方法1: init(int opmode, Key key)
    Cipher.init.overload('int', 'java.security.Key').implementation = function (opmode, key) {
        this.init(opmode, key);
        
        // 检查是否为我们跟踪的AES Cipher
        if (this.$handle in cipherInfo) {
            var info = cipherInfo[this.$handle];
            
            // 保存操作模式和密钥
            info.opMode = opmode === 1 ? "加密(Encrypt)" : "解密(Decrypt)";
            
            try {
                if (key) {
                    info.key = key.getEncoded();
                    console.log('[*] AES Cipher.init');
                    console.log('    操作: ' + info.opMode);
                    console.log('    密钥: ' + formatData(info.key));
                    console.log('    注意: 未设置IV，使用默认全0');
                }
            } catch (e) {
                console.log('    无法获取密钥: ' + e);
            }
        }
    };
    
    // 初始化方法2: init(int opmode, Key key, AlgorithmParameterSpec params)
    Cipher.init.overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec').implementation = function (opmode, key, params) {
        this.init(opmode, key, params);
        
        // 检查是否为我们跟踪的AES Cipher
        if (this.$handle in cipherInfo) {
            var info = cipherInfo[this.$handle];
            
            // 保存操作模式和密钥
            info.opMode = opmode === 1 ? "加密(Encrypt)" : "解密(Decrypt)";
            
            try {
                if (key) {
                    info.key = key.getEncoded();
                }
                
                // 尝试提取IV
                if (params) {
                    var IvParameterSpec = Java.use('javax.crypto.spec.IvParameterSpec');
                    if (params.getClass().getName() === IvParameterSpec.class.getName()) {
                        info.iv = IvParameterSpec.cast(params).getIV();
                    }
                }
                
                console.log('[*] AES Cipher.init');
                console.log('    操作: ' + info.opMode);
                console.log('    密钥: ' + formatData(info.key));
                
                if (info.iv) {
                    console.log('    IV: ' + formatData(info.iv));
                } else {
                    console.log('    IV: 未设置或非IvParameterSpec类型');
                }
            } catch (e) {
                console.log('    参数提取错误: ' + e);
            }
        }
    };
    
    // 监控Cipher.doFinal方法，捕获加密/解密的输入输出
    // doFinal方法1: doFinal(byte[] input)
    Cipher.doFinal.overload('[B').implementation = function (input) {
        var result;
        
        try {
            result = this.doFinal(input);
        } catch (e) {
            console.log('\n[!] AES操作失败: ' + e.toString());
            throw e;
        }
        
        // 检查是否为我们跟踪的AES Cipher
        if (this.$handle in cipherInfo) {
            var info = cipherInfo[this.$handle];
            
            console.log('\n[*] AES ' + info.opMode);
            console.log('    模式: AES/' + info.mode + '/' + info.padding);
            
            if (info.key) {
                console.log('    密钥: ' + formatData(info.key));
            }
            
            if (info.iv) {
                console.log('    IV: ' + formatData(info.iv));
            } else if (info.mode !== "ECB") {
                console.log('    IV: 未捕获到IV');
            }
            
            console.log('    输入数据: ' + formatData(input));
            console.log('    输出数据: ' + formatData(result));
            console.log('    调用堆栈: \n    ' + getStackShort());
        }
        
        return result;
    };
    
    // doFinal方法2: doFinal(byte[] input, int inputOffset, int inputLen)
    Cipher.doFinal.overload('[B', 'int', 'int').implementation = function (input, offset, len) {
        var result;
        
        try {
            result = this.doFinal(input, offset, len);
        } catch (e) {
            console.log('\n[!] AES操作失败: ' + e.toString());
            throw e;
        }
        
        // 检查是否为我们跟踪的AES Cipher
        if (this.$handle in cipherInfo) {
            var info = cipherInfo[this.$handle];
            
            console.log('\n[*] AES ' + info.opMode + ' (带偏移量)');
            console.log('    模式: AES/' + info.mode + '/' + info.padding);
            
            if (info.key) {
                console.log('    密钥: ' + formatData(info.key));
            }
            
            if (info.iv) {
                console.log('    IV: ' + formatData(info.iv));
            } else if (info.mode !== "ECB") {
                console.log('    IV: 未捕获到IV');
            }
            
            try {
                // 提取实际使用的部分数据
                var usedData = Java.array('byte', input.slice(offset, offset + len));
                console.log('    部分输入数据: ' + formatData(usedData) + ' (偏移: ' + offset + ', 长度: ' + len + ')');
            } catch (e) {
                console.log('    输入数据: 无法提取偏移数据: ' + e);
            }
            
            console.log('    输出数据: ' + formatData(result));
            console.log('    调用堆栈: \n    ' + getStackShort());
        }
        
        return result;
    };
    
    // doFinal方法3: doFinal()
    Cipher.doFinal.overload().implementation = function () {
        var result;
        
        try {
            result = this.doFinal();
        } catch (e) {
            console.log('\n[!] AES操作失败: ' + e.toString());
            throw e;
        }
        
        // 检查是否为我们跟踪的AES Cipher
        if (this.$handle in cipherInfo) {
            var info = cipherInfo[this.$handle];
            
            console.log('\n[*] AES ' + info.opMode + ' (完成之前update的数据)');
            console.log('    模式: AES/' + info.mode + '/' + info.padding);
            
            if (info.key) {
                console.log('    密钥: ' + formatData(info.key));
            }
            
            if (info.iv) {
                console.log('    IV: ' + formatData(info.iv));
            } else if (info.mode !== "ECB") {
                console.log('    IV: 未捕获到IV');
            }
            
            console.log('    输入数据: <使用之前update()方法提供>');
            console.log('    输出数据: ' + formatData(result));
            console.log('    调用堆栈: \n    ' + getStackShort());
        }
        
        return result;
    };
    
    // 监控update方法，捕获分块加密/解密的数据
    Cipher.update.overload('[B').implementation = function (input) {
        var result = this.update(input);
        
        // 检查是否为我们跟踪的AES Cipher
        if (this.$handle in cipherInfo) {
            var info = cipherInfo[this.$handle];
            
            console.log('\n[*] AES ' + info.opMode + ' (update)');
            console.log('    模式: AES/' + info.mode + '/' + info.padding);
            console.log('    更新输入数据: ' + formatData(input));
            console.log('    部分输出: ' + formatData(result));
        }
        
        return result;
    };
    
    //===== 监控密钥规范类 =====
    
    // 监控SecretKeySpec构造，捕获AES密钥创建
    var SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
    SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function (keyData, algorithm) {
        var result = this.$init(keyData, algorithm);
        
        if (algorithm && algorithm.toUpperCase().indexOf('AES') !== -1) {
            console.log('\n[*] 创建AES密钥');
            console.log('    算法: ' + algorithm);
            console.log('    密钥数据: ' + formatData(keyData));
            console.log('    密钥长度: ' + keyData.length + ' 字节');
            console.log('    调用堆栈: \n    ' + getStackShort());
        }
        
        return result;
    };
    
    // 监控IvParameterSpec构造，捕获IV设置
    var IvParameterSpec = Java.use('javax.crypto.spec.IvParameterSpec');
    IvParameterSpec.$init.overload('[B').implementation = function (ivData) {
        var result = this.$init(ivData);
        
        console.log('\n[*] 创建IV参数');
        console.log('    IV数据: ' + formatData(ivData));
        console.log('    IV长度: ' + ivData.length + ' 字节');
        console.log('    调用堆栈: \n    ' + getStackShort());
        
        return result;
    };
    
    console.log("[*] AES加密解密监控已启动");
    console.log("[*] 监控范围: Cipher(AES相关)、SecretKeySpec、IvParameterSpec");
}); 