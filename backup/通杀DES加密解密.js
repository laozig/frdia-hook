/*
 * 脚本名称：通杀DES加密解密.js
 * 功能：全面监控DES/3DES加密解密操作，捕获密钥、IV、输入输出数据和配置参数
 * 适用场景：DES/3DES逆向、数据还原、协议分析、安全评估
 * 使用方法：
 *   1. frida -U -f 包名 -l 通杀DES加密解密.js --no-pause
 *   2. 查看控制台输出，获取DES输入输出信息
 * 启动方式说明：
 *   - -U 代表使用USB连接的设备
 *   - -f 代表以spawn方式启动目标应用（推荐，可以捕获启动阶段的加密操作）
 *   - --no-pause 指示Frida不要暂停应用执行，保证App正常运行
 *   - 也可使用 -F 以attach方式附加到已运行的进程
 * 参数说明：
 *   - 包名：目标应用的包名，如com.example.app
 * 监控范围：
 *   - DES(Data Encryption Standard)：经典对称加密算法
 *   - 3DES(Triple DES)：三重DES加密，增强安全性的DES变种
 *   - 支持的工作模式：ECB、CBC、CFB、OFB、CTR等
 *   - 支持的填充方式：PKCS5Padding、NoPadding、ISO10126Padding等
 *   - 密钥管理：监控密钥和IV生成、设置
 *   - 输入输出：监控明文、密文传输
 * DES算法特点：
 *   - 密钥长度：标准DES为64位(8字节)，3DES为192位(24字节)
 *   - 分组大小：64位(8字节)
 *   - 工作模式：ECB(无IV)，CBC/CFB/OFB/CTR(需要IV)
 *   - 常见漏洞点：ECB模式密文模式可见，固定密钥硬编码，弱密钥选择
 * 输出内容：
 *   - 加密/解密配置：算法名称、模式、填充方式
 *   - 密钥/IV：用于加密解密的密钥和初始化向量(十六进制和Base64格式)
 *   - 输入数据：加密前的原始数据或解密前的密文
 *   - 输出结果：加密后的密文或解密后的明文
 *   - 调用位置：发起加密/解密的代码位置
 * 常见使用场景：
 *   - 分析应用中的加密数据传输
 *   - 提取敏感信息的加密密钥
 *   - 逆向工程协议中的加密部分
 *   - 验证加密算法实现安全性
 * 注意事项：
 *   - 某些加固应用需配合反检测脚本
 *   - DES已被认为不够安全，但在某些旧系统中仍有使用
 *   - 监控可能包含敏感数据，请谨慎在安全环境使用
 */

// 通杀DES加密解密
Java.perform(function () {
    // 辅助函数：将字节数组转换为十六进制字符串
    function bytesToHex(bytes) {
        if (!bytes) return "<null>";
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
    
    // 获取Java标准库中的Cipher类引用，用于加密解密操作
    var Cipher = Java.use('javax.crypto.Cipher');
    
    // Hook Cipher.getInstance方法，监控DES/3DES算法的实例创建
    Cipher.getInstance.overload('java.lang.String').implementation = function (transformation) {
        // 检查是否包含DES或3DES字符串，识别DES相关的加密操作
        if (transformation && (transformation.toUpperCase().indexOf('DES') !== -1)) {
            console.log('\n[*] 获取DES/3DES Cipher实例: ' + transformation);
            
            // 解析加密参数并输出详细信息
            var parts = transformation.split('/');
            var algorithm = parts[0];
            var mode = parts.length > 1 ? parts[1] : "ECB"; // 默认ECB模式
            var padding = parts.length > 2 ? parts[2] : "PKCS5Padding"; // 默认填充
            
            console.log('    算法: ' + algorithm);
            console.log('    模式: ' + mode);
            console.log('    填充: ' + padding);
            
            // 检查是否使用不安全的ECB模式
            if (mode === "ECB") {
                console.log('    [!] 警告: 使用ECB模式，可能存在安全隐患');
            }
            
            // 保存算法信息到Cipher对象
            var cipher = this.getInstance(transformation);
            cipherInfo[cipher.$handle] = {
                algorithm: algorithm,
                mode: mode,
                padding: padding,
                opMode: null,
                key: null,
                iv: null
            };
            
            // 输出调用堆栈
            console.log('    调用堆栈: ');
            console.log('    ' + getStackShort());
            
            return cipher;
        }
        
        // 非DES相关的算法，直接执行原始方法
        return this.getInstance(transformation);
    };
    
    // Hook带Provider的getInstance版本
    Cipher.getInstance.overload('java.lang.String', 'java.lang.String').implementation = function (transformation, provider) {
        if (transformation && (transformation.toUpperCase().indexOf('DES') !== -1)) {
            console.log('\n[*] 获取DES/3DES Cipher实例: ' + transformation + ' (Provider: ' + provider + ')');
            
            // 解析加密参数并输出详细信息
            var parts = transformation.split('/');
            var algorithm = parts[0];
            var mode = parts.length > 1 ? parts[1] : "ECB"; // 默认ECB模式
            var padding = parts.length > 2 ? parts[2] : "PKCS5Padding"; // 默认填充
            
            console.log('    算法: ' + algorithm);
            console.log('    模式: ' + mode);
            console.log('    填充: ' + padding);
            
            if (mode === "ECB") {
                console.log('    [!] 警告: 使用ECB模式，可能存在安全隐患');
            }
            
            var cipher = this.getInstance(transformation, provider);
            cipherInfo[cipher.$handle] = {
                algorithm: algorithm,
                mode: mode,
                padding: padding,
                provider: provider,
                opMode: null,
                key: null,
                iv: null
            };
            
            return cipher;
        }
        
        return this.getInstance(transformation, provider);
    };
    
    // 监控Cipher.init方法，捕获密钥、IV和操作模式(加密/解密)
    // 初始化方法1: init(int opmode, Key key)
    Cipher.init.overload('int', 'java.security.Key').implementation = function (opmode, key) {
        this.init(opmode, key);
        
        // 检查是否为我们跟踪的DES Cipher
        if (this.$handle in cipherInfo) {
            var info = cipherInfo[this.$handle];
            
            // 保存操作模式和密钥
            info.opMode = opmode === 1 ? "加密(Encrypt)" : "解密(Decrypt)";
            
            try {
                if (key) {
                    info.key = key.getEncoded();
                    console.log('[*] DES/3DES Cipher.init');
                    console.log('    操作: ' + info.opMode);
                    console.log('    密钥: ' + formatData(info.key));
                    console.log('    密钥长度: ' + info.key.length + ' 字节');
                    
                    // 检查DES密钥弱点
                    if (info.algorithm === "DES" && info.key.length === 8) {
                        console.log('    [!] 注意: 使用标准DES 56位密钥 (8字节含校验位)');
                    }
                    if (info.algorithm === "DESede" && info.key.length === 24) {
                        console.log('    [!] 注意: 使用3DES 168位密钥 (24字节含校验位)');
                    }
                    
                    if (info.mode !== "ECB") {
                        console.log('    [!] 警告: ' + info.mode + '模式需要IV，但未设置IV参数');
                    }
                }
            } catch (e) {
                console.log('    无法获取密钥: ' + e);
            }
        }
    };
    
    // 初始化方法2: init(int opmode, Key key, AlgorithmParameterSpec params)
    Cipher.init.overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec').implementation = function (opmode, key, params) {
        this.init(opmode, key, params);
        
        // 检查是否为我们跟踪的DES Cipher
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
                
                console.log('[*] DES/3DES Cipher.init');
                console.log('    操作: ' + info.opMode);
                console.log('    密钥: ' + formatData(info.key));
                console.log('    密钥长度: ' + info.key.length + ' 字节');
                
                if (info.iv) {
                    console.log('    IV: ' + formatData(info.iv));
                    console.log('    IV长度: ' + info.iv.length + ' 字节');
                } else {
                    console.log('    IV: 未设置或非IvParameterSpec类型');
                    if (info.mode !== "ECB") {
                        console.log('    [!] 警告: ' + info.mode + '模式需要IV，但未能提取IV参数');
                    }
                }
            } catch (e) {
                console.log('    参数提取错误: ' + e);
            }
        }
    };
    
    // 监控Cipher.doFinal方法，捕获实际的加密/解密操作
    // doFinal方法1: doFinal(byte[] input)
    Cipher.doFinal.overload('[B').implementation = function (input) {
        var result;
        
        try {
            result = this.doFinal(input);
        } catch (e) {
            console.log('\n[!] DES/3DES操作失败: ' + e.toString());
            throw e;
        }
        
        // 检查是否为我们跟踪的DES Cipher
        if (this.$handle in cipherInfo) {
            var info = cipherInfo[this.$handle];
            
            // 只处理DES/3DES相关算法
            if (info.algorithm.toUpperCase().indexOf('DES') !== -1) {
                console.log('\n[*] DES/3DES ' + info.opMode + ' 操作:');
                console.log('    算法详情: ' + info.algorithm + '/' + info.mode + '/' + info.padding);
                
                if (info.key) {
                    console.log('    密钥: ' + formatData(info.key));
                    console.log('    密钥长度: ' + info.key.length + ' 字节');
                }
                
                if (info.iv) {
                    console.log('    IV: ' + formatData(info.iv));
                } else if (info.mode !== "ECB") {
                    console.log('    IV: 未设置 (可能使用默认全零IV)');
                }
                
                console.log('    输入数据: ' + formatData(input));
                console.log('    输出数据: ' + formatData(result));
                console.log('    调用堆栈: \n    ' + getStackShort());
            }
        }
        
        return result;
    };
    
    // doFinal方法2: doFinal(byte[] input, int inputOffset, int inputLen)
    Cipher.doFinal.overload('[B', 'int', 'int').implementation = function (input, offset, len) {
        var result;
        
        try {
            result = this.doFinal(input, offset, len);
        } catch (e) {
            console.log('\n[!] DES/3DES操作失败: ' + e.toString());
            throw e;
        }
        
        // 检查是否为我们跟踪的DES Cipher
        if (this.$handle in cipherInfo) {
            var info = cipherInfo[this.$handle];
            
            // 只处理DES/3DES相关算法
            if (info.algorithm.toUpperCase().indexOf('DES') !== -1) {
                console.log('\n[*] DES/3DES ' + info.opMode + ' 操作 (带偏移量):');
                console.log('    算法详情: ' + info.algorithm + '/' + info.mode + '/' + info.padding);
                
                if (info.key) {
                    console.log('    密钥: ' + formatData(info.key));
                }
                
                if (info.iv) {
                    console.log('    IV: ' + formatData(info.iv));
                } else if (info.mode !== "ECB") {
                    console.log('    IV: 未设置');
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
        }
        
        return result;
    };
    
    // 监控update方法，捕获分块加密/解密的数据
    Cipher.update.overload('[B').implementation = function (input) {
        var result = this.update(input);
        
        // 检查是否为我们跟踪的DES Cipher
        if (this.$handle in cipherInfo) {
            var info = cipherInfo[this.$handle];
            
            // 只处理DES/3DES相关算法
            if (info.algorithm.toUpperCase().indexOf('DES') !== -1) {
                console.log('\n[*] DES/3DES ' + info.opMode + ' update操作:');
                console.log('    算法详情: ' + info.algorithm + '/' + info.mode + '/' + info.padding);
                console.log('    更新输入数据: ' + formatData(input));
                console.log('    部分输出: ' + formatData(result));
            }
        }
        
        return result;
    };
    
    // 监控DES密钥创建
    var SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
    SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function(keyData, algorithm) {
        if (algorithm && algorithm.toUpperCase().indexOf('DES') !== -1) {
            console.log('\n[*] 创建DES/3DES密钥');
            console.log('    算法: ' + algorithm);
            console.log('    密钥数据: ' + formatData(keyData));
            console.log('    密钥长度: ' + keyData.length + ' 字节');
            
            // 分析密钥安全性
            if (algorithm === "DES" && keyData.length === 8) {
                console.log('    [!] 注意: 使用标准DES 56位密钥 (8字节含校验位)');
                // 检查是否为弱密钥
                var weakKeys = [
                    "0101010101010101", "FEFEFEFEFEFEFEFE", "E0E0E0E0F1F1F1F1", "1F1F1F1F0E0E0E0E"
                ];
                var keyHex = bytesToHex(keyData);
                for (var i = 0; i < weakKeys.length; i++) {
                    if (keyHex.toUpperCase() === weakKeys[i]) {
                        console.log('    [!] 严重警告: 检测到DES弱密钥！');
                        break;
                    }
                }
            }
            if (algorithm === "DESede" && keyData.length === 24) {
                console.log('    [!] 注意: 使用3DES 168位密钥 (24字节含校验位)');
            }
            
            console.log('    调用堆栈: \n    ' + getStackShort());
        }
        
        return this.$init(keyData, algorithm);
    };
    
    // 监控IvParameterSpec创建
    var IvParameterSpec = Java.use('javax.crypto.spec.IvParameterSpec');
    IvParameterSpec.$init.overload('[B').implementation = function(ivData) {
        console.log('\n[*] 创建IV参数');
        console.log('    IV数据: ' + formatData(ivData));
        console.log('    IV长度: ' + ivData.length + ' 字节');
        
        // 检查IV是否全为0或固定值
        var isAllZeros = true;
        var isAllSame = true;
        var firstByte = ivData[0];
        
        for (var i = 0; i < ivData.length; i++) {
            if (ivData[i] !== 0) {
                isAllZeros = false;
            }
            if (ivData[i] !== firstByte) {
                isAllSame = false;
            }
        }
        
        if (isAllZeros) {
            console.log('    [!] 警告: 使用全零IV，存在安全隐患');
        } else if (isAllSame) {
            console.log('    [!] 警告: 使用固定值IV，安全性降低');
        }
        
        console.log('    调用堆栈: \n    ' + getStackShort());
        
        return this.$init(ivData);
    };
    
    console.log("[*] DES/3DES监控已启动");
    console.log("[*] 监控范围: Cipher实例创建, 密钥/IV设置, 加密/解密操作");
    console.log("[*] 监控算法: DES, 3DES(DESede)");
}); 