/*
 * 脚本名称：通杀PBKDF2密钥派生.js
 * 功能：全面监控PBKDF2(Password-Based Key Derivation Function 2)密钥派生算法的使用，分析参数安全性
 * 适用场景：密码学分析、安全协议分析、数据加密解密、密码安全评估
 * 使用方法：
 *   1. frida -U -f 包名 -l 通杀PBKDF2密钥派生.js --no-pause
 *   2. 查看控制台输出，获取PBKDF2参数和结果
 * 启动方式说明：
 *   - -U 代表使用USB连接的设备
 *   - -f 代表以spawn方式启动目标应用（推荐，可以捕获启动阶段的密钥派生）
 *   - --no-pause 指示Frida不要暂停应用执行，保证App正常运行
 *   - 也可使用 -F 以attach方式附加到已运行的进程
 * 参数说明：
 *   - 包名：目标应用的包名，如com.example.app
 * 监控范围：
 *   - Java层: javax.crypto.spec.PBEKeySpec和SecretKeyFactory的PBKDF2实现
 *   - Native层: OpenSSL/BoringSSL的PKCS5_PBKDF2_HMAC函数
 *   - 第三方库: 常见的第三方密码学库中的PBKDF2实现
 *   - 安全评估: 对迭代次数、盐值、密钥长度进行安全评估
 * PBKDF2算法说明：
 *   - 目的: PBKDF2通过反复哈希操作，延长从密码生成密钥的时间，从而增加暴力破解的难度
 *   - 标准: PKCS #5 v2.0 / RFC 2898定义
 *   - 参数: 原始密码、盐值(Salt)、迭代次数(Iterations)、输出密钥长度、伪随机函数(通常为HMAC-SHA1/SHA256)
 *   - 安全性关键因素: 
 *       - 迭代次数越高越安全(2023年建议至少310000次)
 *       - 盐值应随机且唯一(至少16字节)
 *       - 输出密钥长度应足够长(至少32字节/256位)
 *   - 常用场景: 密码存储、加密密钥派生、身份认证令牌生成
 * 输出内容：
 *   - 密码：原始输入密码（敏感信息）
 *   - 盐值：防止彩虹表攻击的随机值
 *   - 迭代次数：提高计算复杂度的重复哈希次数
 *   - 输出长度：生成的密钥长度
 *   - 生成密钥：最终派生的密钥（十六进制格式）
 *   - 安全评估：对参数安全性的评估结果
 *   - 调用位置：调用PBKDF2的代码位置
 * 常见安全问题：
 *   - 迭代次数过低(小于10000)，易受暴力破解
 *   - 使用固定盐值或过短盐值
 *   - 密钥长度不足
 *   - 使用弱哈希函数(如MD5)作为PRF
 * 注意事项：
 *   - 某些加固应用需配合反检测脚本使用
 *   - 输出包含敏感信息，请在安全环境中使用
 *   - 大量密钥派生操作可能对应用性能有影响
 */

// 通杀PBKDF2密钥派生
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
                return "字符串: " + Java.use('java.lang.String').$new(bytes, 'UTF-8');
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
            Java.use("java.lang.Exception").$new()).split('\n').slice(2, 7).join('\n    ');
    }
    
    // 辅助函数：评估PBKDF2参数安全性
    function evaluatePBKDF2Security(salt, iterations, keyLength) {
        var issues = [];
        var recommendations = [];
        
        // 评估迭代次数
        if (!iterations) {
            issues.push("未指定迭代次数，使用默认值");
        } else if (iterations < 1000) {
            issues.push("迭代次数极低 (" + iterations + ")，安全性严重不足");
            recommendations.push("推荐迭代次数: 至少310,000次(2023年OWASP建议)");
        } else if (iterations < 10000) {
            issues.push("迭代次数过低 (" + iterations + ")，低于安全标准");
            recommendations.push("推荐迭代次数: 至少310,000次(2023年OWASP建议)");
        } else if (iterations < 100000) {
            issues.push("迭代次数可接受但不理想 (" + iterations + ")");
            recommendations.push("考虑增加迭代次数至310,000次以上");
        }
        
        // 评估盐值
        if (!salt) {
            issues.push("未使用盐值，极易受到彩虹表攻击");
            recommendations.push("推荐使用至少16字节的随机盐值");
        } else if (salt.length < 8) {
            issues.push("盐值长度不足 (" + salt.length + " 字节)");
            recommendations.push("推荐盐值长度至少16字节");
        }
        
        // 检测盐值是否全为0或固定值
        if (salt && salt.length > 0) {
            var isAllZeros = true;
            var isAllSame = true;
            var firstByte = salt[0];
            
            for (var i = 0; i < salt.length; i++) {
                if (salt[i] !== 0) {
                    isAllZeros = false;
                }
                if (salt[i] !== firstByte) {
                    isAllSame = false;
                }
            }
            
            if (isAllZeros) {
                issues.push("盐值全为零，严重降低安全性");
                recommendations.push("使用安全随机数生成器产生盐值");
            } else if (isAllSame) {
                issues.push("盐值为固定重复值，降低安全性");
                recommendations.push("使用安全随机数生成器产生盐值");
            }
        }
        
        // 评估密钥长度
        if (!keyLength) {
            issues.push("未指定输出密钥长度");
        } else if (keyLength < 128) {
            issues.push("密钥长度过短 (" + keyLength + " bits)，安全性不足");
            recommendations.push("推荐密钥长度至少256位(32字节)");
        } else if (keyLength < 256) {
            issues.push("密钥长度可接受但不理想 (" + keyLength + " bits)");
            recommendations.push("考虑使用至少256位的密钥长度");
        }
        
        return {
            issues: issues,
            recommendations: recommendations
        };
    }
    
    // 监控PBEKeySpec构造函数获取PBKDF2参数
    var PBEKeySpec = Java.use('javax.crypto.spec.PBEKeySpec');
    
    // 带完整参数的构造函数
    PBEKeySpec.$init.overload('[C', '[B', 'int', 'int').implementation = function(password, salt, iterationCount, keyLength) {
        console.log('\n[*] PBKDF2密钥派生参数:');
        
        // 显示密码（敏感信息，生产环境应谨慎显示）
        try {
            console.log('    密码: ' + Java.use('java.lang.String').$new(password));
        } catch (e) {
            console.log('    密码: <无法显示>');
        }
        
        // 显示盐值
        if (salt) {
            console.log('    盐值: ' + formatData(salt));
            console.log('    盐值长度: ' + salt.length + ' 字节');
        } else {
            console.log('    盐值: null (严重安全风险)');
        }
        
        // 显示迭代次数和密钥长度
        console.log('    迭代次数: ' + iterationCount);
        console.log('    密钥长度: ' + keyLength + ' bits (' + (keyLength / 8) + ' 字节)');
        
        // 安全评估
        var security = evaluatePBKDF2Security(salt, iterationCount, keyLength);
        
        if (security.issues.length > 0) {
            console.log('    [!] 安全评估问题:');
            for (var i = 0; i < security.issues.length; i++) {
                console.log('        - ' + security.issues[i]);
            }
        }
        
        if (security.recommendations.length > 0) {
            console.log('    [!] 安全建议:');
            for (var i = 0; i < security.recommendations.length; i++) {
                console.log('        - ' + security.recommendations[i]);
            }
        }
        
        // 打印调用堆栈
        console.log('    调用堆栈: ');
        console.log('    ' + getStackShort());
        
        return this.$init(password, salt, iterationCount, keyLength);
    };
    
    // 不指定密钥长度的构造函数
    try {
        PBEKeySpec.$init.overload('[C', '[B', 'int').implementation = function(password, salt, iterationCount) {
            console.log('\n[*] PBKDF2密钥派生参数(未指定密钥长度):');
            
            // 显示密码（敏感信息，生产环境应谨慎显示）
            try {
                console.log('    密码: ' + Java.use('java.lang.String').$new(password));
            } catch (e) {
                console.log('    密码: <无法显示>');
            }
            
            // 显示盐值
            if (salt) {
                console.log('    盐值: ' + formatData(salt));
                console.log('    盐值长度: ' + salt.length + ' 字节');
            } else {
                console.log('    盐值: null (严重安全风险)');
            }
            
            // 显示迭代次数
            console.log('    迭代次数: ' + iterationCount);
            console.log('    密钥长度: 未指定(将使用默认值)');
            
            // 安全评估
            var security = evaluatePBKDF2Security(salt, iterationCount, null);
            
            if (security.issues.length > 0) {
                console.log('    [!] 安全评估问题:');
                for (var i = 0; i < security.issues.length; i++) {
                    console.log('        - ' + security.issues[i]);
                }
            }
            
            if (security.recommendations.length > 0) {
                console.log('    [!] 安全建议:');
                for (var i = 0; i < security.recommendations.length; i++) {
                    console.log('        - ' + security.recommendations[i]);
                }
            }
            
            // 打印调用堆栈
            console.log('    调用堆栈: ');
            console.log('    ' + getStackShort());
            
            return this.$init(password, salt, iterationCount);
        };
    } catch (e) {
        console.log("[-] 监控PBEKeySpec三参数构造函数失败: " + e);
    }
    
    // 监控SecretKeyFactory.generateSecret获取PBKDF2结果
    var SecretKeyFactory = Java.use('javax.crypto.SecretKeyFactory');
    SecretKeyFactory.generateSecret.implementation = function(keySpec) {
        var result = this.generateSecret(keySpec);
        
        // 检查是否是PBKDF2算法
        var algorithm = this.getAlgorithm();
        if (algorithm.indexOf('PBKDF2') !== -1) {
            try {
                var secretKey = result;
                var encoded = secretKey.getEncoded();
                
                console.log('[*] PBKDF2密钥生成结果:');
                console.log('    算法: ' + algorithm);
                console.log('    生成密钥: ' + formatData(encoded));
                console.log('    密钥长度: ' + encoded.length + ' 字节');
            } catch (e) {
                console.log('    无法获取生成的密钥: ' + e);
            }
        }
        
        return result;
    };
    
    // 监控SecretKeyFactory.getInstance获取使用的算法
    SecretKeyFactory.getInstance.overload('java.lang.String').implementation = function(algorithm) {
        var factory = this.getInstance(algorithm);
        
        // 检查是否是PBKDF2算法
        if (algorithm.indexOf('PBKDF2') !== -1) {
            console.log('\n[*] 获取PBKDF2 SecretKeyFactory: ' + algorithm);
            
            // 根据算法细节分析安全性
            if (algorithm.indexOf('SHA1') !== -1) {
                console.log('    [!] 注意: 使用SHA-1作为PRF，建议使用SHA-256或更强的哈希函数');
            }
            if (algorithm.indexOf('SHA256') !== -1 || algorithm.indexOf('SHA-256') !== -1) {
                console.log('    [+] 良好: 使用SHA-256作为PRF');
            }
            if (algorithm.indexOf('SHA512') !== -1 || algorithm.indexOf('SHA-512') !== -1) {
                console.log('    [+] 优秀: 使用SHA-512作为PRF');
            }
            
            console.log('    调用堆栈: ');
            console.log('    ' + getStackShort());
        }
        
        return factory;
    };
    
    // 监控带Provider的getInstance版本
    try {
        SecretKeyFactory.getInstance.overload('java.lang.String', 'java.lang.String').implementation = function(algorithm, provider) {
            var factory = this.getInstance(algorithm, provider);
            
            // 检查是否是PBKDF2算法
            if (algorithm.indexOf('PBKDF2') !== -1) {
                console.log('\n[*] 获取PBKDF2 SecretKeyFactory: ' + algorithm + ' (Provider: ' + provider + ')');
                
                // 根据算法细节分析安全性
                if (algorithm.indexOf('SHA1') !== -1) {
                    console.log('    [!] 注意: 使用SHA-1作为PRF，建议使用SHA-256或更强的哈希函数');
                }
                if (algorithm.indexOf('SHA256') !== -1 || algorithm.indexOf('SHA-256') !== -1) {
                    console.log('    [+] 良好: 使用SHA-256作为PRF');
                }
                if (algorithm.indexOf('SHA512') !== -1 || algorithm.indexOf('SHA-512') !== -1) {
                    console.log('    [+] 优秀: 使用SHA-512作为PRF');
                }
                
                console.log('    调用堆栈: ');
                console.log('    ' + getStackShort());
            }
            
            return factory;
        };
    } catch (e) {}
    
    // 监控Mac算法，某些PBKDF2是通过HmacSHA1等实现的
    var Mac = Java.use('javax.crypto.Mac');
    Mac.getInstance.overload('java.lang.String').implementation = function(algorithm) {
        var mac = this.getInstance(algorithm);
        
        if (algorithm.indexOf('Hmac') !== -1) {
            // 只记录可能与PBKDF2相关的Mac实例
            var stackTrace = getStackShort();
            if (stackTrace.indexOf('PBKDF2') !== -1 ||
                stackTrace.indexOf('PBE') !== -1 ||
                stackTrace.indexOf('KeyDerivation') !== -1) {
                console.log('[*] 获取Mac算法(用于PBKDF2): ' + algorithm);
                console.log('    调用堆栈: ');
                console.log('    ' + stackTrace);
            }
        }
        
        return mac;
    };
    
    // 监控Java 9+ KeyDerivationFunc接口（如果存在）
    try {
        var keyDerivationClasses = [
            'java.security.spec.KeyDerivationFunc',
            'javax.crypto.KeyDerivationFunction'
        ];
        
        for (var i = 0; i < keyDerivationClasses.length; i++) {
            try {
                var KeyDerivationClass = Java.use(keyDerivationClasses[i]);
                if (KeyDerivationClass) {
                    var methods = KeyDerivationClass.class.getDeclaredMethods();
                    for (var j = 0; j < methods.length; j++) {
                        var methodName = methods[j].getName();
                        if (methodName.indexOf('derive') !== -1) {
                            try {
                                KeyDerivationClass[methodName].implementation = function() {
                                    console.log('[*] 检测到密钥派生函数调用: ' + this.getClass().getName() + '.' + methodName);
                                    var result = this[methodName].apply(this, arguments);
                                    return result;
                                };
                            } catch (e) {}
                        }
                    }
                }
            } catch (e) {}
        }
    } catch (e) {}
    
    // Native层监控OpenSSL的PBKDF2实现
    try {
        // 尝试在多个可能的库中查找PKCS5_PBKDF2_HMAC函数
        var libraries = ['libcrypto.so', 'libssl.so', null]; // null表示在所有已加载的库中搜索
        var pbkdf2Func = null;
        
        for (var i = 0; i < libraries.length; i++) {
            // 查找标准PBKDF2函数
            pbkdf2Func = Module.findExportByName(libraries[i], 'PKCS5_PBKDF2_HMAC');
            if (pbkdf2Func) {
                console.log('[+] 在' + (libraries[i] || '已加载库') + '中找到PKCS5_PBKDF2_HMAC函数');
                break;
            }
            
            // 查找SHA1变种PBKDF2函数(旧版OpenSSL)
            pbkdf2Func = Module.findExportByName(libraries[i], 'PKCS5_PBKDF2_HMAC_SHA1');
            if (pbkdf2Func) {
                console.log('[+] 在' + (libraries[i] || '已加载库') + '中找到PKCS5_PBKDF2_HMAC_SHA1函数');
                break;
            }
        }
        
        if (pbkdf2Func) {
            // PKCS5_PBKDF2_HMAC函数原型:
            // int PKCS5_PBKDF2_HMAC(const char *pass, int passlen,
            //                      const unsigned char *salt, int saltlen,
            //                      int iter, const EVP_MD *digest,
            //                      int keylen, unsigned char *out);
            
            Interceptor.attach(pbkdf2Func, {
                onEnter: function(args) {
                    // 保存参数以便在onLeave中使用
                    this.passPtr = args[0];
                    this.passLen = args[1].toInt32();
                    this.saltPtr = args[2];
                    this.saltLen = args[3].toInt32();
                    this.iter = args[4].toInt32();
                    this.keyLen = args[6].toInt32();
                    this.outPtr = args[7];
                    
                    console.log('\n[*] Native PBKDF2调用:');
                    
                    // 尝试显示密码
                    if (this.passPtr && this.passLen > 0) {
                        try {
                            var passBytes = Memory.readByteArray(this.passPtr, this.passLen);
                            var passHex = '';
                            for (var i = 0; i < Math.min(passBytes.byteLength, 32); i++) {
                                var b = passBytes[i].toString(16);
                                if (b.length == 1) passHex += '0';
                                passHex += b;
                            }
                            console.log('    密码(HEX): ' + passHex);
                            
                            // 尝试将密码显示为字符串
                            var isPrintable = true;
                            for (var i = 0; i < passBytes.byteLength; i++) {
                                if (passBytes[i] < 32 || passBytes[i] > 126) {
                                    isPrintable = false;
                                    break;
                                }
                            }
                            if (isPrintable) {
                                console.log('    密码(字符串): ' + Memory.readUtf8String(this.passPtr, this.passLen));
                            }
                        } catch (e) {
                            console.log('    无法读取密码: ' + e);
                        }
                    }
                    
                    // 尝试显示盐值
                    if (this.saltPtr && this.saltLen > 0) {
                        try {
                            var saltBytes = Memory.readByteArray(this.saltPtr, this.saltLen);
                            var saltHex = '';
                            for (var i = 0; i < Math.min(saltBytes.byteLength, 32); i++) {
                                var b = saltBytes[i].toString(16);
                                if (b.length == 1) saltHex += '0';
                                saltHex += b;
                            }
                            console.log('    盐值(HEX): ' + saltHex);
                            console.log('    盐值长度: ' + this.saltLen + ' 字节');
                        } catch (e) {
                            console.log('    无法读取盐值: ' + e);
                        }
                    } else {
                        console.log('    [!] 警告: 未使用盐值或盐值长度为0');
                    }
                    
                    // 显示迭代次数和密钥长度
                    console.log('    迭代次数: ' + this.iter);
                    console.log('    输出密钥长度: ' + this.keyLen + ' 字节');
                    
                    // 安全评估
                    var security = evaluatePBKDF2Security(
                        this.saltPtr && this.saltLen > 0 ? new Array(this.saltLen) : null, 
                        this.iter, 
                        this.keyLen * 8
                    );
                    
                    if (security.issues.length > 0) {
                        console.log('    [!] 安全评估问题:');
                        for (var i = 0; i < security.issues.length; i++) {
                            console.log('        - ' + security.issues[i]);
                        }
                    }
                    
                    if (security.recommendations.length > 0) {
                        console.log('    [!] 安全建议:');
                        for (var i = 0; i < security.recommendations.length; i++) {
                            console.log('        - ' + security.recommendations[i]);
                        }
                    }
                    
                    // 打印调用堆栈
                    console.log('    调用堆栈: ');
                    console.log('    ' + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n    '));
                },
                
                onLeave: function(retval) {
                    // 如果成功并且我们有输出指针
                    if (retval.toInt32() === 1 && this.outPtr && this.keyLen > 0) {
                        try {
                            var outBytes = Memory.readByteArray(this.outPtr, this.keyLen);
                            var outHex = '';
                            for (var i = 0; i < outBytes.byteLength; i++) {
                                var b = outBytes[i].toString(16);
                                if (b.length == 1) outHex += '0';
                                outHex += b;
                            }
                            console.log('[*] Native PBKDF2结果(HEX): ' + outHex);
                            console.log('    结果长度: ' + outBytes.byteLength + ' 字节');
                        } catch (e) {
                            console.log('[*] 无法读取PBKDF2结果: ' + e);
                        }
                    } else {
                        console.log('[*] Native PBKDF2调用返回: ' + retval);
                    }
                }
            });
            
            console.log('[+] 成功Hook Native PBKDF2函数');
        }
    } catch (e) {
        console.log('[-] Hook Native PBKDF2失败: ' + e);
    }
    
    console.log("[*] PBKDF2密钥派生监控已启动");
    console.log("[*] 监控范围: PBEKeySpec, SecretKeyFactory, Native PBKDF2");
    console.log("[*] 安全评估: 参数强度分析，弱点检测");
}); 