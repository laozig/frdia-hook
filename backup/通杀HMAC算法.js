/*
 * 脚本名称：通杀HMAC算法.js
 * 功能：全面监控所有HMAC(Hash-based Message Authentication Code)消息认证码算法调用和参数
 * 适用场景：API数据校验、安全协议分析、签名验证分析、加密通信、密码学审计
 * 使用方法：
 *   1. frida -U -f 包名 -l 通杀HMAC算法.js --no-pause
 *   2. 查看控制台输出，获取HMAC调用信息
 * 启动方式说明：
 *   - -U 代表使用USB连接的设备
 *   - -f 代表以spawn方式启动目标应用（推荐，可以捕获启动阶段的HMAC操作）
 *   - --no-pause 指示Frida不要暂停应用执行，保证App正常运行
 *   - 也可使用 -F 以attach方式附加到已运行的进程
 * 参数说明：
 *   - 包名：目标应用的包名，如com.example.app
 * 监控范围：
 *   - javax.crypto.Mac：Java加密扩展包中的HMAC实现
 *   - 支持的算法：HmacMD5、HmacSHA1、HmacSHA256、HmacSHA384、HmacSHA512等
 *   - 密钥管理：SecretKeySpec对象创建和使用
 *   - 数据流：update和doFinal操作的完整数据流
 *   - 常见应用场景检测：JWT签名、API验证、OAuth等
 * HMAC算法作用：
 *   - 用于验证消息的完整性和真实性
 *   - 结合哈希算法和密钥生成消息认证码
 *   - 防止消息被篡改或伪造
 *   - 可验证消息发送者持有相同的密钥
 * HMAC算法安全性：
 *   - 依赖于底层哈希函数的安全性：SHA256/SHA512强于SHA1、MD5
 *   - 密钥长度至少应与哈希输出长度相同
 *   - 密钥应随机生成，不应硬编码
 *   - 不应用于存储密码（应使用专门的密码哈希函数如PBKDF2、bcrypt等）
 * 输出内容：
 *   - 算法名称：使用的HMAC算法，如HmacSHA256
 *   - 密钥信息：用于HMAC计算的密钥（十六进制和Base64格式）
 *   - 输入数据：用于计算HMAC的原始数据
 *   - 输出结果：HMAC计算结果（十六进制和Base64格式）
 *   - 安全检测：JWT令牌识别、算法安全性评估、常见应用场景识别
 *   - 调用位置：发起HMAC计算的代码位置
 * 常见使用场景：
 *   - API请求签名验证
 *   - JWT (JSON Web Token) 签名
 *   - OAuth消息认证
 *   - 安全握手协议
 *   - 数据完整性校验
 *   - 消息防篡改机制
 * 注意事项：
 *   - 输出可能包含敏感信息，请在安全环境使用
 *   - 某些加固应用需配合反检测脚本
 *   - 大型应用可能产生大量HMAC计算，可能需要添加过滤
 */

// 通杀HMAC算法
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
            
            if (isPrintable) {
                var str = Java.use('java.lang.String').$new(bytes);
                // 检查是否为JSON
                if ((str.startsWith('{') && str.endsWith('}')) || 
                    (str.startsWith('[') && str.endsWith(']'))) {
                    return "JSON: " + str;
                }
                // 检查是否为Base64
                if (/^[A-Za-z0-9+/=]+$/.test(str)) {
                    try {
                        var decoded = Java.use('android.util.Base64').decode(str, 0);
                        var decodedStr = Java.use('java.lang.String').$new(decoded);
                        if (isPrintableString(decodedStr)) {
                            return "Base64编码字符串: " + str + "\nBase64解码: " + decodedStr;
                        }
                    } catch (e) {}
                }
                // 普通字符串
                return "字符串: " + str;
            } else {
                // 显示为十六进制和Base64格式
                var hexStr = bytesToHex(bytes);
                var base64 = Java.use('android.util.Base64').encodeToString(bytes, 0);
                
                if (bytes.length <= 32) {
                    return "HEX: " + hexStr + "\nBase64: " + base64;
                } else {
                    return "HEX: " + hexStr.substring(0, 64) + "... (总长度: " + bytes.length + "字节)\n" +
                           "Base64: " + base64.substring(0, 64) + "... (总长度: " + base64.length + "字符)";
                }
            }
        } catch (e) {
            return "<数据解析错误: " + e + ">";
        }
    }
    
    // 辅助函数：检查字符串是否可打印
    function isPrintableString(str) {
        for (var i = 0; i < str.length; i++) {
            var code = str.charCodeAt(i);
            if (code < 32 || code > 126) {
                return false;
            }
        }
        return true;
    }
    
    // 辅助函数：检测潜在的JWT令牌
    function detectJWT(data) {
        try {
            // JWT格式: xxxxx.yyyyy.zzzzz (头.载荷.签名)
            var str = Java.use('java.lang.String').$new(data);
            if (/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(str)) {
                var parts = str.split('.');
                if (parts.length === 3) {
                    try {
                        // 尝试解码头部和载荷
                        var decodedHeader = Java.use('java.lang.String').$new(
                            Java.use('android.util.Base64').decode(parts[0], 0), 'UTF-8');
                        var decodedPayload = Java.use('java.lang.String').$new(
                            Java.use('android.util.Base64').decode(parts[1], 0), 'UTF-8');
                        
                        if (decodedHeader.indexOf('{') === 0 && decodedPayload.indexOf('{') === 0) {
                            return {
                                isJWT: true,
                                header: decodedHeader,
                                payload: decodedPayload,
                                signature: parts[2]
                            };
                        }
                    } catch (e) {}
                }
            }
        } catch (e) {}
        
        return { isJWT: false };
    }
    
    // 辅助函数：评估HMAC算法安全性
    function evaluateHMACSecurity(algorithm, keyLength) {
        var issues = [];
        var recommendations = [];
        
        if (algorithm.indexOf('MD5') !== -1) {
            issues.push("使用基于MD5的HMAC算法，MD5已被证明存在碰撞漏洞");
            recommendations.push("推荐使用HMAC-SHA256或更强的算法");
        } else if (algorithm.indexOf('SHA1') !== -1) {
            issues.push("使用基于SHA-1的HMAC算法，SHA-1在某些应用场景中已不推荐使用");
            recommendations.push("推荐使用HMAC-SHA256或更强的算法");
        }
        
        if (keyLength && keyLength < 16) {
            issues.push("密钥长度较短(" + keyLength + "字节)，可能不足以提供足够的安全强度");
            recommendations.push("HMAC密钥长度建议至少等于哈希输出长度");
        }
        
        return {
            algorithm: algorithm,
            issues: issues,
            recommendations: recommendations,
            isSecure: (algorithm.indexOf('MD5') === -1 && algorithm.indexOf('SHA1') === -1 && (!keyLength || keyLength >= 16))
        };
    }
    
    // 辅助函数：获取简短调用堆栈
    function getStackShort() {
        return Java.use("android.util.Log").getStackTraceString(
            Java.use("java.lang.Exception").$new()).split('\n').slice(2, 5).join('\n    ');
    }
    
    // 存储Mac对象的算法和数据，用于关联不同调用
    var macInfo = {};
    
    // 监控Mac类相关方法
    var Mac = Java.use('javax.crypto.Mac');
    
    // 监控Mac.getInstance方法，捕获使用的算法类型
    Mac.getInstance.overload('java.lang.String').implementation = function (algo) {
        var mac = this.getInstance(algo);
        
        // 仅记录HMAC相关算法
        if (algo && algo.indexOf('Hmac') !== -1) {
            console.log('\n[*] 获取HMAC算法实例: ' + algo);
            
            // 初始化Mac对象信息
            macInfo[mac.$handle] = {
                algorithm: algo,
                key: null,
                inputData: [],
                securityEval: evaluateHMACSecurity(algo)
            };
            
            // 输出算法安全性评估
            var securityEval = macInfo[mac.$handle].securityEval;
            if (securityEval.issues.length > 0) {
                console.log('    [!] 安全性问题:');
                for (var i = 0; i < securityEval.issues.length; i++) {
                    console.log('        - ' + securityEval.issues[i]);
                }
            }
            
            if (securityEval.recommendations.length > 0) {
                console.log('    [!] 安全建议:');
                for (var i = 0; i < securityEval.recommendations.length; i++) {
                    console.log('        - ' + securityEval.recommendations[i]);
                }
            }
            
            // 打印调用堆栈，帮助定位调用代码位置
            console.log('    调用堆栈: \n    ' + getStackShort());
        }
        
        return mac;
    };
    
    // 监控Mac.getInstance的Provider重载版本
    Mac.getInstance.overload('java.lang.String', 'java.lang.String').implementation = function (algo, provider) {
        var mac = this.getInstance(algo, provider);
        
        if (algo && algo.indexOf('Hmac') !== -1) {
            console.log('\n[*] 获取HMAC算法实例: ' + algo + ' (Provider: ' + provider + ')');
            
            // 初始化Mac对象信息
            macInfo[mac.$handle] = {
                algorithm: algo,
                provider: provider,
                key: null,
                inputData: [],
                securityEval: evaluateHMACSecurity(algo)
            };
            
            // 输出算法安全性评估
            var securityEval = macInfo[mac.$handle].securityEval;
            if (securityEval.issues.length > 0) {
                console.log('    [!] 安全性问题:');
                for (var i = 0; i < securityEval.issues.length; i++) {
                    console.log('        - ' + securityEval.issues[i]);
                }
            }
            
            console.log('    调用堆栈: \n    ' + getStackShort());
        }
        
        return mac;
    };
    
    // 监控Mac.getInstance的另一个Provider重载版本
    Mac.getInstance.overload('java.lang.String', 'java.security.Provider').implementation = function (algo, provider) {
        var mac = this.getInstance(algo, provider);
        
        if (algo && algo.indexOf('Hmac') !== -1) {
            console.log('\n[*] 获取HMAC算法实例: ' + algo + ' (Provider: ' + provider.getName() + ')');
            
            // 初始化Mac对象信息
            macInfo[mac.$handle] = {
                algorithm: algo,
                provider: provider.getName(),
                key: null,
                inputData: [],
                securityEval: evaluateHMACSecurity(algo)
            };
            
            console.log('    调用堆栈: \n    ' + getStackShort());
        }
        
        return mac;
    };
    
    // 监控init方法以获取密钥信息
    Mac.init.overload('java.security.Key').implementation = function (key) {
        var algo = this.getAlgorithm();
        
        if (algo && algo.indexOf('Hmac') !== -1) {
            try {
                var keyBytes = key.getEncoded();
                console.log('[*] 初始化HMAC(' + algo + ')');
                console.log('    密钥算法: ' + key.getAlgorithm());
                console.log('    密钥格式: ' + key.getFormat());
                console.log('    密钥内容: ' + formatData(keyBytes));
                console.log('    密钥长度: ' + keyBytes.length + ' 字节');
                
                // 检测可能的硬编码密钥
                var stackTrace = getStackShort();
                if (stackTrace.indexOf("SecretKeySpec") !== -1 && 
                    (stackTrace.indexOf("String") !== -1 || stackTrace.indexOf("getBytes") !== -1)) {
                    console.log('    [!] 警告: 可能使用了硬编码密钥或来自字符串的密钥');
                }
                
                // 更新Mac对象的密钥信息
                if (this.$handle in macInfo) {
                    macInfo[this.$handle].key = keyBytes;
                    
                    // 更新安全性评估
                    macInfo[this.$handle].securityEval = evaluateHMACSecurity(algo, keyBytes.length);
                    var securityEval = macInfo[this.$handle].securityEval;
                    
                    if (securityEval.issues.length > 0) {
                        console.log('    [!] 安全性问题:');
                        for (var i = 0; i < securityEval.issues.length; i++) {
                            console.log('        - ' + securityEval.issues[i]);
                        }
                    }
                    
                    if (securityEval.recommendations.length > 0) {
                        console.log('    [!] 安全建议:');
                        for (var i = 0; i < securityEval.recommendations.length; i++) {
                            console.log('        - ' + securityEval.recommendations[i]);
                        }
                    }
                }
            } catch (e) {
                console.log('[*] 初始化HMAC(' + algo + '): 无法提取密钥信息: ' + e);
            }
        }
        
        return this.init(key);
    };
    
    // 监控update方法，用于收集输入数据
    Mac.update.overload('[B').implementation = function (input) {
        var algo = this.getAlgorithm();
        
        if (algo && algo.indexOf('Hmac') !== -1) {
            console.log('[*] HMAC(' + algo + ') update: ');
            console.log('    输入: ' + formatData(input));
            
            // 将输入数据添加到Mac对象信息
            if (this.$handle in macInfo) {
                macInfo[this.$handle].inputData.push(input);
            }
        }
        
        return this.update(input);
    };
    
    // 监控update的offset/len重载版本
    Mac.update.overload('[B', 'int', 'int').implementation = function (input, offset, length) {
        var algo = this.getAlgorithm();
        
        if (algo && algo.indexOf('Hmac') !== -1) {
            try {
                var data = new Array(length);
                for (var i = 0; i < length; i++) {
                    data[i] = input[offset + i];
                }
                
                console.log('[*] HMAC(' + algo + ') update(偏移量: ' + offset + ', 长度: ' + length + '): ');
                console.log('    部分输入: ' + formatData(data));
                
                // 将输入数据添加到Mac对象信息
                if (this.$handle in macInfo) {
                    macInfo[this.$handle].inputData.push(data);
                }
            } catch (e) {
                console.log('[*] HMAC(' + algo + ') update: 无法解析偏移数据');
            }
        }
        
        return this.update(input, offset, length);
    };
    
    // 监控doFinal方法，捕获最终的HMAC计算结果
    Mac.doFinal.overload().implementation = function () {
        var algo = this.getAlgorithm();
        var result = this.doFinal();
        
        if (algo && algo.indexOf('Hmac') !== -1) {
            console.log('[*] HMAC(' + algo + ') doFinal');
            console.log('    结果: ' + formatData(result));
            
            // 使用累积的输入数据进行常见模式检测
            if (this.$handle in macInfo) {
                analyzeHMACUsage(macInfo[this.$handle], result);
            }
        }
        
        return result;
    };
    
    // 监控doFinal的输入重载版本
    Mac.doFinal.overload('[B').implementation = function (input) {
        var algo = this.getAlgorithm();
        var result = this.doFinal(input);
        
        if (algo && algo.indexOf('Hmac') !== -1) {
            console.log('[*] HMAC(' + algo + ') doFinal');
            console.log('    输入: ' + formatData(input));
            console.log('    结果: ' + formatData(result));
            
            // 检测JWT
            var jwt = detectJWT(input);
            if (jwt.isJWT) {
                console.log('    [!] 检测到可能的JWT令牌验证:');
                console.log('        头部: ' + jwt.header);
                console.log('        载荷: ' + jwt.payload);
            }
            
            // 将最终输入添加到Mac对象信息
            if (this.$handle in macInfo) {
                macInfo[this.$handle].inputData.push(input);
                analyzeHMACUsage(macInfo[this.$handle], result);
            }
            
            // 打印调用堆栈
            console.log('    调用堆栈: \n    ' + getStackShort());
        }
        
        return result;
    };
    
    // 监控doFinal的offset/len重载版本
    Mac.doFinal.overload('[B', 'int', 'int').implementation = function (input, offset, length) {
        var algo = this.getAlgorithm();
        var result = this.doFinal(input, offset, length);
        
        if (algo && algo.indexOf('Hmac') !== -1) {
            try {
                var data = new Array(length);
                for (var i = 0; i < length; i++) {
                    data[i] = input[offset + i];
                }
                
                console.log('[*] HMAC(' + algo + ') doFinal(偏移量: ' + offset + ', 长度: ' + length + ')');
                console.log('    部分输入: ' + formatData(data));
                console.log('    结果: ' + formatData(result));
                
                // 将最终输入添加到Mac对象信息
                if (this.$handle in macInfo) {
                    macInfo[this.$handle].inputData.push(data);
                    analyzeHMACUsage(macInfo[this.$handle], result);
                }
            } catch (e) {
                console.log('[*] HMAC(' + algo + ') doFinal: 无法解析偏移数据');
            }
        }
        
        return result;
    };
    
    // 辅助函数：分析HMAC使用场景
    function analyzeHMACUsage(info, result) {
        // 已分析则跳过
        if (info.analyzed) return;
        
        console.log('    [+] HMAC使用场景分析:');
        
        // 合并所有输入数据
        var allInputs = info.inputData.join('');
        
        // 检测JWT签名
        var jwtPattern = /eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+/;
        if (allInputs.match(jwtPattern)) {
            console.log('        - 可能用于JWT令牌签名/验证');
        }
        
        // 检测OAuth签名
        if (allInputs.indexOf('oauth_signature') !== -1 || 
            allInputs.indexOf('oauth_consumer_key') !== -1) {
            console.log('        - 可能用于OAuth签名生成/验证');
        }
        
        // 检测API请求签名
        if (allInputs.indexOf('GET ') !== -1 || 
            allInputs.indexOf('POST ') !== -1 || 
            allInputs.indexOf('PUT ') !== -1 || 
            allInputs.indexOf('DELETE ') !== -1) {
            console.log('        - 可能用于API请求签名');
        }
        
        // 检测常见HTTP头部
        if (allInputs.indexOf('Authorization:') !== -1 || 
            allInputs.indexOf('Content-Type:') !== -1 || 
            allInputs.indexOf('User-Agent:') !== -1) {
            console.log('        - 可能用于HTTP请求签名');
        }
        
        // 输出安全性评估总结
        if (info.securityEval) {
            if (info.securityEval.isSecure) {
                console.log('        - 使用安全的HMAC配置');
            } else {
                console.log('        - 存在安全性问题，参见上方详细警告');
            }
        }
        
        // 标记为已分析
        info.analyzed = true;
    }
    
    // 监控SecretKeySpec的创建
    try {
        var SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
        SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function (keyBytes, algorithm) {
            var result = this.$init(keyBytes, algorithm);
            
            if (algorithm && algorithm.indexOf('Hmac') !== -1) {
                console.log('[*] 创建HMAC密钥: ' + algorithm);
                console.log('    密钥数据: ' + formatData(keyBytes));
                console.log('    密钥长度: ' + keyBytes.length + ' 字节');
                
                // 检测可能的硬编码密钥
                var stackTrace = getStackShort();
                if (stackTrace.indexOf("String") !== -1 || stackTrace.indexOf("getBytes") !== -1) {
                    console.log('    [!] 警告: 可能使用了硬编码密钥或来自字符串的密钥');
                    console.log('    调用堆栈: \n    ' + stackTrace);
                }
                
                // 安全性评估
                var securityEval = evaluateHMACSecurity(algorithm, keyBytes.length);
                if (securityEval.issues.length > 0) {
                    console.log('    [!] 安全性问题:');
                    for (var i = 0; i < securityEval.issues.length; i++) {
                        console.log('        - ' + securityEval.issues[i]);
                    }
                }
                
                if (securityEval.recommendations.length > 0) {
                    console.log('    [!] 安全建议:');
                    for (var i = 0; i < securityEval.recommendations.length; i++) {
                        console.log('        - ' + securityEval.recommendations[i]);
                    }
                }
            }
            
            return result;
        };
    } catch (e) {
        console.log("[-] SecretKeySpec Hook失败: " + e);
    }
    
    console.log("[*] HMAC算法监控已启动");
    console.log("[*] 支持的算法: HmacMD5, HmacSHA1, HmacSHA256, HmacSHA384, HmacSHA512");
    console.log("[*] 监控范围: 算法选择, 密钥设置, 数据输入, 结果输出");
    console.log("[*] 安全检测: JWT令牌, OAuth签名, 算法安全性, 密钥强度");
});