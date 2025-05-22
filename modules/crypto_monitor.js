/*
 * 加密监控模块
 * 功能：监控和记录常见加密算法的使用，自动提取密钥、IV、明文、密文
 * 支持：AES/DES/RSA/MD5/SHA/Base64 等
 */

module.exports = function(config, logger, utils) {
    var tag = "CRYPTO";
    logger.info(tag, "加密监控模块初始化");
    
    // 存储加密信息
    var keyStore = {
        keys: {},
        ivs: {},
        add: function(algorithm, key, iv, plaintext, ciphertext) {
            var id = this._generateId(algorithm, key);
            this.keys[id] = {
                algorithm: algorithm,
                key: key,
                keyHex: this._toHex(key),
                keyBase64: this._toBase64(key),
                iv: iv,
                ivHex: iv ? this._toHex(iv) : null,
                ivBase64: iv ? this._toBase64(iv) : null,
                timestamp: new Date(),
                samples: []
            };
            
            if (plaintext || ciphertext) {
                this._addSample(id, plaintext, ciphertext);
            }
            
            // 输出加密信息
            this._logKeyInfo(id);
        },
        _addSample: function(id, plaintext, ciphertext) {
            if (!this.keys[id]) return;
            
            this.keys[id].samples.push({
                plaintext: plaintext,
                plaintextHex: plaintext ? this._toHex(plaintext) : null,
                plaintextBase64: plaintext ? this._toBase64(plaintext) : null,
                ciphertext: ciphertext,
                ciphertextHex: ciphertext ? this._toHex(ciphertext) : null,
                ciphertextBase64: ciphertext ? this._toBase64(ciphertext) : null,
                timestamp: new Date()
            });
        },
        _generateId: function(algorithm, key) {
            return algorithm + "-" + this._toHex(key);
        },
        _toHex: function(data) {
            if (!data) return null;
            
            try {
                if (typeof data === 'string') {
                    return this._bytesToHex(utils.stringToBytes(data));
                } else if (data instanceof Array) {
                    return this._bytesToHex(data);
                } else {
                    return data.toString();
                }
            } catch(e) {
                return String(data);
            }
        },
        _toBase64: function(data) {
            if (!data) return null;
            
            try {
                if (Java.available) {
                    var base64 = Java.use("android.util.Base64");
                    if (typeof data === 'string') {
                        return base64.encodeToString(utils.stringToBytes(data), 0);
                    } else if (data instanceof Array) {
                        return base64.encodeToString(data, 0);
                    }
                }
                return String(data);
            } catch(e) {
                return String(data);
            }
        },
        _bytesToHex: function(bytes) {
            var hex = '';
            for (var i = 0; i < bytes.length; i++) {
                hex += ('0' + (bytes[i] & 0xFF).toString(16)).slice(-2);
            }
            return hex;
        },
        _logKeyInfo: function(id) {
            if (!this.keys[id]) return;
            
            var info = this.keys[id];
            logger.info(tag, "====== 发现加密密钥 ======");
            logger.info(tag, "算法: " + info.algorithm);
            logger.info(tag, "密钥: " + info.key);
            logger.info(tag, "密钥(HEX): " + info.keyHex);
            logger.info(tag, "密钥(B64): " + info.keyBase64);
            
            if (info.iv) {
                logger.info(tag, "IV: " + info.iv);
                logger.info(tag, "IV(HEX): " + info.ivHex);
                logger.info(tag, "IV(B64): " + info.ivBase64);
            }
            
            if (info.samples.length > 0) {
                var lastSample = info.samples[info.samples.length - 1];
                logger.info(tag, "明文样本: " + lastSample.plaintext);
                logger.info(tag, "明文(HEX): " + lastSample.plaintextHex);
                logger.info(tag, "明文(B64): " + lastSample.plaintextBase64);
                logger.info(tag, "密文样本: " + lastSample.ciphertext);
                logger.info(tag, "密文(HEX): " + lastSample.ciphertextHex);
                logger.info(tag, "密文(B64): " + lastSample.ciphertextBase64);
            }
            logger.info(tag, "==========================");
        }
    };
    
    // 开始Hook加密相关API
    Java.perform(function() {
        // 1. Hook javax.crypto.Cipher
        hookCipher();
        
        // 2. Hook java.security.MessageDigest
        hookMessageDigest();
        
        // 3. Hook Base64
        hookBase64();
        
        // 4. Hook RSA
        hookRSA();
        
        // 5. Hook 常见第三方加密库
        hookThirdPartyLibs();
    });
    
    // Hook Cipher (AES, DES, etc.)
    function hookCipher() {
        try {
            var Cipher = Java.use("javax.crypto.Cipher");
            var SecretKey = Java.use("javax.crypto.SecretKey");
            var IvParameterSpec = Java.use("javax.crypto.spec.IvParameterSpec");
            
            // Hook init
            Cipher.init.overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec').implementation = function(mode, key, params) {
                var result = this.init(mode, key, params);
                
                var algorithm = this.getAlgorithm();
                var modeStr = mode === 1 ? "加密" : mode === 2 ? "解密" : mode + "";
                
                try {
                    var keyBytes = key.getEncoded();
                    var iv = null;
                    
                    // 尝试获取IV
                    if (params && params.$className === "javax.crypto.spec.IvParameterSpec") {
                        iv = params.getIV();
                    }
                    
                    keyStore.add(algorithm, keyBytes, iv);
                    
                    logger.info(tag, "Cipher.init() " + modeStr + " 算法: " + algorithm + 
                              utils.getStackTrace());
                } catch (e) {
                    logger.error(tag, "Cipher初始化分析错误: " + e);
                }
                
                return result;
            };
            
            // Hook doFinal
            Cipher.doFinal.overload('[B').implementation = function(input) {
                try {
                    var algorithm = this.getAlgorithm();
                    var mode = this.getOpmode(); // 1=加密, 2=解密
                    
                    var result = this.doFinal(input);
                    
                    if (mode === 1) { // 加密
                        logger.info(tag, algorithm + " 加密");
                        logger.info(tag, "明文: " + utils.bytesToString(input));
                        logger.info(tag, "密文: " + utils.bytesToString(result));
                    } else { // 解密
                        logger.info(tag, algorithm + " 解密");
                        logger.info(tag, "密文: " + utils.bytesToString(input));
                        logger.info(tag, "明文: " + utils.bytesToString(result));
                    }
                    
                    return result;
                } catch(e) {
                    logger.error(tag, "Cipher.doFinal 错误: " + e);
                    return this.doFinal(input);
                }
            };
            
            // Hook SecretKeySpec
            var SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
            SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function(keyBytes, algorithm) {
                var result = this.$init(keyBytes, algorithm);
                
                try {
                    logger.info(tag, "密钥创建: " + algorithm);
                    logger.info(tag, "密钥: " + keyBytes);
                    keyStore.add(algorithm, keyBytes, null);
                } catch (e) {
                    logger.error(tag, "SecretKeySpec 错误: " + e);
                }
                
                return result;
            };
            
            // Hook IvParameterSpec
            IvParameterSpec.$init.overload('[B').implementation = function(ivBytes) {
                var result = this.$init(ivBytes);
                
                try {
                    logger.info(tag, "IV创建:");
                    logger.info(tag, "IV: " + ivBytes);
                } catch (e) {
                    logger.error(tag, "IvParameterSpec 错误: " + e);
                }
                
                return result;
            };
            
            logger.info(tag, "已Hook javax.crypto.Cipher相关类");
        } catch (e) {
            logger.error(tag, "Cipher Hook失败: " + e);
        }
    }
    
    // Hook MessageDigest (MD5, SHA等)
    function hookMessageDigest() {
        try {
            var MessageDigest = Java.use("java.security.MessageDigest");
            
            // Hook digest
            MessageDigest.digest.overload().implementation = function() {
                try {
                    var algorithm = this.getAlgorithm();
                    var result = this.digest();
                    
                    logger.info(tag, algorithm + " 摘要计算完成");
                    logger.info(tag, "摘要结果(HEX): " + keyStore._bytesToHex(result));
                    
                    return result;
                } catch(e) {
                    logger.error(tag, "MessageDigest.digest 错误: " + e);
                    return this.digest();
                }
            };
            
            // Hook update
            MessageDigest.update.overload('[B').implementation = function(input) {
                try {
                    var algorithm = this.getAlgorithm();
                    logger.info(tag, algorithm + " 摘要更新");
                    logger.info(tag, "输入: " + utils.bytesToString(input));
                    
                    return this.update(input);
                } catch(e) {
                    logger.error(tag, "MessageDigest.update 错误: " + e);
                    return this.update(input);
                }
            };
            
            logger.info(tag, "已Hook java.security.MessageDigest");
        } catch (e) {
            logger.error(tag, "MessageDigest Hook失败: " + e);
        }
    }
    
    // Hook Base64
    function hookBase64() {
        try {
            var Base64 = Java.use("android.util.Base64");
            
            // Hook encode
            Base64.encode.overload('[B', 'int').implementation = function(input, flags) {
                try {
                    var result = this.encode(input, flags);
                    
                    logger.info(tag, "Base64编码");
                    logger.info(tag, "原文: " + utils.bytesToString(input));
                    logger.info(tag, "编码: " + utils.bytesToString(result));
                    
                    return result;
                } catch(e) {
                    logger.error(tag, "Base64.encode 错误: " + e);
                    return this.encode(input, flags);
                }
            };
            
            // Hook decode
            Base64.decode.overload('[B', 'int').implementation = function(input, flags) {
                try {
                    var result = this.decode(input, flags);
                    
                    logger.info(tag, "Base64解码");
                    logger.info(tag, "编码: " + utils.bytesToString(input));
                    logger.info(tag, "原文: " + utils.bytesToString(result));
                    
                    return result;
                } catch(e) {
                    logger.error(tag, "Base64.decode 错误: " + e);
                    return this.decode(input, flags);
                }
            };
            
            // 同样处理String重载版本
            Base64.encodeToString.overload('[B', 'int').implementation = function(input, flags) {
                try {
                    var result = this.encodeToString(input, flags);
                    
                    logger.info(tag, "Base64编码为字符串");
                    logger.info(tag, "原文: " + utils.bytesToString(input));
                    logger.info(tag, "编码: " + result);
                    
                    return result;
                } catch(e) {
                    logger.error(tag, "Base64.encodeToString 错误: " + e);
                    return this.encodeToString(input, flags);
                }
            };
            
            logger.info(tag, "已Hook android.util.Base64");
        } catch (e) {
            logger.error(tag, "Base64 Hook失败: " + e);
        }
    }
    
    // Hook RSA加密
    function hookRSA() {
        try {
            // KeyPairGenerator (RSA密钥生成)
            var KeyPairGenerator = Java.use("java.security.KeyPairGenerator");
            KeyPairGenerator.generateKeyPair.implementation = function() {
                var keyPair = this.generateKeyPair();
                
                try {
                    var algorithm = this.getAlgorithm();
                    logger.info(tag, "生成密钥对: " + algorithm);
                    
                    // 获取私钥和公钥
                    var privateKey = keyPair.getPrivate();
                    var publicKey = keyPair.getPublic();
                    
                    logger.info(tag, "私钥格式: " + privateKey.getFormat());
                    logger.info(tag, "私钥编码: " + keyStore._bytesToHex(privateKey.getEncoded()));
                    
                    logger.info(tag, "公钥格式: " + publicKey.getFormat());
                    logger.info(tag, "公钥编码: " + keyStore._bytesToHex(publicKey.getEncoded()));
                } catch(e) {
                    logger.error(tag, "RSA密钥分析错误: " + e);
                }
                
                return keyPair;
            };
            
            // RSACipher操作
            try {
                var Cipher = Java.use("javax.crypto.Cipher");
                var originalDoFinal = Cipher.doFinal.overload('[B');
                
                // 监控RSA加解密
                Cipher.doFinal.overload('[B').implementation = function(input) {
                    var result = originalDoFinal.call(this, input);
                    
                    try {
                        var algorithm = this.getAlgorithm();
                        if (algorithm.indexOf("RSA") !== -1) {
                            var mode = this.getOpmode(); // 1=加密, 2=解密
                            if (mode === 1) { // 加密
                                logger.info(tag, "RSA加密操作");
                                logger.info(tag, "明文: " + utils.bytesToString(input));
                                logger.info(tag, "密文(HEX): " + keyStore._bytesToHex(result));
                            } else { // 解密
                                logger.info(tag, "RSA解密操作");
                                logger.info(tag, "密文(HEX): " + keyStore._bytesToHex(input));
                                logger.info(tag, "明文: " + utils.bytesToString(result));
                            }
                        }
                    } catch(e) {
                        logger.error(tag, "RSA分析错误: " + e);
                    }
                    
                    return result;
                };
            } catch(e) {
                logger.error(tag, "RSA Cipher Hook失败: " + e);
            }
            
            logger.info(tag, "已Hook RSA相关操作");
        } catch (e) {
            logger.error(tag, "RSA Hook失败: " + e);
        }
    }
    
    // Hook第三方加密库
    function hookThirdPartyLibs() {
        // 尝试Hook常见的第三方加密库
        try {
            // BouncyCastle
            try {
                var BCClasses = [
                    "org.bouncycastle.crypto.engines.AESEngine",
                    "org.bouncycastle.crypto.engines.DESEngine",
                    "org.bouncycastle.crypto.modes.CBCBlockCipher",
                    "org.bouncycastle.crypto.paddings.PKCS7Padding"
                ];
                
                BCClasses.forEach(function(className) {
                    try {
                        var ClassObj = Java.use(className);
                        logger.debug(tag, "发现BouncyCastle类: " + className);
                        
                        if (className === "org.bouncycastle.crypto.engines.AESEngine") {
                            ClassObj.processBlock.implementation = function(in_buf, inOff, out_buf, outOff) {
                                logger.info(tag, "BouncyCastle AES操作");
                                var result = this.processBlock(in_buf, inOff, out_buf, outOff);
                                return result;
                            };
                        }
                    } catch (e) {
                        logger.debug(tag, "未找到BouncyCastle类: " + className);
                    }
                });
                
                logger.info(tag, "已尝试Hook BouncyCastle库");
            } catch (e) {
                logger.debug(tag, "BouncyCastle Hook失败，应用可能未使用此库");
            }
            
            // Apache Commons Codec
            try {
                var commonsCodecClasses = [
                    "org.apache.commons.codec.binary.Base64",
                    "org.apache.commons.codec.digest.DigestUtils"
                ];
                
                commonsCodecClasses.forEach(function(className) {
                    try {
                        var ClassObj = Java.use(className);
                        logger.debug(tag, "发现Commons Codec类: " + className);
                        
                        if (className === "org.apache.commons.codec.digest.DigestUtils") {
                            ClassObj.md5.overload("java.lang.String").implementation = function(input) {
                                var result = this.md5(input);
                                logger.info(tag, "CommonCodec MD5: " + input + " -> " + result);
                                return result;
                            };
                        }
                    } catch (e) {
                        logger.debug(tag, "未找到Commons Codec类: " + className);
                    }
                });
                
                logger.info(tag, "已尝试Hook Apache Commons Codec库");
            } catch (e) {
                logger.debug(tag, "Commons Codec Hook失败，应用可能未使用此库");
            }
        } catch (e) {
            logger.error(tag, "第三方库Hook失败: " + e);
        }
    }
    
    logger.info(tag, "加密监控模块加载完成");
    return {
        keyStore: keyStore
    };
}; 