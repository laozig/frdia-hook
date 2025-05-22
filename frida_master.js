/**
 * Frida全功能Hook框架主入口文件
 * 支持Frida 14.0.0及以上版本
 */

// 配置参数
var config = {
    logLevel: 'info',           // 日志级别: debug, info, warn, error
    fileLogging: true,          // 是否保存日志到文件
    logFilePath: '/sdcard/frida_log.txt',  // 日志文件路径
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
    } catch (e) {
        logger.error('SYSTEM', '创建日志文件失败: ' + e);
        config.fileLogging = false; // 无法创建日志文件时禁用文件日志
    }
}

// 模块加载函数
function loadModules() {
    try {
        // 加载反调试绕过模块
        if (config.bypassAllDetection) {
            require('./modules/anti_debug.js')(config, logger, utils);
        }
        
        // 加载加密监控模块
        require('./modules/crypto_monitor.js')(config, logger, utils);
        
        // 加载网络监控模块
        require('./modules/network_monitor.js')(config, logger, utils);
        
        // 加载敏感API监控模块
        require('./modules/sensitive_api.js')(config, logger, utils);
        
        // 加载自动提取器模块
        if (config.autoExtractKeys) {
            require('./modules/auto_extractor.js')(config, logger, utils);
        }
        
        // 加载系统API监控模块
        require('./modules/system_api_monitor.js')(config, logger, utils);
        
        // 加载DEX脱壳模块
        require('./modules/dex_dumper.js')(config, logger, utils);
        
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
        createLogFile();
    }
    
    // 显示启动信息
    logger.info('SYSTEM', 'Frida全功能Hook框架初始化完成');
    logger.info('SYSTEM', '日志级别: ' + config.logLevel);
    logger.info('SYSTEM', '绕过检测: ' + (config.bypassAllDetection ? '启用' : '禁用'));
    logger.info('SYSTEM', 'Frida版本: ' + (config.fridaVersion || '未知'));
    logger.info('SYSTEM', '兼容模式: ' + (config.fridaCompatMode ? '启用' : '禁用'));
    
    // 延迟加载模块，确保应用有足够时间初始化
    setTimeout(function() {
        try {
            Java.perform(function() {
                logger.info('SYSTEM', 'Java环境准备就绪');
                loadModules();
            });
        } catch (e) {
            logger.error('SYSTEM', 'Java环境初始化失败: ' + e);
            // 尝试使用兼容性更强的方式
            if (!config.fridaCompatMode) {
                logger.info('SYSTEM', '切换到兼容模式并重试...');
                config.fridaCompatMode = true;
                Java.perform(loadModules);
            }
        }
    }, 1000);
}

// 启动框架
main(); 
