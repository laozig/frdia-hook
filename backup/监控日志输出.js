/*
 * 脚本名称：监控日志输出.js
 * 功能：全面监控Android应用日志输出，支持过滤、分析和敏感数据检测
 * 适用场景：
 *   - 应用调试和分析
 *   - 敏感信息泄露检测
 *   - 隐藏日志分析
 *   - 安全审计和合规检查
 * 使用方法：
 *   1. frida -U -f 包名 -l 监控日志输出.js --no-pause
 *   2. 查看控制台输出，获取应用的日志内容
 * 启动方式说明：
 *   - -U 代表使用USB连接的设备
 *   - -f 代表以spawn方式启动目标应用（推荐，可捕获启动阶段的日志）
 *   - --no-pause 指示Frida不要暂停应用执行
 * 支持特性：
 *   - 监控所有日志级别(VERBOSE、DEBUG、INFO、WARN、ERROR)
 *   - 敏感数据检测与脱敏
 *   - 日志源和内容过滤
 *   - 调用堆栈追踪
 *   - 系统日志钩子（System.out/err）
 *   - 保存日志到本地文件
 */

Java.perform(function () {
    // 配置选项
    var config = {
        logLevel: 2,                 // 0:关闭 1:错误 2:基本信息 3:详细
        printStack: true,            // 是否打印调用堆栈
        maxStackDepth: 5,            // 最大堆栈深度
        detectSensitiveData: true,   // 检测敏感数据
        filterByTag: null,           // 按标签过滤日志，null表示不过滤
        filterByContent: null,       // 按内容过滤日志，null表示不过滤
        blockSensitiveData: false,   // 是否阻止包含敏感数据的日志输出
        hookSystemOut: true,         // 是否钩住System.out/err
        saveToFile: false,           // 是否保存日志到文件
        logFile: "/sdcard/frida-logs.txt", // 日志保存路径
        monitorThirdPartyLoggers: true, // 监控第三方日志库
        maxLogLength: 500,           // 日志最大显示长度
        ignorePackages: ["com.android.internal", "android.os"] // 忽略的包名
    };
    
    // 敏感数据正则表达式
    var sensitivePatterns = {
        creditCard: /\b(?:\d[ -]*?){13,16}\b/,
        email: /[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+/,
        phone: /\b(?:\+?(\d{1,3}))?[-. (]*(\d{3})[-. )]*(\d{3})[-. ]*(\d{4})\b/,
        idCard: /\b\d{6}(?:19|20)?\d{2}(?:0[1-9]|1[012])(?:0[1-9]|[12]\d|3[01])\d{3}(?:\d|X|x)\b/, // 中国身份证
        password: /(?:password|passwd|pwd|密码)[=: ]+"?\S+["']?/i,
        apiKey: /(?:api[_-]?key|token|secret|auth)[=: ]+"?\S+["']?/i,
        imei: /\b(?:\d{15}|\d{17})\b/ // IMEI号
    };
    
    // 统计信息
    var stats = {
        totalLogs: 0,
        byLevel: {
            v: 0, d: 0, i: 0, w: 0, e: 0, wtf: 0
        },
        sensitiveDetected: 0,
        blocked: 0
    };
    
    // 创建日志文件（如果启用）
    var logFile = null;
    if (config.saveToFile) {
        try {
            var File = Java.use("java.io.File");
            var FileWriter = Java.use("java.io.FileWriter");
            
            var file = File.$new(config.logFile);
            logFile = FileWriter.$new(file, true); // true表示追加模式
            
            logFile.write("=== Frida日志监控会话开始: " + new Date().toString() + " ===\n");
            logFile.flush();
        } catch (e) {
            console.log("[!] 创建日志文件失败: " + e);
            config.saveToFile = false;
        }
    }
    
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
        
        // 保存到文件（如果启用）
        if (config.saveToFile && logFile) {
            try {
                logFile.write(new Date().toISOString() + " " + message + "\n");
                logFile.flush();
            } catch (e) {
                console.log("[!] 写入日志文件失败: " + e);
            }
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
            var foundAppCode = false;
            
            // 尝试跳过日志库代码，直接显示应用代码
            for (var i = 0; i < stackElements.length; i++) {
                var element = stackElements[i];
                var className = element.getClassName();
                
                // 跳过Frida相关的堆栈和日志库代码
                if (className.indexOf("com.android.internal.os") !== -1 ||
                    className.indexOf("android.util.Log") !== -1 ||
                    className.indexOf("java.lang.reflect") !== -1 ||
                    className.indexOf("dalvik.system") !== -1) {
                    continue;
                }
                
                // 跳过被忽略的包
                var shouldSkip = false;
                for (var p = 0; p < config.ignorePackages.length; p++) {
                    if (className.indexOf(config.ignorePackages[p]) === 0) {
                        shouldSkip = true;
                        break;
                    }
                }
                
                if (shouldSkip) continue;
                
                // 找到应用代码
                foundAppCode = true;
                stack += "\n        " + className + "." + 
                         element.getMethodName() + "(" + 
                         (element.getFileName() != null ? element.getFileName() : "Unknown Source") + ":" + 
                         element.getLineNumber() + ")";
                
                if (--limit <= 0) break;
            }
            
            if (!foundAppCode) {
                // 如果没有找到应用代码，则显示前几帧
                limit = Math.min(stackElements.length, config.maxStackDepth);
                for (var i = 0; i < limit; i++) {
                    var element = stackElements[i];
                    stack += "\n        " + element.getClassName() + "." + 
                             element.getMethodName() + "(" + 
                             (element.getFileName() != null ? element.getFileName() : "Unknown Source") + ":" + 
                             element.getLineNumber() + ")";
                }
            }
            
            return stack;
            
        } catch (e) {
            return "\n    调用堆栈获取失败: " + e;
        }
    }
    
    // 检测文本中的敏感信息
    function detectSensitiveInfo(text) {
        if (!config.detectSensitiveData || !text) return null;
        
        try {
            var results = [];
            for (var key in sensitivePatterns) {
                if (sensitivePatterns[key].test(text)) {
                    results.push(key);
                }
            }
            
            return results.length > 0 ? results : null;
        } catch (e) {
            return null;
        }
    }
    
    // 脱敏处理文本
    function maskSensitiveData(text) {
        if (!text) return text;
        
        try {
            // 信用卡号码
            text = text.replace(sensitivePatterns.creditCard, function(match) {
                return match.substr(0, 4) + " **** **** " + match.substr(-4);
            });
            
            // 电子邮件
            text = text.replace(sensitivePatterns.email, function(match) {
                var parts = match.split('@');
                var username = parts[0];
                var domain = parts[1];
                return username.substr(0, 3) + "***@" + domain;
            });
            
            // 手机号码
            text = text.replace(sensitivePatterns.phone, function(match) {
                return match.substr(0, 3) + "****" + match.substr(-4);
            });
            
            // 密码
            text = text.replace(sensitivePatterns.password, function(match) {
                return match.replace(/("?\S+["']?)$/, "\"********\"");
            });
            
            // API密钥
            text = text.replace(sensitivePatterns.apiKey, function(match) {
                return match.replace(/("?\S+["']?)$/, "\"********\"");
            });
            
            return text;
        } catch (e) {
            return text;
        }
    }
    
    // 处理日志消息
    function processLogMessage(level, tag, message) {
        stats.totalLogs++;
        stats.byLevel[level]++;
        
        // 按标签和内容过滤
        if (config.filterByTag && tag.indexOf(config.filterByTag) === -1) {
            return null; // 不符合标签过滤条件
        }
        if (config.filterByContent && message && message.indexOf(config.filterByContent) === -1) {
            return null; // 不符合内容过滤条件
        }
        
        // 检测敏感信息
        var sensitiveTypes = detectSensitiveInfo(message);
        
        // 如果找到敏感信息
        if (sensitiveTypes) {
            stats.sensitiveDetected++;
            
            // 如果需要阻止敏感日志输出
            if (config.blockSensitiveData) {
                stats.blocked++;
                return false; // 阻止日志输出
            }
            
            // 脱敏处理
            message = maskSensitiveData(message);
        }
        
        // 格式化日志等级
        var levelName = {
            'v': 'VERBOSE',
            'd': 'DEBUG',
            'i': 'INFO',
            'w': 'WARN',
            'e': 'ERROR',
            'wtf': 'ASSERT'
        }[level] || level;
        
        // 检查消息长度，截断过长内容
        var originalLength = message ? message.length : 0;
        if (message && message.length > config.maxLogLength) {
            message = message.substring(0, config.maxLogLength) + 
                     "... (总长度: " + originalLength + " 字符)";
        }
        
        // 构建日志输出
        var output = "日志[" + levelName + "] '" + tag + "': " + message;
        
        // 添加敏感信息标记
        if (sensitiveTypes) {
            output += " [!发现敏感信息: " + sensitiveTypes.join(", ") + "]";
        }
        
        // 添加调用堆栈
        if (config.printStack) {
            output += getStackTrace();
        }
        
        return output;
    }
    
    // 钩住原生Log类
    try {
        var Log = Java.use('android.util.Log');
        
        // 钩住所有日志级别
        var logLevels = ['v', 'd', 'i', 'w', 'e', 'wtf'];
        
        logLevels.forEach(function(level) {
            // 处理所有重载
            Log[level].overloads.forEach(function(overload) {
                overload.implementation = function() {
                    var args = Array.prototype.slice.call(arguments);
                    
                    // 提取标签和消息参数
                    var tag = args[0] || "<no tag>";
                    var msg = "";
                    
                    if (args.length >= 2) {
                        if (args[1] !== null) {
                            msg = args[1].toString();
                        }
                    }
                    
                    // 处理日志消息
                    var processedMsg = processLogMessage(level, tag, msg);
                    
                    // 如果需要阻止日志输出
                    if (processedMsg === false) {
                        if (level === 'wtf') {
                            return 0; // wtf方法返回int
                        }
                        return -1; // 其他日志方法通常也返回int
                    }
                    
                    // 如果消息被过滤掉了
                    if (processedMsg === null) {
                        return overload.apply(this, args); // 正常调用，但不打印
                    }
                    
                    // 打印处理后的消息
                    log(2, processedMsg);
                    
                    // 调用原始方法
                    return overload.apply(this, args);
                };
            });
        });
        
        log(2, "成功钩住android.util.Log类的所有方法");
    } catch (e) {
        log(1, "钩住android.util.Log类失败: " + e);
    }
    
    // 钩住System.out和System.err
    if (config.hookSystemOut) {
        try {
            var PrintStream = Java.use("java.io.PrintStream");
            
            // System.out.println
            PrintStream.println.overload('java.lang.String').implementation = function(message) {
                var processedMsg = processLogMessage('i', "System.out", message);
                
                // 如果消息被过滤掉或阻止
                if (processedMsg === null || processedMsg === false) {
                    return this.println(message); // 调用原始方法但不记录
                }
                
                log(2, processedMsg);
                return this.println(message);
            };
            
            // System.err.println
            var errPrintStream = Java.use("java.io.PrintStream");
            errPrintStream.println.overload('java.lang.String').implementation = function(message) {
                var processedMsg = processLogMessage('e', "System.err", message);
                
                // 如果消息被过滤掉或阻止
                if (processedMsg === null || processedMsg === false) {
                    return this.println(message); // 调用原始方法但不记录
                }
                
                log(2, processedMsg);
                return this.println(message);
            };
            
            log(2, "成功钩住System.out和System.err");
        } catch (e) {
            log(1, "钩住System.out/err失败: " + e);
        }
    }
    
    // 尝试钩住常见第三方日志库
    if (config.monitorThirdPartyLoggers) {
        // Timber - 常用第三方日志库
        try {
            var Timber = Java.use("timber.log.Timber$Tree");
            Timber.log.overload('int', 'java.lang.String', 'java.lang.Object[]').implementation = function(priority, message, args) {
                var priorityLevel = {0:'v', 1:'d', 2:'i', 3:'w', 4:'e', 5:'wtf'}[priority] || 'd';
                var expandedMessage = message;
                
                // 简单处理格式化占位符
                if (args && args.length > 0) {
                    try {
                        for (var i = 0; i < args.length; i++) {
                            expandedMessage = expandedMessage.replace(/%s|%d|%f|%.+?/, args[i]);
                        }
                    } catch (e) {
                        expandedMessage += " [格式化失败: " + e + "]";
                    }
                }
                
                var processedMsg = processLogMessage(priorityLevel, "Timber", expandedMessage);
                
                if (processedMsg !== null && processedMsg !== false) {
                    log(2, processedMsg);
                }
                
                return this.log(priority, message, args);
            };
            log(2, "成功钩住Timber日志库");
        } catch (e) {
            // Timber库可能不存在，不触发错误
        }
        
        // 尝试钩住其他日志库...
    }
    
    // 打印初始化信息
    log(2, "日志监控模块已启动");
    log(2, "监控范围: Android.util.Log.*、System.out/err" + 
       (config.monitorThirdPartyLoggers ? "、第三方日志库" : ""));
    
    if (config.detectSensitiveData) {
        log(2, "已启用敏感数据检测: " + Object.keys(sensitivePatterns).length + " 种类型");
        if (config.blockSensitiveData) {
            log(2, "[!] 敏感数据屏蔽已启用，含敏感数据的日志将被阻止输出");
        }
    }
    
    if (config.filterByTag) {
        log(2, "标签过滤: " + config.filterByTag);
    }
    
    // 定期打印统计信息
    setInterval(function() {
        if (stats.totalLogs > 0) {
            log(2, "日志统计: 总数(" + stats.totalLogs + 
                 "), V(" + stats.byLevel.v + 
                 "), D(" + stats.byLevel.d + 
                 "), I(" + stats.byLevel.i + 
                 "), W(" + stats.byLevel.w + 
                 "), E(" + stats.byLevel.e + 
                 "), WTF(" + stats.byLevel.wtf + 
                 "), 敏感(" + stats.sensitiveDetected + 
                 "), 阻止(" + stats.blocked + ")");
        }
    }, 30000); // 每30秒打印一次
}); 