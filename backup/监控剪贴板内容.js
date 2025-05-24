/*
 * 脚本名称：监控剪贴板内容.js
 * 功能：监控Android应用读取和写入剪贴板的行为，检测敏感数据泄露风险
 * 适用场景：
 *   - 隐私泄露检测
 *   - 敏感数据流跟踪
 *   - 逆向App功能分析
 *   - 安全审计和合规检查
 * 使用方法：
 *   1. frida -U -f 包名 -l 监控剪贴板内容.js --no-pause
 *   2. 查看控制台输出，了解应用的剪贴板访问行为
 * 启动方式说明：
 *   - -U 代表使用USB连接的设备
 *   - -f 代表以spawn方式启动目标应用（推荐）
 *   - --no-pause 指示Frida不要暂停应用执行
 * 支持特性：
 *   - 监控剪贴板读取和写入
 *   - 检测多种敏感数据类型
 *   - 记录访问调用堆栈
 *   - 支持HTML、文本和URI等多种内容格式
 *   - 识别应用剪贴板访问模式
 */

Java.perform(function () {
    // 配置选项
    var config = {
        logLevel: 2,              // 0:关闭 1:错误 2:基本信息 3:详细
        printStack: true,         // 是否打印调用堆栈
        maxStackDepth: 5,         // 最大堆栈深度
        monitorAllFormats: true,  // 监控所有剪贴板格式
        detectSensitiveData: true, // 检测敏感数据
        maxClipLength: 500,       // 剪贴板内容最大显示长度
        obfuscateSensitive: true  // 是否对敏感信息进行脱敏处理
    };
    
    // 敏感数据正则表达式
    var sensitivePatterns = {
        creditCard: /\b(?:\d[ -]*?){13,16}\b/,
        email: /[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+/,
        phone: /\b(?:\+?(\d{1,3}))?[-. (]*(\d{3})[-. )]*(\d{3})[-. ]*(\d{4})\b/,
        idCard: /\b\d{6}(?:19|20)?\d{2}(?:0[1-9]|1[012])(?:0[1-9]|[12]\d|3[01])\d{3}(?:\d|X|x)\b/, // 中国身份证
        password: /(?:password|passwd|pwd|密码)[=: ]+\S+/i,
        apiKey: /(?:api[_-]?key|token|secret|auth)[=: ]+\S+/i,
        address: /(?:地址|address)[=: ]+\S{10,}/i
    };
    
    // 统计信息
    var stats = {
        reads: 0,
        writes: 0,
        sensitiveDetected: 0
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
                // 跳过Frida相关的堆栈
                if (className.indexOf("com.android.internal.os") !== -1) continue;
                
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
    
    // 检测文本中的敏感信息
    function detectSensitiveInfo(text) {
        if (!config.detectSensitiveData || !text) return null;
        
        var results = [];
        for (var key in sensitivePatterns) {
            if (sensitivePatterns[key].test(text)) {
                results.push(key);
            }
        }
        
        return results.length > 0 ? results : null;
    }
    
    // 格式化显示剪贴板内容
    function formatClipContent(content, type) {
        if (!content) return "<空内容>";
        
        try {
            var text = content.toString();
            
            // 检查文本长度，截断过长内容
            if (text.length > config.maxClipLength) {
                text = text.substring(0, config.maxClipLength) + "... (总长度: " + text.length + "字符)";
            }
            
            // 检测敏感信息
            var sensitiveTypes = detectSensitiveInfo(text);
            if (sensitiveTypes) {
                stats.sensitiveDetected++;
                
                // 对敏感信息进行脱敏处理
                if (config.obfuscateSensitive) {
                    // 简单的脱敏处理，替换部分字符为*
                    sensitiveTypes.forEach(function(type) {
                        switch (type) {
                            case "creditCard":
                                text = text.replace(sensitivePatterns.creditCard, function(match) {
                                    return match.substr(0, 4) + " **** **** " + match.substr(-4);
                                });
                                break;
                            case "email":
                                text = text.replace(sensitivePatterns.email, function(match) {
                                    var parts = match.split('@');
                                    var username = parts[0];
                                    var domain = parts[1];
                                    return username.substr(0, 3) + "***@" + domain;
                                });
                                break;
                            case "phone":
                                text = text.replace(sensitivePatterns.phone, function(match) {
                                    return match.substr(0, 3) + "****" + match.substr(-4);
                                });
                                break;
                            // 其他类型敏感信息的脱敏处理...
                        }
                    });
                }
                
                return text + "\n    [!] 检测到敏感信息类型: " + sensitiveTypes.join(", ");
            }
            
            return text;
            
        } catch (e) {
            return "<无法解析内容: " + e + ">";
        }
    }
    
    // 提取剪贴板数据
    function extractClipData(clip) {
        if (!clip) return null;
        
        try {
            var result = {};
            result.itemCount = clip.getItemCount();
            result.description = clip.getDescription() ? clip.getDescription().toString() : null;
            
            var items = [];
            for (var i = 0; i < result.itemCount; i++) {
                var item = clip.getItemAt(i);
                var itemData = {};
                
                // 获取文本内容
                try { itemData.text = item.getText() ? item.getText().toString() : null; } catch(e) {}
                
                // 获取HTML内容
                if (config.monitorAllFormats) {
                    try { itemData.html = item.getHtmlText(); } catch(e) {}
                    
                    // 获取URI
                    try { itemData.uri = item.getUri() ? item.getUri().toString() : null; } catch(e) {}
                    
                    // 获取Intent
                    try { itemData.intent = item.getIntent(); } catch(e) {}
                }
                
                items.push(itemData);
            }
            
            result.items = items;
            return result;
            
        } catch (e) {
            log(1, "解析剪贴板数据失败: " + e);
            return null;
        }
    }
    
    // 监控剪贴板管理器
    var ClipboardManager = Java.use('android.content.ClipboardManager');
    
    // 监控读取剪贴板内容
    ClipboardManager.getPrimaryClip.implementation = function () {
        var clip = this.getPrimaryClip();
        stats.reads++;
        
        log(2, "读取剪贴板 [#" + stats.reads + "]");
        
        if (clip) {
            var clipData = extractClipData(clip);
            if (clipData) {
                log(2, "    项目数量: " + clipData.itemCount);
                
                if (clipData.description) {
                    log(3, "    描述: " + clipData.description);
                }
                
                for (var i = 0; i < clipData.items.length; i++) {
                    var item = clipData.items[i];
                    
                    if (item.text) {
                        log(2, "    文本内容: " + formatClipContent(item.text, "text"));
                    }
                    
                    if (config.monitorAllFormats) {
                        if (item.html) {
                            log(3, "    HTML内容: " + formatClipContent(item.html, "html"));
                        }
                        if (item.uri) {
                            log(3, "    URI: " + item.uri);
                        }
                        if (item.intent) {
                            log(3, "    Intent: " + item.intent);
                        }
                    }
                }
            }
        } else {
            log(2, "    剪贴板为空");
        }
        
        if (config.printStack) {
            log(3, getStackTrace());
        }
        
        return clip;
    };
    
    // 监控写入剪贴板内容
    ClipboardManager.setPrimaryClip.implementation = function (clip) {
        stats.writes++;
        
        log(2, "写入剪贴板 [#" + stats.writes + "]");
        
        if (clip) {
            var clipData = extractClipData(clip);
            if (clipData) {
                log(2, "    项目数量: " + clipData.itemCount);
                
                if (clipData.description) {
                    log(3, "    描述: " + clipData.description);
                }
                
                for (var i = 0; i < clipData.items.length; i++) {
                    var item = clipData.items[i];
                    
                    if (item.text) {
                        log(2, "    文本内容: " + formatClipContent(item.text, "text"));
                    }
                    
                    if (config.monitorAllFormats) {
                        if (item.html) {
                            log(3, "    HTML内容: " + formatClipContent(item.html, "html"));
                        }
                        if (item.uri) {
                            log(3, "    URI: " + item.uri);
                        }
                        if (item.intent) {
                            log(3, "    Intent: " + item.intent);
                        }
                    }
                }
            }
        } else {
            log(2, "    尝试写入空剪贴板");
        }
        
        if (config.printStack) {
            log(3, getStackTrace());
        }
        
        return this.setPrimaryClip(clip);
    };
    
    // 监控hasText方法
    ClipboardManager.hasText.implementation = function () {
        var hasText = this.hasText();
        log(3, "检查剪贴板是否有文本: " + hasText);
        return hasText;
    };
    
    // 监控剪贴板变化的监听器
    ClipboardManager.addPrimaryClipChangedListener.implementation = function (listener) {
        log(2, "添加剪贴板变化监听器: " + listener.getClass().getName());
        
        if (config.printStack) {
            log(3, getStackTrace());
        }
        
        return this.addPrimaryClipChangedListener(listener);
    };
    
    // 监控移除剪贴板监听器
    ClipboardManager.removePrimaryClipChangedListener.implementation = function (listener) {
        log(2, "移除剪贴板变化监听器: " + listener.getClass().getName());
        return this.removePrimaryClipChangedListener(listener);
    };
    
    // 尝试监控Android 10+的剪贴板新方法
    try {
        // Android 10新增方法
        ClipboardManager.clearPrimaryClip.implementation = function () {
            log(2, "清空剪贴板");
            
            if (config.printStack) {
                log(3, getStackTrace());
            }
            
            return this.clearPrimaryClip();
        };
    } catch (e) {
        // 旧版Android可能没有此方法
    }
    
    // 打印初始化信息
    log(2, "剪贴板监控模块已启动");
    if (config.detectSensitiveData) {
        log(2, "已启用敏感数据检测: " + Object.keys(sensitivePatterns).length + " 种类型");
    }
    
    // 定期打印统计信息
    setInterval(function() {
        if (stats.reads > 0 || stats.writes > 0) {
            log(2, "剪贴板统计: 读取(" + stats.reads + 
                 "), 写入(" + stats.writes + 
                 "), 敏感数据(" + stats.sensitiveDetected + ")");
        }
    }, 30000); // 每30秒打印一次
}); 