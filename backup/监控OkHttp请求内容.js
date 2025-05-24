/*
 * 脚本名称：监控OkHttp请求内容.js
 * 功能描述：监控应用使用OkHttp库发送的网络请求，包括URL和请求体内容
 * 
 * 适用场景：
 *   - 分析应用的网络通信行为
 *   - 获取应用与服务器交互的数据
 *   - 发现隐藏的API调用和数据传输
 *   - 调试网络相关问题
 *   - 分析应用的认证机制和数据加密方式
 *
 * 使用方法：
 *   1. frida -U -f 目标应用包名 -l 监控OkHttp请求内容.js --no-pause
 *   2. 或者 frida -U --attach-pid 目标进程PID -l 监控OkHttp请求内容.js
 *   3. 操作应用触发网络请求，观察控制台输出的请求URL和内容
 *
 * 启动方式说明：
 *   - -U: 使用USB连接的设备
 *   - -f: 指定以spawn方式启动的应用包名
 *   - --attach-pid: 附加到已运行的进程
 *   - --no-pause: 注入后不暂停应用执行
 *
 * 工作原理：
 *   Hook OkHttp3库中的RealCall.execute方法，该方法是OkHttp发起同步网络请求的入口点。
 *   当应用使用OkHttp发送请求时，脚本会拦截这些调用，从Request对象中提取URL信息，
 *   并尝试读取请求体内容。通过这种方式，可以获取应用发送到服务器的所有数据，
 *   包括URL、参数、请求头和请求体等信息。
 *
 * 注意事项：
 *   - 此脚本仅适用于使用OkHttp3库的应用
 *   - 仅监控同步请求，可以扩展脚本监控异步请求(enqueue方法)
 *   - 某些请求体可能无法直接读取，如流式上传
 *   - 建议配合监控OkHttp响应内容.js一起使用，获取完整通信数据
 *   - 对于HTTPS请求，可以配合绕过SSL证书校验.js使用
 *   - 不同版本的OkHttp可能需要调整Hook点
 */

// 配置选项
var config = {
    // 基本设置
    printHeaders: true,          // 是否打印请求头
    printStacktrace: true,       // 是否打印调用堆栈
    prettyPrintJson: true,       // 是否美化JSON输出
    monitorAsync: true,          // 是否监控异步请求
    colorOutput: true,           // 是否启用彩色输出
    
    // 筛选设置
    excludeUrls: [],             // 要排除的URL关键词
    includeUrlsOnly: [],         // 只包含这些URL关键词(空数组表示不限制)
    
    // 敏感信息处理
    maskSensitiveHeaders: true,  // 是否掩码敏感头部信息
    sensitiveHeaders: [          // 敏感头部名称
        "Authorization", 
        "Cookie", 
        "Set-Cookie", 
        "X-Auth-Token"
    ],
    
    // 日志设置
    saveToFile: false,           // 是否保存到文件
    logFilePath: "/sdcard/okhttp_log.txt"  // 日志文件路径
};

// 统计信息
var stats = {
    totalRequests: 0,
    syncRequests: 0,
    asyncRequests: 0,
    methodStats: {},
    hostStats: {},
    startTime: new Date().getTime()
};

// Hook OkHttp 的网络请求，监控所有请求的 URL 和请求体
Java.perform(function () {
    // 辅助函数：获取简短的调用堆栈
    function getStackTrace() {
        if (!config.printStacktrace) return "";
        
        try {
            var Exception = Java.use("java.lang.Exception");
            var Log = Java.use("android.util.Log");
            
            var exception = Exception.$new();
            var stackString = Log.getStackTraceString(exception);
            exception.$dispose();
            
            // 提取关键帧
            var lines = stackString.split('\n');
            var relevantLines = [];
            var startCapturing = false;
            
            for (var i = 0; i < lines.length; i++) {
                var line = lines[i];
                
                // 跳过Frida和OkHttp内部栈
                if (line.indexOf("com.android.okhttp") !== -1 || 
                    line.indexOf("okhttp3.") !== -1) {
                    if (!startCapturing) continue;
                }
                
                startCapturing = true;
                
                // 跳过系统类
                if (line.indexOf("java.lang.") !== -1 || 
                    line.indexOf("java.util.") !== -1 ||
                    line.indexOf("android.os.") !== -1) {
                    continue;
                }
                
                relevantLines.push(line);
                if (relevantLines.length >= 5) break; // 只取前5帧
            }
            
            return "\n    调用栈: \n        " + relevantLines.join("\n        ");
        } catch (e) {
            return "\n    获取调用栈失败: " + e;
        }
    }
    
    // 辅助函数：美化JSON输出
    function prettyPrintJson(str) {
        if (!config.prettyPrintJson) return str;
        
        try {
            if (str.indexOf("{") === 0 || str.indexOf("[") === 0) {
                var jsonObj = JSON.parse(str);
                return JSON.stringify(jsonObj, null, 4);
            }
        } catch (e) {}
        
        return str;
    }
    
    // 辅助函数：检查URL是否应该被排除
    function shouldExcludeUrl(url) {
        // 检查排除列表
        for (var i = 0; i < config.excludeUrls.length; i++) {
            if (url.indexOf(config.excludeUrls[i]) !== -1) {
                return true;
            }
        }
        
        // 检查包含列表(如果存在)
        if (config.includeUrlsOnly.length > 0) {
            var included = false;
            for (var i = 0; i < config.includeUrlsOnly.length; i++) {
                if (url.indexOf(config.includeUrlsOnly[i]) !== -1) {
                    included = true;
                    break;
                }
            }
            return !included;
        }
        
        return false;
    }
    
    // 辅助函数：处理敏感头部信息
    function maskSensitiveHeader(name, value) {
        if (!config.maskSensitiveHeaders) return value;
        
        // 检查是否是敏感头部
        for (var i = 0; i < config.sensitiveHeaders.length; i++) {
            if (name.toLowerCase() === config.sensitiveHeaders[i].toLowerCase()) {
                if (value.length > 8) {
                    return value.substring(0, 4) + "..." + value.substring(value.length - 4);
                } else {
                    return "********";
                }
            }
        }
        
        return value;
    }
    
    // 辅助函数：提取域名
    function extractHost(url) {
        try {
            // 移除协议前缀
            var hostStart = url.indexOf("://");
            if (hostStart !== -1) {
                hostStart += 3;
                var hostEnd = url.indexOf("/", hostStart);
                if (hostEnd !== -1) {
                    return url.substring(hostStart, hostEnd);
                } else {
                    return url.substring(hostStart);
                }
            }
        } catch (e) {}
        return "unknown-host";
    }
    
    // 辅助函数：更新统计信息
    function updateStats(isAsync, method, url) {
        stats.totalRequests++;
        if (isAsync) {
            stats.asyncRequests++;
        } else {
            stats.syncRequests++;
        }
        
        // 更新请求方法统计
        stats.methodStats[method] = (stats.methodStats[method] || 0) + 1;
        
        // 更新主机统计
        var host = extractHost(url);
        stats.hostStats[host] = (stats.hostStats[host] || 0) + 1;
    }
    
    // 主要函数：处理请求
    function processRequest(request, isAsync) {
        try {
            var url = request.url().toString();
            var method = request.method();
            
            // 检查是否应该排除此URL
            if (shouldExcludeUrl(url)) {
                return;
            }
            
            // 更新统计
            updateStats(isAsync, method, url);
            
            // 构建请求信息字符串
            var requestInfo = "";
            
            // 请求标题
            var title = "[*] OkHttp " + (isAsync ? "异步" : "同步") + "请求: " + method + " " + url;
            if (config.colorOutput) {
                if (method === "GET") {
                    title = "\x1b[32m" + title + "\x1b[0m"; // 绿色
                } else if (method === "POST") {
                    title = "\x1b[33m" + title + "\x1b[0m"; // 黄色
                } else if (method === "PUT") {
                    title = "\x1b[34m" + title + "\x1b[0m"; // 蓝色
                } else if (method === "DELETE") {
                    title = "\x1b[31m" + title + "\x1b[0m"; // 红色
                }
            }
            requestInfo += title + "\n";
            
            // 显示请求头
            if (config.printHeaders) {
                requestInfo += "    请求头:\n";
                var headers = request.headers();
                var headerNames = headers.names().toArray();
                
                for (var i = 0; i < headerNames.length; i++) {
                    var name = headerNames[i];
                    var value = headers.get(name);
                    requestInfo += "        " + name + ": " + maskSensitiveHeader(name, value) + "\n";
                }
            }
            
            // 显示请求体
        var body = request.body();
        if (body) {
            try {
                var Buffer = Java.use('okio.Buffer');
                var buffer = Buffer.$new();
                body.writeTo(buffer);
                var charset = Java.use('java.nio.charset.Charset').forName('UTF-8');
                var content = buffer.readString(charset);
                    
                    // 尝试美化JSON
                    var formattedContent = prettyPrintJson(content);
                    requestInfo += "    请求体:\n";
                    
                    // 对于美化后的JSON，每行添加缩进
                    if (formattedContent !== content) {
                        var lines = formattedContent.split('\n');
                        for (var i = 0; i < lines.length; i++) {
                            requestInfo += "        " + lines[i] + "\n";
                        }
                    } else {
                        requestInfo += "        " + content + "\n";
                    }
                } catch (e) {
                    requestInfo += "    请求体: <无法读取: " + e + ">\n";
                }
            } else {
                requestInfo += "    请求体: <无>\n";
            }
            
            // 显示调用栈
            if (config.printStacktrace) {
                requestInfo += getStackTrace() + "\n";
            }
            
            // 打印请求信息
            console.log(requestInfo);
            
            // 保存到文件
            if (config.saveToFile) {
                try {
                    var File = Java.use("java.io.File");
                    var FileOutputStream = Java.use("java.io.FileOutputStream");
                    var OutputStreamWriter = Java.use("java.io.OutputStreamWriter");
                    var BufferedWriter = Java.use("java.io.BufferedWriter");
                    
                    var file = File.$new(config.logFilePath);
                    var fileExists = file.exists();
                    var writer = BufferedWriter.$new(OutputStreamWriter.$new(
                        FileOutputStream.$new(file, true)));
                    
                    if (!fileExists) {
                        writer.write("--- OkHttp请求日志 ---\n\n");
                    }
                    
                    writer.write(requestInfo + "\n");
                    writer.flush();
                    writer.close();
            } catch (e) {
                    console.log("[!] 写入日志文件失败: " + e);
                }
            }
        } catch (e) {
            console.log("[!] 处理请求时发生错误: " + e);
        }
    }
    
    // 显示统计信息
    function showStats() {
        var duration = (new Date().getTime() - stats.startTime) / 1000;
        var statsInfo = "\n[*] OkHttp请求统计 (运行时间: " + duration.toFixed(1) + "秒):\n";
        statsInfo += "    总请求数: " + stats.totalRequests + "\n";
        statsInfo += "    同步请求: " + stats.syncRequests + "\n";
        statsInfo += "    异步请求: " + stats.asyncRequests + "\n";
        
        // 请求方法统计
        statsInfo += "    HTTP方法统计:\n";
        var methodNames = Object.keys(stats.methodStats);
        for (var i = 0; i < methodNames.length; i++) {
            var method = methodNames[i];
            statsInfo += "        " + method + ": " + stats.methodStats[method] + "\n";
        }
        
        // 主机统计
        statsInfo += "    主机统计 (前5个):\n";
        var hostNames = Object.keys(stats.hostStats).sort(function(a, b) {
            return stats.hostStats[b] - stats.hostStats[a];
        });
        
        for (var i = 0; i < Math.min(5, hostNames.length); i++) {
            var host = hostNames[i];
            statsInfo += "        " + host + ": " + stats.hostStats[host] + "\n";
        }
        
        console.log(statsInfo);
    }
    
    // 定期显示统计
    setInterval(showStats, 60000); // 每分钟显示一次统计
    
    //============ 开始Hook OkHttp ============//
    try {
        // 1. 监控同步请求
        var RealCall = Java.use('okhttp3.RealCall');
        RealCall.execute.implementation = function () {
            var request = this.request();
            processRequest(request, false);
            
            var startTime = new Date().getTime();
            var response = this.execute();
            var endTime = new Date().getTime();
            var executionTime = endTime - startTime;
            
            console.log("[*] 请求完成，耗时: " + executionTime + "ms");
            return response;
        };
        
        // 2. 监控异步请求
        if (config.monitorAsync) {
            RealCall.enqueue.overload('okhttp3.Callback').implementation = function (callback) {
                var request = this.request();
                processRequest(request, true);
                
                // 创建回调包装器以获取响应时间
                var startTime = new Date().getTime();
                var callbackWrapper = Java.registerClass({
                    name: 'okhttp3.CallbackWrapper',
                    implements: [Java.use('okhttp3.Callback')],
                    fields: {
                        originalCallback: 'okhttp3.Callback'
                    },
                    methods: {
                        '<init>': [{
                            returnType: 'void',
                            argumentTypes: ['okhttp3.Callback'],
                            implementation: function(original) {
                                this.originalCallback.value = original;
                            }
                        }],
                        onFailure: [{
                            returnType: 'void',
                            argumentTypes: ['okhttp3.Call', 'java.io.IOException'],
                            implementation: function(call, e) {
                                var endTime = new Date().getTime();
                                var executionTime = endTime - startTime;
                                console.log("[*] 异步请求失败，耗时: " + executionTime + "ms, 错误: " + e);
                                this.originalCallback.value.onFailure(call, e);
                            }
                        }],
                        onResponse: [{
                            returnType: 'void',
                            argumentTypes: ['okhttp3.Call', 'okhttp3.Response'],
                            implementation: function(call, response) {
                                var endTime = new Date().getTime();
                                var executionTime = endTime - startTime;
                                console.log("[*] 异步请求完成，耗时: " + executionTime + "ms");
                                this.originalCallback.value.onResponse(call, response);
                            }
                        }]
                    }
                });
                
                var wrappedCallback = callbackWrapper.$new(callback);
                return this.enqueue(wrappedCallback);
            };
        }
        
        console.log("[+] OkHttp请求监控已启动");
        console.log("    同步请求监控: 已启用");
        console.log("    异步请求监控: " + (config.monitorAsync ? "已启用" : "已禁用"));
        console.log("    请求头显示: " + (config.printHeaders ? "已启用" : "已禁用"));
        console.log("    JSON美化: " + (config.prettyPrintJson ? "已启用" : "已禁用"));
        console.log("    调用栈显示: " + (config.printStacktrace ? "已启用" : "已禁用"));
        
    } catch (e) {
        console.log("[!] OkHttp监控设置失败: " + e);
        
        // 尝试其他可能的类名/包名
        try {
            console.log("[*] 尝试使用替代方式监控OkHttp...");
            
            // 查找可能的OkHttp类
            var possibleClasses = [
                "com.android.okhttp.Call",
                "com.android.okhttp.OkHttpClient",
                "com.squareup.okhttp.Call",
                "com.squareup.okhttp.OkHttpClient"
            ];
            
            for (var i = 0; i < possibleClasses.length; i++) {
                try {
                    var TestClass = Java.use(possibleClasses[i]);
                    console.log("[+] 找到备选OkHttp类: " + possibleClasses[i]);
                    // 这里可以实现对这些替代类的Hook
                } catch (e) {
                    // 类不存在，继续检查下一个
                }
            }
        } catch (e2) {
            console.log("[!] 无法找到有效的OkHttp类: " + e2);
        }
    }
}); 