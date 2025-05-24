/**
 * 内存搜索修改脚本
 * 
 * 功能：在Android应用的内存中搜索和修改特定值
 * 作用：修改游戏数值、绕过验证等
 * 适用：游戏修改、应用破解、数据分析
 */

// 等待Java虚拟机加载完成
Java.perform(function() {
    console.log("[*] 内存搜索修改脚本已启动");

    // 全局配置
    var config = {
        // 是否打印详细日志
        verbose: true,
        // 搜索结果最大数量
        maxResults: 1000,
        // 搜索范围限制（字节）
        searchRangeLimit: 10 * 1024 * 1024, // 10MB
        // 内存转储最大大小
        maxDumpSize: 1024 * 1024 // 1MB
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
     * 工具函数：格式化十六进制数据
     */
    function hexdump(data, size) {
        if (!data) return "null";
        
        size = size || 32;
        if (typeof data === "number") {
            data = ptr(data);
        }
        
        try {
            var buf = Memory.readByteArray(data, size);
            if (buf === null) {
                return "无法读取内存";
            }
            
            var result = [];
            var bytes = new Uint8Array(buf);
            var ascii = "";
            var line = "";
            
            for (var i = 0; i < bytes.length; i++) {
                // 每16字节换行
                if (i % 16 === 0) {
                    if (line !== "") {
                        result.push(line + "  " + ascii);
                        ascii = "";
                        line = "";
                    }
                    line = ("0000" + i.toString(16)).substr(-4) + ": ";
                }
                
                var value = bytes[i].toString(16);
                if (value.length === 1) {
                    value = "0" + value;
                }
                line += value + " ";
                
                if (bytes[i] >= 32 && bytes[i] <= 126) {
                    ascii += String.fromCharCode(bytes[i]);
                } else {
                    ascii += ".";
                }
            }
            
            if (line !== "") {
                var padding = "   ".repeat(16 - (bytes.length % 16));
                result.push(line + padding + "  " + ascii);
            }
            
            return result.join("\n");
        } catch (e) {
            return "hexdump错误: " + e;
        }
    }

    /**
     * 工具函数：获取模块内存范围
     */
    function getModuleRanges(moduleName) {
        var ranges = [];
        
        if (!moduleName) {
            // 获取所有模块的内存范围
            var modules = Process.enumerateModules();
            for (var i = 0; i < modules.length; i++) {
                var module = modules[i];
                ranges.push({
                    base: module.base,
                    size: module.size,
                    name: module.name,
                    path: module.path
                });
                
                if (config.verbose) {
                    console.log("[+] 模块: " + module.name + " 基址: " + module.base + " 大小: " + module.size);
                }
            }
        } else {
            // 获取指定模块的内存范围
            var module = Process.findModuleByName(moduleName);
            if (module) {
                ranges.push({
                    base: module.base,
                    size: module.size,
                    name: module.name,
                    path: module.path
                });
                
                if (config.verbose) {
                    console.log("[+] 模块: " + module.name + " 基址: " + module.base + " 大小: " + module.size);
                }
            } else {
                console.log("[-] 找不到模块: " + moduleName);
            }
        }
        
        return ranges;
    }

    /**
     * 工具函数：获取堆内存范围
     */
    function getHeapRanges() {
        var ranges = [];
        
        try {
            var JavaRuntime = Java.use('java.lang.Runtime');
            var runtime = JavaRuntime.getRuntime();
            var totalMemory = runtime.totalMemory();
            var freeMemory = runtime.freeMemory();
            var usedMemory = totalMemory - freeMemory;
            
            console.log("[+] Java堆内存信息:");
            console.log("    总内存: " + totalMemory + " 字节 (" + (totalMemory / 1024 / 1024).toFixed(2) + " MB)");
            console.log("    已使用: " + usedMemory + " 字节 (" + (usedMemory / 1024 / 1024).toFixed(2) + " MB)");
            console.log("    空闲: " + freeMemory + " 字节 (" + (freeMemory / 1024 / 1024).toFixed(2) + " MB)");
            
            // 获取堆内存范围
            var heapRanges = Process.enumerateRanges({
                protection: 'rw-',
                coalesce: true
            });
            
            for (var i = 0; i < heapRanges.length; i++) {
                var range = heapRanges[i];
                
                // 只选择可读写的内存区域
                if (range.protection.indexOf('r') !== -1 && range.protection.indexOf('w') !== -1) {
                    ranges.push({
                        base: range.base,
                        size: range.size,
                        protection: range.protection,
                        file: range.file ? range.file.path : "unknown"
                    });
                    
                    if (config.verbose) {
                        console.log("[+] 内存区域: " + range.base + " - " + range.base.add(range.size) + 
                                    " 大小: " + range.size + " 权限: " + range.protection + 
                                    (range.file ? " 文件: " + range.file.path : ""));
                    }
                }
            }
        } catch (e) {
            console.log("[-] 获取堆内存范围失败: " + e);
        }
        
        return ranges;
    }

    /**
     * 工具函数：在内存中搜索特定值
     */
    function searchMemory(pattern, type, ranges) {
        var results = [];
        
        if (!ranges || ranges.length === 0) {
            console.log("[+] 未指定内存范围，使用所有可读写内存");
            ranges = Process.enumerateRanges({
                protection: 'rw-',
                coalesce: true
            });
        }
        
        console.log("[+] 开始搜索内存: " + pattern + " (类型: " + type + ")");
        console.log("[+] 搜索范围: " + ranges.length + " 个内存区域");
        
        // 根据类型转换搜索模式
        var searchPattern;
        var searchFunction;
        
        switch (type.toLowerCase()) {
            case "int":
            case "integer":
                var intValue = parseInt(pattern);
                searchFunction = function(address, size) {
                    var results = [];
                    for (var i = 0; i <= size - 4; i += 4) {
                        try {
                            var value = Memory.readInt(address.add(i));
                            if (value === intValue) {
                                results.push(address.add(i));
                            }
                        } catch (e) {
                            // 忽略读取错误
                        }
                    }
                    return results;
                };
                break;
                
            case "float":
                var floatValue = parseFloat(pattern);
                searchFunction = function(address, size) {
                    var results = [];
                    for (var i = 0; i <= size - 4; i += 4) {
                        try {
                            var value = Memory.readFloat(address.add(i));
                            if (Math.abs(value - floatValue) < 0.0001) {
                                results.push(address.add(i));
                            }
                        } catch (e) {
                            // 忽略读取错误
                        }
                    }
                    return results;
                };
                break;
                
            case "double":
                var doubleValue = parseFloat(pattern);
                searchFunction = function(address, size) {
                    var results = [];
                    for (var i = 0; i <= size - 8; i += 8) {
                        try {
                            var value = Memory.readDouble(address.add(i));
                            if (Math.abs(value - doubleValue) < 0.0001) {
                                results.push(address.add(i));
                            }
                        } catch (e) {
                            // 忽略读取错误
                        }
                    }
                    return results;
                };
                break;
                
            case "string":
            case "utf8":
                searchFunction = function(address, size) {
                    var results = [];
                    var haystack = Memory.readByteArray(address, size);
                    if (!haystack) return results;
                    
                    var haystackStr = "";
                    try {
                        haystackStr = Memory.readUtf8String(address, size);
                    } catch (e) {
                        // 如果读取失败，尝试按字节搜索
                        var bytes = new Uint8Array(haystack);
                        haystackStr = "";
                        for (var i = 0; i < bytes.length; i++) {
                            haystackStr += String.fromCharCode(bytes[i]);
                        }
                    }
                    
                    var index = 0;
                    while (true) {
                        index = haystackStr.indexOf(pattern, index);
                        if (index === -1) break;
                        results.push(address.add(index));
                        index += pattern.length;
                    }
                    
                    return results;
                };
                break;
                
            case "hex":
                // 将十六进制字符串转换为字节数组
                var hexPattern = pattern.replace(/\s/g, "");
                if (hexPattern.length % 2 !== 0) {
                    console.log("[-] 无效的十六进制字符串: " + pattern);
                    return results;
                }
                
                var bytes = [];
                for (var i = 0; i < hexPattern.length; i += 2) {
                    bytes.push(parseInt(hexPattern.substr(i, 2), 16));
                }
                
                searchFunction = function(address, size) {
                    var results = [];
                    var haystack = Memory.readByteArray(address, size);
                    if (!haystack) return results;
                    
                    var haystackBytes = new Uint8Array(haystack);
                    
                    // 简单的字节匹配搜索
                    for (var i = 0; i <= haystackBytes.length - bytes.length; i++) {
                        var found = true;
                        for (var j = 0; j < bytes.length; j++) {
                            if (haystackBytes[i + j] !== bytes[j]) {
                                found = false;
                                break;
                            }
                        }
                        
                        if (found) {
                            results.push(address.add(i));
                        }
                    }
                    
                    return results;
                };
                break;
                
            default:
                console.log("[-] 不支持的搜索类型: " + type);
                return results;
        }
        
        // 开始搜索
        for (var i = 0; i < ranges.length; i++) {
            var range = ranges[i];
            
            // 跳过太大的内存区域
            if (range.size > config.searchRangeLimit) {
                console.log("[*] 跳过过大的内存区域: " + range.base + " 大小: " + range.size);
                continue;
            }
            
            try {
                if (config.verbose) {
                    console.log("[+] 搜索内存区域: " + range.base + " 大小: " + range.size);
                }
                
                var rangeResults = searchFunction(range.base, range.size);
                
                for (var j = 0; j < rangeResults.length; j++) {
                    results.push({
                        address: rangeResults[j],
                        memory: range
                    });
                    
                    // 限制结果数量
                    if (results.length >= config.maxResults) {
                        console.log("[!] 达到最大结果数量限制: " + config.maxResults);
                        return results;
                    }
                }
                
                if (rangeResults.length > 0 && config.verbose) {
                    console.log("[+] 在内存区域中找到 " + rangeResults.length + " 个匹配");
                }
            } catch (e) {
                console.log("[-] 搜索内存区域失败: " + range.base + " 错误: " + e);
            }
        }
        
        console.log("[+] 搜索完成，共找到 " + results.length + " 个匹配");
        return results;
    }

    /**
     * 工具函数：修改内存中的值
     */
    function writeMemory(address, value, type) {
        try {
            switch (type.toLowerCase()) {
                case "int":
                case "integer":
                    Memory.writeInt(address, parseInt(value));
                    console.log("[+] 已写入整数值: " + value + " 到地址: " + address);
                    break;
                    
                case "float":
                    Memory.writeFloat(address, parseFloat(value));
                    console.log("[+] 已写入浮点值: " + value + " 到地址: " + address);
                    break;
                    
                case "double":
                    Memory.writeDouble(address, parseFloat(value));
                    console.log("[+] 已写入双精度值: " + value + " 到地址: " + address);
                    break;
                    
                case "string":
                case "utf8":
                    Memory.writeUtf8String(address, value);
                    console.log("[+] 已写入字符串: " + value + " 到地址: " + address);
                    break;
                    
                case "hex":
                    var hexValue = value.replace(/\s/g, "");
                    if (hexValue.length % 2 !== 0) {
                        console.log("[-] 无效的十六进制字符串: " + value);
                        return false;
                    }
                    
                    var bytes = [];
                    for (var i = 0; i < hexValue.length; i += 2) {
                        bytes.push(parseInt(hexValue.substr(i, 2), 16));
                    }
                    
                    Memory.writeByteArray(address, bytes);
                    console.log("[+] 已写入十六进制数据: " + value + " 到地址: " + address);
                    break;
                    
                default:
                    console.log("[-] 不支持的写入类型: " + type);
                    return false;
            }
            
            return true;
        } catch (e) {
            console.log("[-] 写入内存失败: " + e);
            return false;
        }
    }

    /**
     * 工具函数：转储内存区域
     */
    function dumpMemory(address, size) {
        size = size || 256; // 默认转储256字节
        
        if (size > config.maxDumpSize) {
            console.log("[!] 转储大小超过限制，调整为: " + config.maxDumpSize + " 字节");
            size = config.maxDumpSize;
        }
        
        try {
            console.log("[+] 转储内存地址: " + address + " 大小: " + size + " 字节");
            var data = Memory.readByteArray(address, size);
            return hexdump(data, size);
        } catch (e) {
            console.log("[-] 转储内存失败: " + e);
            return null;
        }
    }

    /**
     * 工具函数：监视内存地址变化
     */
    function watchMemory(address, size, type, callback) {
        size = size || 4; // 默认监视4字节
        
        try {
            console.log("[+] 开始监视内存地址: " + address + " 大小: " + size + " 字节");
            
            var memoryAccessMonitor = {
                onAccess: function(details) {
                    var value;
                    
                    switch (type.toLowerCase()) {
                        case "int":
                        case "integer":
                            value = Memory.readInt(address);
                            break;
                        case "float":
                            value = Memory.readFloat(address);
                            break;
                        case "double":
                            value = Memory.readDouble(address);
                            break;
                        case "string":
                        case "utf8":
                            value = Memory.readUtf8String(address);
                            break;
                        default:
                            value = "未知类型";
                    }
                    
                    console.log("\n[+] 检测到内存访问:");
                    console.log("    地址: " + address);
                    console.log("    操作: " + details.operation);
                    console.log("    PC: " + details.from);
                    console.log("    当前值: " + value);
                    
                    // 打印调用堆栈
                    var stack = Thread.backtrace(details.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress);
                    console.log("    调用堆栈:");
                    for (var i = 0; i < stack.length; i++) {
                        console.log("        " + stack[i]);
                    }
                    
                    // 如果有回调函数，调用它
                    if (callback) {
                        callback(details, value);
                    }
                }
            };
            
            Memory.protect(address, size, 'rwx');
            var memoryAccessMonitorId = Memory.addMemoryAccessMonitor({
                base: address,
                size: size,
                callbacks: memoryAccessMonitor
            });
            
            return memoryAccessMonitorId;
        } catch (e) {
            console.log("[-] 监视内存失败: " + e);
            return null;
        }
    }

    /**
     * 工具函数：停止监视内存
     */
    function unwatchMemory(id) {
        try {
            Memory.removeMemoryAccessMonitor(id);
            console.log("[+] 已停止监视内存");
            return true;
        } catch (e) {
            console.log("[-] 停止监视内存失败: " + e);
            return false;
        }
    }

    /**
     * 工具函数：扫描Java对象
     */
    function scanJavaObjects(className) {
        try {
            var clazz = Java.use(className);
            var instances = [];
            
            Java.choose(className, {
                onMatch: function(instance) {
                    instances.push(instance);
                },
                onComplete: function() {
                    console.log("[+] 找到 " + instances.length + " 个 " + className + " 实例");
                    
                    // 打印每个实例的信息
                    for (var i = 0; i < instances.length; i++) {
                        var instance = instances[i];
                        console.log("\n[+] 实例 #" + (i + 1) + ":");
                        
                        // 尝试获取实例的字段
                        try {
                            var fields = clazz.class.getDeclaredFields();
                            for (var j = 0; j < fields.length; j++) {
                                var field = fields[j];
                                field.setAccessible(true);
                                
                                try {
                                    var value = field.get(instance);
                                    console.log("    " + field.getName() + " = " + value);
                                } catch (e) {
                                    console.log("    " + field.getName() + " = <无法访问>");
                                }
                            }
                        } catch (e) {
                            console.log("    <无法获取字段信息>");
                        }
                        
                        // 尝试调用toString方法
                        try {
                            console.log("    toString() = " + instance.toString());
                        } catch (e) {
                            console.log("    toString() = <无法调用>");
                        }
                    }
                }
            });
            
            return instances.length;
        } catch (e) {
            console.log("[-] 扫描Java对象失败: " + e);
            return 0;
        }
    }

    /**
     * 导出API到全局
     */
    // 搜索内存
    global.searchMemory = function(pattern, type, moduleName) {
        var ranges;
        if (moduleName) {
            ranges = getModuleRanges(moduleName);
        } else {
            ranges = getHeapRanges();
        }
        
        return searchMemory(pattern, type, ranges);
    };
    
    // 写入内存
    global.writeMemory = function(address, value, type) {
        if (typeof address === "string") {
            address = ptr(address);
        }
        
        return writeMemory(address, value, type);
    };
    
    // 转储内存
    global.dumpMemory = function(address, size) {
        if (typeof address === "string") {
            address = ptr(address);
        }
        
        return dumpMemory(address, size);
    };
    
    // 监视内存
    global.watchMemory = function(address, size, type, callback) {
        if (typeof address === "string") {
            address = ptr(address);
        }
        
        return watchMemory(address, size, type, callback);
    };
    
    // 停止监视内存
    global.unwatchMemory = function(id) {
        return unwatchMemory(id);
    };
    
    // 扫描Java对象
    global.scanJavaObjects = function(className) {
        return scanJavaObjects(className);
    };
    
    // 获取模块内存范围
    global.getModuleRanges = function(moduleName) {
        return getModuleRanges(moduleName);
    };
    
    // 获取堆内存范围
    global.getHeapRanges = function() {
        return getHeapRanges();
    };
    
    // 修改配置
    global.setConfig = function(newConfig) {
        for (var key in newConfig) {
            if (config.hasOwnProperty(key)) {
                config[key] = newConfig[key];
                console.log("[+] 配置已更新: " + key + " = " + newConfig[key]);
            }
        }
    };
    
    // 打印当前配置
    global.showConfig = function() {
        console.log("[+] 当前配置:");
        for (var key in config) {
            console.log("    " + key + ": " + config[key]);
        }
    };

    console.log("[*] 内存搜索修改脚本已加载");
    console.log("[*] 使用方法:");
    console.log("    searchMemory(pattern, type, moduleName) - 搜索内存");
    console.log("    writeMemory(address, value, type) - 写入内存");
    console.log("    dumpMemory(address, size) - 转储内存");
    console.log("    watchMemory(address, size, type, callback) - 监视内存");
    console.log("    unwatchMemory(id) - 停止监视内存");
    console.log("    scanJavaObjects(className) - 扫描Java对象");
    console.log("    getModuleRanges(moduleName) - 获取模块内存范围");
    console.log("    getHeapRanges() - 获取堆内存范围");
    console.log("    setConfig({key: value}) - 修改配置");
    console.log("    showConfig() - 打印当前配置");
}); 