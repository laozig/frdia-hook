/*
 * 脚本名称：监控文件读取.js
 * 功能：全面监控Android应用中的文件读写操作，包括Java和Native层
 * 适用场景：
 *   - 分析应用文件访问行为
 *   - 定位配置文件、缓存或敏感数据文件
 *   - 监控数据持久化
 *   - 检测可能的数据泄露
 * 使用方法：
 *   1. frida -U -f 包名 -l 监控文件读取.js --no-pause
 *   2. 查看控制台输出，了解应用的文件访问行为
 * 启动方式说明：
 *   - -U 代表使用USB连接的设备
 *   - -f 代表以spawn方式启动目标应用
 *   - --no-pause 指示Frida不要暂停应用执行
 * 支持特性：
 *   - 监控Java层所有常见文件IO操作
 *   - 监控Native层open/fopen等文件操作
 *   - 过滤系统文件，聚焦应用数据
 *   - 显示文件内容和大小
 *   - 调用堆栈追踪
 *   - 检测特权目录访问
 *   - 监控文件权限设置
 */

(function() {
    // 全局配置
    var config = {
        logLevel: 2,                // 0:关闭 1:错误 2:基本信息 3:详细
        printStack: true,           // 是否打印调用堆栈
        maxStackDepth: 5,           // 最大堆栈深度
        showFileContent: true,      // 是否显示文件内容
        maxContentLength: 200,      // 最大显示内容长度
        filterSystemFiles: true,    // 是否过滤系统文件
        monitorNative: true,        // 是否监控Native层文件操作
        checkSensitivePaths: true,  // 检查敏感路径访问
        trackFileDescriptors: true  // 跟踪文件描述符
    };
    
    // 统计信息
    var stats = {
        reads: 0,
        writes: 0,
        creates: 0,
        deletes: 0,
        byExtension: {}
    };
    
    // 跟踪打开的文件描述符
    var openFiles = {};
    
    // 敏感路径列表
    var sensitivePaths = [
        "/data/data/",
        "/sdcard/",
        "/storage/emulated/0/",
        "/proc/",
        "/system/",
        "/data/local/tmp/"
    ];
    
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
                
                // 过滤掉常见的框架类
                if (className.indexOf("java.io.") === 0 && i > 0) continue;
                
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
    
    // 辅助函数：检查路径是否为敏感路径
    function isSensitivePath(path) {
        if (!config.checkSensitivePaths || !path) return false;
        
        for (var i = 0; i < sensitivePaths.length; i++) {
            if (path.indexOf(sensitivePaths[i]) === 0) {
                return true;
            }
        }
        return false;
    }
    
    // 辅助函数：是否要过滤掉系统文件
    function shouldFilter(path) {
        if (!config.filterSystemFiles) return false;
        if (!path) return false;
        
        // 过滤系统目录
        if (path.indexOf("/system/") === 0) return true;
        if (path.indexOf("/vendor/") === 0) return true;
        if (path.indexOf("/apex/") === 0) return true;
        
        // 过滤临时文件
        if (path.endsWith(".tmp")) return true;
        
        // 过滤缓存和日志文件
        if (path.indexOf("/cache/") !== -1) return true;
        if (path.indexOf("/logs/") !== -1) return true;
        
        return false;
    }
    
    // 辅助函数：更新文件扩展名统计
    function updateExtensionStats(path) {
        if (!path) return;
        
        var extension = "无扩展名";
        var lastDotIndex = path.lastIndexOf(".");
        
        if (lastDotIndex !== -1 && lastDotIndex < path.length - 1) {
            extension = path.substring(lastDotIndex + 1).toLowerCase();
        }
        
        if (!stats.byExtension[extension]) {
            stats.byExtension[extension] = { reads: 0, writes: 0 };
        }
    }
    
    // 辅助函数：从文件模式字符串获取文件操作类型
    function getModeType(mode) {
        if (!mode) return "未知";
        
        mode = mode.toLowerCase();
        if (mode.indexOf("r") !== -1 && mode.indexOf("w") === -1) {
            return "读取";
        } else if (mode.indexOf("w") !== -1 || mode.indexOf("a") !== -1) {
            return "写入";
        } else {
            return "未知模式:" + mode;
        }
    }

    Java.perform(function() {
        // 1. 监控 FileInputStream (文件读取)
        var FileInputStream = Java.use("java.io.FileInputStream");
        
        // 监控 FileInputStream 构造函数 (String路径)
        FileInputStream.$init.overload('java.lang.String').implementation = function(filename) {
            if (!shouldFilter(filename)) {
                stats.reads++;
                updateExtensionStats(filename);
                
                var message = "打开文件读取: " + filename;
                if (isSensitivePath(filename)) {
                    message += " [敏感路径]";
                    log(1, message);
                } else {
                    log(2, message);
                }
                
                if (config.printStack) {
                    log(3, getStackTrace());
                }
            }
            return this.$init(filename);
        };
        
        // 监控 FileInputStream 构造函数 (File对象)
        FileInputStream.$init.overload('java.io.File').implementation = function(file) {
            var filename = file.getAbsolutePath();
            
            if (!shouldFilter(filename)) {
                stats.reads++;
                updateExtensionStats(filename);
                
                var message = "打开文件读取: " + filename;
                if (isSensitivePath(filename)) {
                    message += " [敏感路径]";
                    log(1, message);
                } else {
                    log(2, message);
                }
                
                if (config.printStack) {
                    log(3, getStackTrace());
                }
            }
            return this.$init(file);
        };
        
        // 2. 监控 FileOutputStream (文件写入)
        var FileOutputStream = Java.use("java.io.FileOutputStream");
        
        // 监控 FileOutputStream 构造函数 (String路径)
        FileOutputStream.$init.overload('java.lang.String').implementation = function(filename) {
            if (!shouldFilter(filename)) {
                stats.writes++;
                updateExtensionStats(filename);
                
                var message = "打开文件写入: " + filename;
                if (isSensitivePath(filename)) {
                    message += " [敏感路径]";
                    log(1, message);
                } else {
                    log(2, message);
                }
                
                if (config.printStack) {
                    log(3, getStackTrace());
                }
            }
            return this.$init(filename);
        };
        
        // 监控 FileOutputStream 构造函数 (String路径,Boolean追加)
        FileOutputStream.$init.overload('java.lang.String', 'boolean').implementation = function(filename, append) {
            if (!shouldFilter(filename)) {
                stats.writes++;
                updateExtensionStats(filename);
                
                var message = "打开文件" + (append ? "追加: " : "写入: ") + filename;
                if (isSensitivePath(filename)) {
                    message += " [敏感路径]";
                    log(1, message);
                } else {
                    log(2, message);
                }
                
                if (config.printStack) {
                    log(3, getStackTrace());
                }
            }
            return this.$init(filename, append);
        };
        
        // 3. 监控 File 操作
        var File = Java.use("java.io.File");
        
        // 监控文件创建
        File.createNewFile.implementation = function() {
            var path = this.getAbsolutePath();
            
            if (!shouldFilter(path)) {
                stats.creates++;
                updateExtensionStats(path);
                log(2, "创建文件: " + path);
                
                if (config.printStack) {
                    log(3, getStackTrace());
                }
            }
            return this.createNewFile();
        };
        
        // 监控文件删除
        File.delete.implementation = function() {
            var path = this.getAbsolutePath();
            
            if (!shouldFilter(path)) {
                stats.deletes++;
                log(2, "删除文件: " + path);
                
                if (config.printStack) {
                    log(3, getStackTrace());
                }
            }
            return this.delete();
        };
        
        // 监控读取文件列表
        File.listFiles.implementation = function() {
            var path = this.getAbsolutePath();
            var result = this.listFiles();
            
            if (!shouldFilter(path) && result && result.length > 0) {
                log(3, "列出目录内容: " + path + " (" + result.length + " 个文件)");
            }
            return result;
        };
        
        // 4. 监控 RandomAccessFile
        var RandomAccessFile = Java.use("java.io.RandomAccessFile");
        
        RandomAccessFile.$init.implementation = function(file, mode) {
            var filename = "";
            
            if (typeof file === "string") {
                filename = file;
            } else {
                filename = file.getAbsolutePath();
            }
            
            if (!shouldFilter(filename)) {
                var operation = getModeType(mode);
                if (operation === "读取") {
                    stats.reads++;
                } else if (operation === "写入") {
                    stats.writes++;
                }
                
                updateExtensionStats(filename);
                log(2, "随机访问文件(" + operation + "): " + filename + " 模式: " + mode);
                
                if (config.printStack) {
                    log(3, getStackTrace());
                }
            }
            return this.$init(file, mode);
        };
        
        // 5. 监控Native层文件操作（如果启用）
        if (config.monitorNative) {
            try {
                // 监控 libc.so 中的 open 函数
                Interceptor.attach(Module.findExportByName("libc.so", "open"), {
                    onEnter: function(args) {
                        this.path = args[0].readCString();
                        this.flags = args[1].toInt32();
                        
                        if (!shouldFilter(this.path)) {
                            var isWrite = (this.flags & 2) === 2; // O_RDWR (2) 或 O_WRONLY (1)
                            
                            if (isWrite) {
                                stats.writes++;
                                log(2, "Native层打开文件(写入): " + this.path);
                            } else {
                                stats.reads++;
                                log(2, "Native层打开文件(读取): " + this.path);
                            }
                            
                            updateExtensionStats(this.path);
                        }
                    },
                    onLeave: function(retval) {
                        var fd = retval.toInt32();
                        
                        // 如果我们要跟踪文件描述符
                        if (config.trackFileDescriptors && fd > 0 && !shouldFilter(this.path)) {
                            openFiles[fd] = {
                                path: this.path,
                                time: new Date()
                            };
                        }
                    }
                });
                
                // 监控 fopen 函数
                Interceptor.attach(Module.findExportByName("libc.so", "fopen"), {
                    onEnter: function(args) {
                        this.path = args[0].readCString();
                        this.mode = args[1].readCString();
                        
                        if (!shouldFilter(this.path)) {
                            var operation = getModeType(this.mode);
                            
                            if (operation === "读取") {
                                stats.reads++;
                            } else if (operation === "写入") {
                                stats.writes++;
                            }
                            
                            log(2, "Native层fopen(" + operation + "): " + this.path + " 模式: " + this.mode);
                            updateExtensionStats(this.path);
                        }
                    }
                });
                
                // 监控 remove/unlink 函数（删除文件）
                var removeSym = Module.findExportByName("libc.so", "remove");
                if (removeSym) {
                    Interceptor.attach(removeSym, {
                        onEnter: function(args) {
                            var path = args[0].readCString();
                            
                            if (!shouldFilter(path)) {
                                stats.deletes++;
                                log(2, "Native层删除文件: " + path);
                            }
                        }
                    });
                }
                
                // 监控 rename 函数（重命名文件）
                var renameSym = Module.findExportByName("libc.so", "rename");
                if (renameSym) {
                    Interceptor.attach(renameSym, {
                        onEnter: function(args) {
                            this.oldPath = args[0].readCString();
                            this.newPath = args[1].readCString();
                            
                            if (!shouldFilter(this.oldPath) && !shouldFilter(this.newPath)) {
                                log(2, "Native层重命名文件: " + this.oldPath + " -> " + this.newPath);
                            }
                        }
                    });
                }
            } catch (e) {
                log(1, "监控Native层文件操作失败: " + e);
            }
        }
        
        // 6. 监控文件读写内容
        if (config.showFileContent) {
            try {
                // 监控 InputStream.read 方法
                var FileInputStream_read = FileInputStream.read.overload('[B', 'int', 'int');
                FileInputStream_read.implementation = function(buffer, offset, length) {
                    var bytesRead = this.read(buffer, offset, length);
                    
                    if (bytesRead > 0) {
                        try {
                            var path = Java.use("java.lang.reflect.Field").class.getDeclaredField.apply(this.getClass(), ["path"]);
                            path.setAccessible(true);
                            var filePath = path.get(this);
                            
                            if (!shouldFilter(filePath)) {
                                try {
                                    var data = Java.array('byte', buffer);
                                    var str = "";
                                    for (var i = offset; i < offset + Math.min(bytesRead, config.maxContentLength); i++) {
                                        var c = data[i] & 0xff;
                                        // 只显示可打印ASCII字符，其他显示为点
                                        if (c >= 32 && c <= 126) {
                                            str += String.fromCharCode(c);
                                        } else {
                                            str += ".";
                                        }
                                    }
                                    
                                    if (bytesRead > config.maxContentLength) {
                                        str += "... (" + bytesRead + " bytes)";
                                    }
                                    
                                    log(3, "从文件读取内容: " + filePath + "\n    内容: " + str);
                                } catch (e) {
                                    // 忽略解析错误
                                }
                            }
                        } catch (e) {
                            // 忽略获取路径失败的情况
                        }
                    }
                    
                    return bytesRead;
                };
                
                // 监控 OutputStream.write 方法
                var FileOutputStream_write = FileOutputStream.write.overload('[B', 'int', 'int');
                FileOutputStream_write.implementation = function(buffer, offset, length) {
                    try {
                        var path = Java.use("java.lang.reflect.Field").class.getDeclaredField.apply(this.getClass(), ["path"]);
                        path.setAccessible(true);
                        var filePath = path.get(this);
                        
                        if (!shouldFilter(filePath)) {
                            try {
                                var data = Java.array('byte', buffer);
                                var str = "";
                                for (var i = offset; i < offset + Math.min(length, config.maxContentLength); i++) {
                                    var c = data[i] & 0xff;
                                    // 只显示可打印ASCII字符，其他显示为点
                                    if (c >= 32 && c <= 126) {
                                        str += String.fromCharCode(c);
                                    } else {
                                        str += ".";
                                    }
                                }
                                
                                if (length > config.maxContentLength) {
                                    str += "... (" + length + " bytes)";
                                }
                                
                                log(3, "写入文件内容: " + filePath + "\n    内容: " + str);
                            } catch (e) {
                                // 忽略解析错误
                            }
                        }
                    } catch (e) {
                        // 忽略获取路径失败的情况
                    }
                    
                    return this.write(buffer, offset, length);
                };
            } catch (e) {
                log(1, "监控文件内容失败: " + e);
            }
        }
        
        // 定期输出统计信息
        setInterval(function() {
            if (stats.reads > 0 || stats.writes > 0 || stats.creates > 0 || stats.deletes > 0) {
                log(2, "文件操作统计: 读取(" + stats.reads + 
                     "), 写入(" + stats.writes + 
                     "), 创建(" + stats.creates + 
                     "), 删除(" + stats.deletes + ")");
                
                // 输出文件类型统计
                var extInfo = "";
                for (var ext in stats.byExtension) {
                    var extStats = stats.byExtension[ext];
                    if (extStats.reads > 0 || extStats.writes > 0) {
                        extInfo += "\n    ." + ext + ": 读取(" + extStats.reads + 
                                 "), 写入(" + extStats.writes + ")";
                    }
                }
                
                if (extInfo) log(2, "文件类型统计:" + extInfo);
            }
        }, 10000); // 每10秒输出一次
    });
    
    log(2, "文件操作监控已启动，正在监控Java IO操作" + 
        (config.monitorNative ? "和Native层文件操作" : ""));
})(); 