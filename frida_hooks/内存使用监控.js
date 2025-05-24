/**
 * 内存使用监控脚本
 * 
 * 功能：监控Android应用的内存使用情况
 * 作用：分析内存占用、检测内存泄漏、优化内存使用
 * 适用：内存问题排查、性能优化、OOM问题分析
 */

// 等待Java虚拟机加载完成
Java.perform(function() {
    console.log("[*] 内存使用监控脚本已启动");

    // 全局配置
    var config = {
        // 是否显示详细日志
        verbose: true,
        // 是否打印调用堆栈
        printStack: true,
        // 是否监控大对象分配
        monitorLargeAllocations: true,
        // 大对象阈值（字节）
        largeObjectThreshold: 1024 * 1024, // 1MB
        // 是否监控内存泄漏
        monitorLeaks: true,
        // 是否监控Bitmap创建
        monitorBitmaps: true,
        // 是否周期性收集内存信息
        periodicCollection: true,
        // 收集周期（毫秒）
        collectionInterval: 5000
    };

    // 内存使用数据
    var memoryData = {
        // 内存使用历史
        memoryHistory: [],
        // 大对象分配记录
        largeAllocations: [],
        // 对象计数
        objectCounts: {},
        // Bitmap统计
        bitmapStats: {
            count: 0,
            totalSize: 0,
            largest: {size: 0, stack: ""}
        }
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
     * 工具函数：格式化字节大小
     */
    function formatBytes(bytes) {
        if (bytes < 1024) return bytes + " B";
        else if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + " KB";
        else if (bytes < 1024 * 1024 * 1024) return (bytes / 1024 / 1024).toFixed(2) + " MB";
        else return (bytes / 1024 / 1024 / 1024).toFixed(2) + " GB";
    }

    /**
     * 工具函数：收集内存使用信息
     */
    function collectMemoryInfo() {
        try {
            var Runtime = Java.use("java.lang.Runtime");
            var ActivityManager = Java.use("android.app.ActivityManager");
            var Debug = Java.use("android.os.Debug");
            var Context = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext();
            
            var runtime = Runtime.getRuntime();
            var maxMemory = runtime.maxMemory();
            var totalMemory = runtime.totalMemory();
            var freeMemory = runtime.freeMemory();
            var usedMemory = totalMemory - freeMemory;
            
            // 获取更详细的内存信息
            var memoryInfo = null;
            try {
                var ActivityManager_MemoryInfo = Java.use("android.app.ActivityManager$MemoryInfo");
                memoryInfo = ActivityManager_MemoryInfo.$new();
                var activityManager = Context.getSystemService(Context.ACTIVITY_SERVICE);
                activityManager.getMemoryInfo(memoryInfo);
            } catch (e) {
                console.log("[-] 无法获取ActivityManager.MemoryInfo: " + e);
            }
            
            // 获取Native堆信息
            var nativeHeapSize = 0;
            var nativeHeapAllocated = 0;
            var nativeHeapFree = 0;
            
            try {
                nativeHeapSize = Debug.getNativeHeapSize();
                nativeHeapAllocated = Debug.getNativeHeapAllocatedSize();
                nativeHeapFree = Debug.getNativeHeapFreeSize();
            } catch (e) {
                console.log("[-] 无法获取Native堆信息: " + e);
            }
            
            // 记录内存信息
            var timestamp = new Date().getTime();
            var memInfo = {
                timestamp: timestamp,
                java: {
                    max: maxMemory,
                    total: totalMemory,
                    free: freeMemory,
                    used: usedMemory
                },
                native: {
                    size: nativeHeapSize,
                    allocated: nativeHeapAllocated,
                    free: nativeHeapFree
                },
                system: memoryInfo ? {
                    availMem: memoryInfo.availMem.value,
                    totalMem: memoryInfo.totalMem ? memoryInfo.totalMem.value : 0,
                    threshold: memoryInfo.threshold.value,
                    lowMemory: memoryInfo.lowMemory.value
                } : null
            };
            
            memoryData.memoryHistory.push(memInfo);
            
            // 只保留最近20条记录
            if (memoryData.memoryHistory.length > 20) {
                memoryData.memoryHistory.shift();
            }
            
            return memInfo;
        } catch (e) {
            console.log("[-] 收集内存信息失败: " + e);
            return null;
        }
    }

    /**
     * 工具函数：打印内存使用信息
     */
    function printMemoryInfo() {
        var memInfo = collectMemoryInfo();
        if (!memInfo) return;
        
        console.log("\n[*] 内存使用情况:");
        
        // Java堆
        console.log("    Java堆:");
        console.log("        最大内存: " + formatBytes(memInfo.java.max));
        console.log("        已分配: " + formatBytes(memInfo.java.total) + " (" + (memInfo.java.total * 100 / memInfo.java.max).toFixed(2) + "%)");
        console.log("        已使用: " + formatBytes(memInfo.java.used) + " (" + (memInfo.java.used * 100 / memInfo.java.total).toFixed(2) + "%)");
        console.log("        空闲: " + formatBytes(memInfo.java.free));
        
        // Native堆
        if (memInfo.native.size > 0) {
            console.log("    Native堆:");
            console.log("        大小: " + formatBytes(memInfo.native.size));
            console.log("        已分配: " + formatBytes(memInfo.native.allocated) + " (" + (memInfo.native.allocated * 100 / memInfo.native.size).toFixed(2) + "%)");
            console.log("        空闲: " + formatBytes(memInfo.native.free));
        }
        
        // 系统内存
        if (memInfo.system) {
            console.log("    系统内存:");
            console.log("        可用: " + formatBytes(memInfo.system.availMem));
            if (memInfo.system.totalMem > 0) {
                console.log("        总内存: " + formatBytes(memInfo.system.totalMem));
                console.log("        使用率: " + ((1 - memInfo.system.availMem / memInfo.system.totalMem) * 100).toFixed(2) + "%");
            }
            console.log("        低内存阈值: " + formatBytes(memInfo.system.threshold));
            console.log("        低内存状态: " + (memInfo.system.lowMemory ? "是" : "否"));
        }
        
        // Bitmap统计
        console.log("    Bitmap统计:");
        console.log("        数量: " + memoryData.bitmapStats.count);
        console.log("        总大小: " + formatBytes(memoryData.bitmapStats.totalSize));
        if (memoryData.bitmapStats.count > 0) {
            console.log("        平均大小: " + formatBytes(memoryData.bitmapStats.totalSize / memoryData.bitmapStats.count));
            console.log("        最大Bitmap: " + formatBytes(memoryData.bitmapStats.largest.size));
            if (config.printStack) {
                console.log("        最大Bitmap创建堆栈:\n        " + memoryData.bitmapStats.largest.stack);
            }
        }
        
        // 大对象分配统计
        if (memoryData.largeAllocations.length > 0) {
            console.log("    大对象分配 (最近5个):");
            var recentAllocations = memoryData.largeAllocations.slice(-5);
            for (var i = 0; i < recentAllocations.length; i++) {
                var alloc = recentAllocations[i];
                console.log("        " + alloc.className + ": " + formatBytes(alloc.size));
                if (config.printStack) {
                    console.log("            " + alloc.stack.replace(/\n/g, "\n            "));
                }
            }
        }
        
        // 内存趋势
        if (memoryData.memoryHistory.length > 1) {
            var first = memoryData.memoryHistory[0];
            var last = memoryData.memoryHistory[memoryData.memoryHistory.length - 1];
            var javaMemDiff = last.java.used - first.java.used;
            var timeDiff = (last.timestamp - first.timestamp) / 1000; // 秒
            
            console.log("    内存趋势 (过去 " + timeDiff.toFixed(0) + " 秒):");
            console.log("        Java堆变化: " + (javaMemDiff >= 0 ? "+" : "") + formatBytes(javaMemDiff));
            console.log("        平均增长率: " + formatBytes(javaMemDiff / timeDiff) + "/秒");
            
            if (javaMemDiff > 1024 * 1024 * 5 && timeDiff > 30) { // 如果5分钟内增长超过5MB
                console.log("        [!] 检测到可能的内存泄漏");
            }
        }
    }

    /**
     * 一、监控大对象分配
     */
    if (config.monitorLargeAllocations) {
        try {
            // 监控ByteBuffer分配
            var ByteBuffer = Java.use("java.nio.ByteBuffer");
            
            ByteBuffer.allocate.implementation = function(capacity) {
                var result = this.allocate(capacity);
                
                if (capacity >= config.largeObjectThreshold) {
                    console.log("[!] 大型ByteBuffer分配: " + formatBytes(capacity));
                    
                    if (config.printStack) {
                        var stack = getStackTrace();
                        console.log("    调用堆栈:\n    " + stack);
                        
                        // 记录大对象分配
                        memoryData.largeAllocations.push({
                            className: "ByteBuffer",
                            size: capacity,
                            stack: stack,
                            timestamp: new Date().getTime()
                        });
                        
                        // 只保留最近50条记录
                        if (memoryData.largeAllocations.length > 50) {
                            memoryData.largeAllocations.shift();
                        }
                    }
                }
                
                return result;
            };
            
            ByteBuffer.allocateDirect.implementation = function(capacity) {
                var result = this.allocateDirect(capacity);
                
                if (capacity >= config.largeObjectThreshold) {
                    console.log("[!] 大型直接ByteBuffer分配: " + formatBytes(capacity));
                    
                    if (config.printStack) {
                        var stack = getStackTrace();
                        console.log("    调用堆栈:\n    " + stack);
                        
                        // 记录大对象分配
                        memoryData.largeAllocations.push({
                            className: "ByteBuffer (Direct)",
                            size: capacity,
                            stack: stack,
                            timestamp: new Date().getTime()
                        });
                    }
                }
                
                return result;
            };
            
            // 监控byte[]分配
            var ArrayTracker = Java.use("java.lang.reflect.Array");
            var originalNewInstance = ArrayTracker.newInstance;
            
            if (originalNewInstance) {
                ArrayTracker.newInstance.overload('java.lang.Class', 'int').implementation = function(clazz, length) {
                    var result = originalNewInstance.call(this, clazz, length);
                    
                    // 检查是否为byte[]且大小超过阈值
                    if (clazz.getName() === "byte" && length >= config.largeObjectThreshold) {
                        console.log("[!] 大型byte[]分配: " + formatBytes(length));
                        
                        if (config.printStack) {
                            var stack = getStackTrace();
                            console.log("    调用堆栈:\n    " + stack);
                            
                            // 记录大对象分配
                            memoryData.largeAllocations.push({
                                className: "byte[]",
                                size: length,
                                stack: stack,
                                timestamp: new Date().getTime()
                            });
                        }
                    }
                    
                    return result;
                };
            }
            
            console.log("[+] 大对象分配监控设置完成");
        } catch (e) {
            console.log("[-] 大对象分配监控设置失败: " + e);
        }
    }

    /**
     * 二、监控Bitmap创建
     */
    if (config.monitorBitmaps) {
        try {
            var Bitmap = Java.use("android.graphics.Bitmap");
            
            // 监控createBitmap方法
            Bitmap.createBitmap.overload('int', 'int', 'android.graphics.Bitmap$Config').implementation = function(width, height, config) {
                var result = this.createBitmap(width, height, config);
                
                // 计算大致的内存占用
                var bytesPerPixel = 4; // 默认为ARGB_8888
                if (config) {
                    var configName = config.toString();
                    if (configName.indexOf("RGB_565") !== -1) bytesPerPixel = 2;
                    else if (configName.indexOf("ALPHA_8") !== -1) bytesPerPixel = 1;
                }
                
                var size = width * height * bytesPerPixel;
                memoryData.bitmapStats.count++;
                memoryData.bitmapStats.totalSize += size;
                
                if (size >= config.largeObjectThreshold) {
                    console.log("[!] 大型Bitmap创建: " + width + "x" + height + " (" + formatBytes(size) + ")");
                    
                    if (config.printStack) {
                        var stack = getStackTrace();
                        console.log("    调用堆栈:\n    " + stack);
                        
                        // 记录大对象分配
                        memoryData.largeAllocations.push({
                            className: "Bitmap",
                            size: size,
                            dimensions: width + "x" + height,
                            stack: stack,
                            timestamp: new Date().getTime()
                        });
                    }
                    
                    // 更新最大Bitmap记录
                    if (size > memoryData.bitmapStats.largest.size) {
                        memoryData.bitmapStats.largest.size = size;
                        memoryData.bitmapStats.largest.stack = getStackTrace();
                    }
                }
                
                return result;
            };
            
            // 监控recycle方法
            Bitmap.recycle.implementation = function() {
                if (config.verbose) {
                    console.log("[+] Bitmap.recycle调用");
                    
                    if (config.printStack) {
                        console.log("    调用堆栈:\n    " + getStackTrace());
                    }
                }
                
                // 由于无法获取具体的Bitmap大小，我们只能减少计数
                if (memoryData.bitmapStats.count > 0) {
                    memoryData.bitmapStats.count--;
                }
                
                return this.recycle();
            };
            
            console.log("[+] Bitmap监控设置完成");
        } catch (e) {
            console.log("[-] Bitmap监控设置失败: " + e);
        }
    }

    /**
     * 三、监控内存泄漏
     */
    if (config.monitorLeaks) {
        try {
            // 监控常见的可能导致泄漏的类
            var Context = Java.use("android.content.Context");
            var Activity = Java.use("android.app.Activity");
            
            // 监控registerReceiver
            Context.registerReceiver.overload('android.content.BroadcastReceiver', 'android.content.IntentFilter').implementation = function(receiver, filter) {
                var result = this.registerReceiver(receiver, filter);
                
                console.log("[+] 注册广播接收器: " + receiver.$className);
                console.log("    过滤器: " + filter.toString());
                
                if (config.printStack) {
                    console.log("    调用堆栈:\n    " + getStackTrace());
                }
                
                // 检查是否在Activity中注册但没有在onDestroy中注销
                var stack = getStackTrace();
                if (stack.indexOf("onCreate") !== -1 && stack.indexOf("unregisterReceiver") === -1) {
                    console.log("    [!] 警告: 在Activity.onCreate中注册广播接收器，但可能没有在onDestroy中注销，可能导致内存泄漏");
                }
                
                return result;
            };
            
            // 监控Activity.finish
            Activity.finish.implementation = function() {
                var activityName = this.getClass().getName();
                console.log("[+] Activity.finish: " + activityName);
                
                // 检查是否有未注销的广播接收器
                try {
                    var fields = this.getClass().getDeclaredFields();
                    for (var i = 0; i < fields.length; i++) {
                        var field = fields[i];
                        field.setAccessible(true);
                        var value = field.get(this);
                        
                        if (value !== null && value.$className && value.$className.indexOf("BroadcastReceiver") !== -1) {
                            console.log("    [!] 警告: Activity可能包含未注销的广播接收器: " + field.getName() + " (" + value.$className + ")");
                        }
                    }
                } catch (e) {
                    // 忽略反射错误
                }
                
                return this.finish();
            };
            
            console.log("[+] 内存泄漏监控设置完成");
        } catch (e) {
            console.log("[-] 内存泄漏监控设置失败: " + e);
        }
    }

    /**
     * 四、周期性收集内存信息
     */
    if (config.periodicCollection) {
        // 立即收集一次内存信息
        printMemoryInfo();
        
        // 设置定期收集
        setInterval(function() {
            printMemoryInfo();
        }, config.collectionInterval);
        
        console.log("[+] 周期性内存收集已设置，间隔: " + (config.collectionInterval / 1000) + "秒");
    }

    /**
     * 修改配置的函数
     */
    global.setMemoryConfig = function(newConfig) {
        for (var key in newConfig) {
            if (config.hasOwnProperty(key)) {
                config[key] = newConfig[key];
                console.log("[+] 内存监控配置已更新: " + key + " = " + newConfig[key]);
            }
        }
    };

    /**
     * 导出工具函数
     */
    global.dumpMemoryInfo = function() {
        printMemoryInfo();
    };

    global.getLargeAllocations = function() {
        console.log("[*] 大对象分配记录 (共" + memoryData.largeAllocations.length + "条):");
        for (var i = 0; i < memoryData.largeAllocations.length; i++) {
            var alloc = memoryData.largeAllocations[i];
            console.log("    " + (i+1) + ". " + alloc.className + ": " + formatBytes(alloc.size));
            if (alloc.dimensions) console.log("       尺寸: " + alloc.dimensions);
            console.log("       时间: " + new Date(alloc.timestamp).toLocaleString());
            if (config.printStack) {
                console.log("       堆栈:\n       " + alloc.stack.replace(/\n/g, "\n       "));
            }
        }
    };

    global.forceGC = function() {
        console.log("[*] 强制执行垃圾回收...");
        Java.perform(function() {
            var System = Java.use("java.lang.System");
            System.gc();
            System.runFinalization();
        });
        setTimeout(function() {
            printMemoryInfo();
        }, 1000);
    };

    console.log("[*] 内存使用监控脚本已加载");
    console.log("[*] 使用方法:");
    console.log("    setMemoryConfig({key: value}) - 修改配置");
    console.log("    dumpMemoryInfo() - 打印当前内存使用情况");
    console.log("    getLargeAllocations() - 查看大对象分配记录");
    console.log("    forceGC() - 强制执行垃圾回收");
}); 