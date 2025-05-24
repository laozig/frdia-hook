/**
 * 应用启动流程监控脚本
 * 
 * 功能：监控Android应用的启动流程和关键生命周期方法
 * 作用：分析应用启动过程、初始化流程和性能瓶颈
 * 适用：应用启动分析、性能优化、启动流程逆向
 */

// 等待Java虚拟机加载完成
Java.perform(function() {
    console.log("[*] 应用启动流程监控脚本已启动");

    // 全局配置
    var config = {
        // 是否显示详细日志
        verbose: true,
        // 是否打印调用堆栈
        printStack: true,
        // 是否监控Application生命周期
        monitorApplication: true, 
        // 是否监控Activity生命周期
        monitorActivity: true,
        // 是否监控ContentProvider
        monitorContentProvider: true,
        // 是否监控Service
        monitorService: true,
        // 是否监控BroadcastReceiver
        monitorBroadcastReceiver: true,
        // 是否记录时间戳
        recordTimestamp: true,
        // 是否监控启动时间
        monitorStartupTime: true
    };

    // 记录启动时间
    var startupTimes = {};
    var startTime = new Date().getTime();

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
     * 工具函数：格式化时间戳
     */
    function formatTimestamp() {
        if (!config.recordTimestamp) return "";
        
        var now = new Date();
        var elapsed = now.getTime() - startTime;
        
        return "[" + elapsed + "ms] ";
    }

    /**
     * 工具函数：记录启动时间点
     */
    function recordStartupTime(name) {
        if (!config.monitorStartupTime) return;
        
        var now = new Date().getTime();
        var elapsed = now - startTime;
        startupTimes[name] = elapsed;
    }

    /**
     * 工具函数：打印启动时间统计
     */
    function printStartupTimes() {
        if (!config.monitorStartupTime) return;
        
        console.log("\n[*] 应用启动时间统计:");
        
        // 按时间排序
        var sortedTimes = [];
        for (var name in startupTimes) {
            sortedTimes.push({name: name, time: startupTimes[name]});
        }
        
        sortedTimes.sort(function(a, b) {
            return a.time - b.time;
        });
        
        for (var i = 0; i < sortedTimes.length; i++) {
            var item = sortedTimes[i];
            console.log("    " + item.time + "ms - " + item.name);
        }
    }

    /**
     * 一、监控Application生命周期
     */
    if (config.monitorApplication) {
        try {
            var Application = Java.use("android.app.Application");
            
            // 监控Application.onCreate
            Application.onCreate.implementation = function() {
                var appName = this.getClass().getName();
                console.log(formatTimestamp() + "[+] Application.onCreate: " + appName);
                recordStartupTime("Application.onCreate: " + appName);
                
                if (config.printStack) {
                    console.log("    调用堆栈:\n    " + getStackTrace());
                }
                
                // 调用原始方法
                var result = this.onCreate();
                
                console.log(formatTimestamp() + "[+] Application.onCreate 完成: " + appName);
                recordStartupTime("Application.onCreate完成: " + appName);
                
                return result;
            };
            
            // 监控Application.attachBaseContext
            Application.attachBaseContext.implementation = function(context) {
                var appName = this.getClass().getName();
                console.log(formatTimestamp() + "[+] Application.attachBaseContext: " + appName);
                recordStartupTime("Application.attachBaseContext: " + appName);
                
                if (config.printStack) {
                    console.log("    调用堆栈:\n    " + getStackTrace());
                }
                
                // 调用原始方法
                var result = this.attachBaseContext(context);
                
                console.log(formatTimestamp() + "[+] Application.attachBaseContext 完成: " + appName);
                recordStartupTime("Application.attachBaseContext完成: " + appName);
                
                return result;
            };
            
            console.log("[+] Application生命周期监控设置完成");
        } catch (e) {
            console.log("[-] Application生命周期监控设置失败: " + e);
        }
    }

    /**
     * 二、监控Activity生命周期
     */
    if (config.monitorActivity) {
        try {
            var Activity = Java.use("android.app.Activity");
            
            // 监控Activity.onCreate
            Activity.onCreate.overload("android.os.Bundle").implementation = function(bundle) {
                var activityName = this.getClass().getName();
                console.log(formatTimestamp() + "[+] Activity.onCreate: " + activityName);
                recordStartupTime("Activity.onCreate: " + activityName);
                
                if (config.verbose) {
                    console.log("    Bundle: " + (bundle ? "非空" : "空"));
                    
                    if (config.printStack) {
                        console.log("    调用堆栈:\n    " + getStackTrace());
                    }
                }
                
                // 调用原始方法
                var result = this.onCreate(bundle);
                
                console.log(formatTimestamp() + "[+] Activity.onCreate 完成: " + activityName);
                recordStartupTime("Activity.onCreate完成: " + activityName);
                
                return result;
            };
            
            // 监控Activity.onStart
            Activity.onStart.implementation = function() {
                var activityName = this.getClass().getName();
                console.log(formatTimestamp() + "[+] Activity.onStart: " + activityName);
                recordStartupTime("Activity.onStart: " + activityName);
                
                if (config.printStack && config.verbose) {
                    console.log("    调用堆栈:\n    " + getStackTrace());
                }
                
                // 调用原始方法
                var result = this.onStart();
                
                console.log(formatTimestamp() + "[+] Activity.onStart 完成: " + activityName);
                recordStartupTime("Activity.onStart完成: " + activityName);
                
                return result;
            };
            
            // 监控Activity.onResume
            Activity.onResume.implementation = function() {
                var activityName = this.getClass().getName();
                console.log(formatTimestamp() + "[+] Activity.onResume: " + activityName);
                recordStartupTime("Activity.onResume: " + activityName);
                
                if (config.printStack && config.verbose) {
                    console.log("    调用堆栈:\n    " + getStackTrace());
                }
                
                // 调用原始方法
                var result = this.onResume();
                
                console.log(formatTimestamp() + "[+] Activity.onResume 完成: " + activityName);
                recordStartupTime("Activity.onResume完成: " + activityName);
                
                // 打印启动时间统计
                if (activityName.indexOf("MainActivity") !== -1 || 
                    activityName.indexOf("SplashActivity") !== -1 || 
                    activityName.indexOf("LauncherActivity") !== -1) {
                    setTimeout(printStartupTimes, 1000);
                }
                
                return result;
            };
            
            // 监控Activity.onWindowFocusChanged
            Activity.onWindowFocusChanged.implementation = function(hasFocus) {
                var activityName = this.getClass().getName();
                
                if (hasFocus) {
                    console.log(formatTimestamp() + "[+] Activity.onWindowFocusChanged(true): " + activityName);
                    recordStartupTime("Activity.onWindowFocusChanged: " + activityName);
                    
                    if (config.printStack && config.verbose) {
                        console.log("    调用堆栈:\n    " + getStackTrace());
                    }
                }
                
                // 调用原始方法
                var result = this.onWindowFocusChanged(hasFocus);
                
                if (hasFocus) {
                    console.log(formatTimestamp() + "[+] Activity.onWindowFocusChanged(true) 完成: " + activityName);
                    recordStartupTime("Activity.onWindowFocusChanged完成: " + activityName);
                }
                
                return result;
            };
            
            console.log("[+] Activity生命周期监控设置完成");
        } catch (e) {
            console.log("[-] Activity生命周期监控设置失败: " + e);
        }
    }

    /**
     * 三、监控ContentProvider
     */
    if (config.monitorContentProvider) {
        try {
            var ContentProvider = Java.use("android.content.ContentProvider");
            
            // 监控ContentProvider.onCreate
            ContentProvider.onCreate.implementation = function() {
                var providerName = this.getClass().getName();
                console.log(formatTimestamp() + "[+] ContentProvider.onCreate: " + providerName);
                recordStartupTime("ContentProvider.onCreate: " + providerName);
                
                if (config.printStack) {
                    console.log("    调用堆栈:\n    " + getStackTrace());
                }
                
                // 调用原始方法
                var result = this.onCreate();
                
                console.log(formatTimestamp() + "[+] ContentProvider.onCreate 完成: " + providerName);
                recordStartupTime("ContentProvider.onCreate完成: " + providerName);
                
                return result;
            };
            
            // 监控ContentProvider.attachInfo
            ContentProvider.attachInfo.implementation = function(context, info) {
                var providerName = this.getClass().getName();
                console.log(formatTimestamp() + "[+] ContentProvider.attachInfo: " + providerName);
                recordStartupTime("ContentProvider.attachInfo: " + providerName);
                
                if (config.printStack && config.verbose) {
                    console.log("    调用堆栈:\n    " + getStackTrace());
                }
                
                // 调用原始方法
                var result = this.attachInfo(context, info);
                
                console.log(formatTimestamp() + "[+] ContentProvider.attachInfo 完成: " + providerName);
                recordStartupTime("ContentProvider.attachInfo完成: " + providerName);
                
                return result;
            };
            
            console.log("[+] ContentProvider监控设置完成");
        } catch (e) {
            console.log("[-] ContentProvider监控设置失败: " + e);
        }
    }

    /**
     * 四、监控Service
     */
    if (config.monitorService) {
        try {
            var Service = Java.use("android.app.Service");
            
            // 监控Service.onCreate
            Service.onCreate.implementation = function() {
                var serviceName = this.getClass().getName();
                console.log(formatTimestamp() + "[+] Service.onCreate: " + serviceName);
                recordStartupTime("Service.onCreate: " + serviceName);
                
                if (config.printStack) {
                    console.log("    调用堆栈:\n    " + getStackTrace());
                }
                
                // 调用原始方法
                var result = this.onCreate();
                
                console.log(formatTimestamp() + "[+] Service.onCreate 完成: " + serviceName);
                recordStartupTime("Service.onCreate完成: " + serviceName);
                
                return result;
            };
            
            // 监控Service.onStartCommand
            Service.onStartCommand.implementation = function(intent, flags, startId) {
                var serviceName = this.getClass().getName();
                console.log(formatTimestamp() + "[+] Service.onStartCommand: " + serviceName);
                recordStartupTime("Service.onStartCommand: " + serviceName);
                
                if (config.verbose) {
                    console.log("    Intent: " + (intent ? intent.toString() : "null"));
                    console.log("    Flags: " + flags);
                    console.log("    StartId: " + startId);
                    
                    if (config.printStack) {
                        console.log("    调用堆栈:\n    " + getStackTrace());
                    }
                }
                
                // 调用原始方法
                var result = this.onStartCommand(intent, flags, startId);
                
                console.log(formatTimestamp() + "[+] Service.onStartCommand 完成: " + serviceName);
                recordStartupTime("Service.onStartCommand完成: " + serviceName);
                
                return result;
            };
            
            // 监控Service.onBind
            Service.onBind.implementation = function(intent) {
                var serviceName = this.getClass().getName();
                console.log(formatTimestamp() + "[+] Service.onBind: " + serviceName);
                recordStartupTime("Service.onBind: " + serviceName);
                
                if (config.verbose) {
                    console.log("    Intent: " + (intent ? intent.toString() : "null"));
                    
                    if (config.printStack) {
                        console.log("    调用堆栈:\n    " + getStackTrace());
                    }
                }
                
                // 调用原始方法
                var result = this.onBind(intent);
                
                console.log(formatTimestamp() + "[+] Service.onBind 完成: " + serviceName);
                recordStartupTime("Service.onBind完成: " + serviceName);
                
                return result;
            };
            
            console.log("[+] Service监控设置完成");
        } catch (e) {
            console.log("[-] Service监控设置失败: " + e);
        }
    }

    /**
     * 五、监控BroadcastReceiver
     */
    if (config.monitorBroadcastReceiver) {
        try {
            var BroadcastReceiver = Java.use("android.content.BroadcastReceiver");
            
            // 监控BroadcastReceiver.onReceive
            BroadcastReceiver.onReceive.implementation = function(context, intent) {
                var receiverName = this.getClass().getName();
                console.log(formatTimestamp() + "[+] BroadcastReceiver.onReceive: " + receiverName);
                recordStartupTime("BroadcastReceiver.onReceive: " + receiverName);
                
                if (config.verbose) {
                    console.log("    Intent: " + (intent ? intent.toString() : "null"));
                    if (intent) {
                        console.log("    Action: " + intent.getAction());
                    }
                    
                    if (config.printStack) {
                        console.log("    调用堆栈:\n    " + getStackTrace());
                    }
                }
                
                // 调用原始方法
                var result = this.onReceive(context, intent);
                
                console.log(formatTimestamp() + "[+] BroadcastReceiver.onReceive 完成: " + receiverName);
                recordStartupTime("BroadcastReceiver.onReceive完成: " + receiverName);
                
                return result;
            };
            
            console.log("[+] BroadcastReceiver监控设置完成");
        } catch (e) {
            console.log("[-] BroadcastReceiver监控设置失败: " + e);
        }
    }

    /**
     * 六、监控关键初始化方法
     */
    try {
        // 监控线程创建
        var Thread = Java.use("java.lang.Thread");
        Thread.start.implementation = function() {
            var threadName = this.getName();
            var threadClass = this.getClass().getName();
            
            if (threadName && (threadName.indexOf("main") !== -1 || 
                              threadName.indexOf("UI") !== -1 || 
                              threadName.indexOf("Binder") !== -1 || 
                              threadName.indexOf("Async") !== -1)) {
                console.log(formatTimestamp() + "[+] 线程启动: " + threadName + " (" + threadClass + ")");
                recordStartupTime("线程启动: " + threadName);
                
                if (config.printStack && config.verbose) {
                    console.log("    调用堆栈:\n    " + getStackTrace());
                }
            }
            
            return this.start();
        };
        
        // 监控AsyncTask执行
        try {
            var AsyncTask = Java.use("android.os.AsyncTask");
            AsyncTask.execute.overload("java.lang.Runnable").implementation = function(runnable) {
                console.log(formatTimestamp() + "[+] AsyncTask.execute");
                recordStartupTime("AsyncTask.execute");
                
                if (config.printStack && config.verbose) {
                    console.log("    调用堆栈:\n    " + getStackTrace());
                }
                
                return AsyncTask.execute(runnable);
            };
        } catch (e) {
            // 忽略错误
        }
        
        // 监控Handler.post
        var Handler = Java.use("android.os.Handler");
        Handler.post.implementation = function(runnable) {
            console.log(formatTimestamp() + "[+] Handler.post");
            
            if (config.printStack && config.verbose) {
                console.log("    调用堆栈:\n    " + getStackTrace());
            }
            
            return this.post(runnable);
        };
        
        console.log("[+] 关键初始化方法监控设置完成");
    } catch (e) {
        console.log("[-] 关键初始化方法监控设置失败: " + e);
    }

    /**
     * 七、监控资源加载
     */
    try {
        // 监控资源加载
        var Resources = Java.use("android.content.res.Resources");
        Resources.getDrawable.overload("int").implementation = function(id) {
            var resourceName = this.getResourceName(id);
            console.log(formatTimestamp() + "[+] 加载资源: " + resourceName);
            
            return this.getDrawable(id);
        };
        
        // 监控图片加载
        try {
            var ImageView = Java.use("android.widget.ImageView");
            ImageView.setImageResource.implementation = function(id) {
                try {
                    var resourceName = this.getContext().getResources().getResourceName(id);
                    console.log(formatTimestamp() + "[+] ImageView设置图片资源: " + resourceName);
                } catch (e) {
                    console.log(formatTimestamp() + "[+] ImageView设置图片资源ID: " + id);
                }
                
                return this.setImageResource(id);
            };
        } catch (e) {
            // 忽略错误
        }
        
        console.log("[+] 资源加载监控设置完成");
    } catch (e) {
        console.log("[-] 资源加载监控设置失败: " + e);
    }

    /**
     * 八、监控网络初始化
     */
    try {
        // 监控OkHttpClient创建
        try {
            var OkHttpClient = Java.use("okhttp3.OkHttpClient");
            OkHttpClient.$init.implementation = function() {
                console.log(formatTimestamp() + "[+] 创建OkHttpClient");
                recordStartupTime("创建OkHttpClient");
                
                if (config.printStack) {
                    console.log("    调用堆栈:\n    " + getStackTrace());
                }
                
                return this.$init();
            };
        } catch (e) {
            // 忽略错误
        }
        
        // 监控Retrofit创建
        try {
            var Retrofit = Java.use("retrofit2.Retrofit");
            Retrofit.$init.implementation = function() {
                console.log(formatTimestamp() + "[+] 创建Retrofit");
                recordStartupTime("创建Retrofit");
                
                if (config.printStack) {
                    console.log("    调用堆栈:\n    " + getStackTrace());
                }
                
                return this.$init();
            };
        } catch (e) {
            // 忽略错误
        }
        
        console.log("[+] 网络初始化监控设置完成");
    } catch (e) {
        console.log("[-] 网络初始化监控设置失败: " + e);
    }

    /**
     * 九、监控数据库初始化
     */
    try {
        // 监控SQLiteOpenHelper
        var SQLiteOpenHelper = Java.use("android.database.sqlite.SQLiteOpenHelper");
        SQLiteOpenHelper.getWritableDatabase.implementation = function() {
            var dbName = this.getDatabaseName();
            console.log(formatTimestamp() + "[+] 打开数据库: " + dbName);
            recordStartupTime("打开数据库: " + dbName);
            
            if (config.printStack) {
                console.log("    调用堆栈:\n    " + getStackTrace());
            }
            
            var result = this.getWritableDatabase();
            
            console.log(formatTimestamp() + "[+] 打开数据库完成: " + dbName);
            recordStartupTime("打开数据库完成: " + dbName);
            
            return result;
        };
        
        // 监控Room数据库
        try {
            var RoomDatabase = Java.use("androidx.room.RoomDatabase");
            RoomDatabase.init.implementation = function(config, name) {
                console.log(formatTimestamp() + "[+] 初始化Room数据库: " + name);
                recordStartupTime("初始化Room数据库: " + name);
                
                if (config.printStack) {
                    console.log("    调用堆栈:\n    " + getStackTrace());
                }
                
                var result = this.init(config, name);
                
                console.log(formatTimestamp() + "[+] 初始化Room数据库完成: " + name);
                recordStartupTime("初始化Room数据库完成: " + name);
                
                return result;
            };
        } catch (e) {
            // 忽略错误
        }
        
        console.log("[+] 数据库初始化监控设置完成");
    } catch (e) {
        console.log("[-] 数据库初始化监控设置失败: " + e);
    }

    /**
     * 修改配置的函数
     */
    global.setStartupConfig = function(newConfig) {
        for (var key in newConfig) {
            if (config.hasOwnProperty(key)) {
                config[key] = newConfig[key];
                console.log("[+] 启动监控配置已更新: " + key + " = " + newConfig[key]);
            }
        }
    };

    console.log("[*] 应用启动流程监控脚本已加载");
    console.log("[*] 使用方法:");
    console.log("    setStartupConfig({key: value}) - 修改配置");
    console.log("    例如: setStartupConfig({verbose: false}) - 关闭详细日志");
}); 