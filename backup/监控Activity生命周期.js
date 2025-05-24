/*
 * 脚本名称：监控Activity生命周期.js
 * 功能：全面监控Android应用的Activity生命周期，追踪页面流程和交互过程
 * 适用场景：
 *   - 分析应用导航逻辑和页面流程
 *   - 检测后台Activity行为
 *   - 定位UI相关问题
 *   - 分析特定页面的启动条件和使用频率
 * 使用方法：
 *   1. frida -U -f 包名 -l 监控Activity生命周期.js --no-pause
 *   2. 查看控制台输出，了解应用页面流转和生命周期事件
 * 启动方式说明：
 *   - -U 代表使用USB连接的设备
 *   - -f 代表以spawn方式启动目标应用
 *   - --no-pause 指示Frida不要暂停应用执行
 * 支持特性：
 *   - 监控所有Activity生命周期方法
 *   - 追踪Activity创建顺序和堆栈
 *   - 分析页面停留时间
 *   - 检测页面异常销毁
 *   - Intent参数分析
 *   - 统计页面访问频率
 *   - 绘制页面流转图
 */

(function() {
    // 全局配置
    var config = {
        logLevel: 2,                 // 0:关闭 1:错误 2:基本信息 3:详细
        printStack: true,            // 是否打印调用堆栈
        maxStackDepth: 3,            // 最大堆栈深度
        monitorIntents: true,        // 是否监控Intent内容
        filterSystemDialogs: false,  // 是否过滤系统对话框
        timeFormat: "HH:mm:ss.SSS",  // 时间戳格式
        monitorFragments: true,      // 是否监控Fragment生命周期
        showPageTransitionFlow: true // 是否显示页面流转图
    };
    
    // 统计信息
    var stats = {
        activityCounts: {},          // 每个Activity被访问的次数
        currentActivity: null,       // 当前活动的Activity
        activityStack: [],           // 活动的Activity栈
        startTime: {},               // 记录每个Activity的启动时间
        transitions: {},             // 记录页面间的跳转关系
        fragmentsInActivity: {}      // 记录每个Activity中的Fragment
    };
    
    // 记录当前时间戳
    function getCurrentTime() {
        return new Date().toTimeString().split(' ')[0] + "." + 
               new Date().getMilliseconds().toString().padStart(3, '0');
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
                
                // 过滤掉Android系统类
                if (className.indexOf("android.app.Activity") === 0 && i > 0) continue;
                
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
    
    // 辅助函数：获取Activity简短名称
    function getSimpleActivityName(activity) {
        var fullName = activity.getClass().getName();
        var lastDot = fullName.lastIndexOf(".");
        if (lastDot !== -1) {
            return fullName.substring(lastDot + 1);
        }
        return fullName;
    }
    
    // 辅助函数：更新Activity统计信息
    function updateActivityStats(activity, eventType) {
        var activityName = activity.getClass().getName();
        var simpleName = getSimpleActivityName(activity);
        
        // 更新访问次数
        if (!stats.activityCounts[activityName]) {
            stats.activityCounts[activityName] = 0;
        }
        
        if (eventType === "onCreate") {
            stats.activityCounts[activityName]++;
        }
        
        // 更新当前活动的Activity
        if (eventType === "onResume") {
            if (stats.currentActivity && stats.currentActivity !== activityName) {
                // 记录页面跳转关系
                var source = getSimpleActivityName(Java.cast(Java.use(stats.currentActivity).$new(), Java.use("android.app.Activity")));
                if (!stats.transitions[source]) {
                    stats.transitions[source] = {};
                }
                if (!stats.transitions[source][simpleName]) {
                    stats.transitions[source][simpleName] = 0;
                }
                stats.transitions[source][simpleName]++;
                
                if (config.showPageTransitionFlow) {
                    log(2, "页面跳转: " + source + " -> " + simpleName);
                }
            }
            stats.currentActivity = activityName;
            
            // 将当前Activity添加到栈顶
            var index = stats.activityStack.indexOf(activityName);
            if (index !== -1) {
                stats.activityStack.splice(index, 1);
            }
            stats.activityStack.push(activityName);
            
            // 记录启动时间
            stats.startTime[activityName] = new Date();
        }
        
        // 处理Activity销毁
        if (eventType === "onDestroy") {
            var index = stats.activityStack.indexOf(activityName);
            if (index !== -1) {
                stats.activityStack.splice(index, 1);
            }
            
            // 计算停留时间
            if (stats.startTime[activityName]) {
                var duration = (new Date() - stats.startTime[activityName]) / 1000;
                log(2, "    页面停留时间: " + duration.toFixed(1) + "秒");
                delete stats.startTime[activityName];
            }
        }
    }
    
    // 辅助函数：检查并显示Intent信息
    function checkIntent(activity) {
        if (!config.monitorIntents) return;
        
        try {
            var intent = activity.getIntent();
            if (!intent) return;
            
            var extras = intent.getExtras();
            var action = intent.getAction();
            var categories = intent.getCategories();
            var data = intent.getData();
            
            var intentInfo = "Intent信息:";
            var hasContent = false;
            
            if (action) {
                intentInfo += "\n        Action: " + action;
                hasContent = true;
            }
            
            if (data) {
                intentInfo += "\n        Data URI: " + data.toString();
                hasContent = true;
            }
            
            if (categories) {
                var iterator = categories.iterator();
                var categoriesList = [];
                while (iterator.hasNext()) {
                    categoriesList.push(iterator.next().toString());
                }
                if (categoriesList.length > 0) {
                    intentInfo += "\n        Categories: " + categoriesList.join(", ");
                    hasContent = true;
                }
            }
            
            if (extras) {
                var keysIterator = extras.keySet().iterator();
                var extrasInfo = [];
                while (keysIterator.hasNext()) {
                    var key = keysIterator.next().toString();
                    try {
                        var value = extras.get(key);
                        extrasInfo.push(key + ": " + (value !== null ? value.toString() : "null"));
                    } catch (e) {
                        extrasInfo.push(key + ": <无法访问值>");
                    }
                }
                if (extrasInfo.length > 0) {
                    intentInfo += "\n        Extras: " + extrasInfo.join(", ");
                    hasContent = true;
                }
            }
            
            if (hasContent) {
                log(2, "    " + intentInfo);
            }
        } catch (e) {
            log(1, "    获取Intent信息失败: " + e);
        }
    }

    Java.perform(function() {
        // 监控Activity生命周期
        var Activity = Java.use("android.app.Activity");
        
        // onCreate: Activity创建时调用
        Activity.onCreate.overload('android.os.Bundle').implementation = function(savedInstanceState) {
            var activityName = this.getClass().getName();
            var simpleName = getSimpleActivityName(this);
            
            log(2, getCurrentTime() + " Activity.onCreate: " + simpleName);
            updateActivityStats(this, "onCreate");
            checkIntent(this);
            
            if (config.printStack) {
                log(3, getStackTrace());
            }
            
            // 初始化Fragment列表
            if (config.monitorFragments) {
                stats.fragmentsInActivity[activityName] = [];
            }
            
            this.onCreate(savedInstanceState);
        };
        
        // onStart: Activity即将变为可见时调用
        Activity.onStart.implementation = function() {
            var simpleName = getSimpleActivityName(this);
            log(2, getCurrentTime() + " Activity.onStart: " + simpleName);
            updateActivityStats(this, "onStart");
            
            this.onStart();
        };
        
        // onResume: Activity获取焦点，位于前台时调用
        Activity.onResume.implementation = function() {
            var simpleName = getSimpleActivityName(this);
            log(2, getCurrentTime() + " Activity.onResume: " + simpleName);
            updateActivityStats(this, "onResume");
            
            this.onResume();
        };
        
        // onPause: Activity失去焦点，但仍可见时调用
        Activity.onPause.implementation = function() {
            var simpleName = getSimpleActivityName(this);
            log(2, getCurrentTime() + " Activity.onPause: " + simpleName);
            updateActivityStats(this, "onPause");
            
            this.onPause();
        };
        
        // onStop: Activity完全不可见时调用
        Activity.onStop.implementation = function() {
            var simpleName = getSimpleActivityName(this);
            log(2, getCurrentTime() + " Activity.onStop: " + simpleName);
            updateActivityStats(this, "onStop");
            
            this.onStop();
        };
        
        // onDestroy: Activity销毁时调用
        Activity.onDestroy.implementation = function() {
            var activityName = this.getClass().getName();
            var simpleName = getSimpleActivityName(this);
            
            log(2, getCurrentTime() + " Activity.onDestroy: " + simpleName);
            updateActivityStats(this, "onDestroy");
            
            // 清空Fragment列表
            if (config.monitorFragments) {
                delete stats.fragmentsInActivity[activityName];
            }
            
            this.onDestroy();
        };
        
        // 监控Activity结果返回
        Activity.onActivityResult.implementation = function(requestCode, resultCode, data) {
            var simpleName = getSimpleActivityName(this);
            
            log(2, getCurrentTime() + " Activity.onActivityResult: " + simpleName);
            log(2, "    请求码: " + requestCode + ", 结果码: " + resultCode);
            
            // 尝试解析返回的数据
            if (data) {
                try {
                    var extras = data.getExtras();
                    if (extras) {
                        var keysIterator = extras.keySet().iterator();
                        var extrasInfo = [];
                        while (keysIterator.hasNext()) {
                            var key = keysIterator.next().toString();
                            try {
                                var value = extras.get(key);
                                extrasInfo.push(key + ": " + (value !== null ? value.toString() : "null"));
                            } catch (e) {
                                extrasInfo.push(key + ": <无法访问值>");
                            }
                        }
                        if (extrasInfo.length > 0) {
                            log(2, "    返回数据: " + extrasInfo.join(", "));
                        }
                    }
                } catch (e) {
                    log(1, "    解析返回数据失败: " + e);
                }
            }
            
            this.onActivityResult(requestCode, resultCode, data);
        };
        
        // 可选：监控其他Activity回调方法
        Activity.onRestart.implementation = function() {
            var simpleName = getSimpleActivityName(this);
            log(3, getCurrentTime() + " Activity.onRestart: " + simpleName);
            
            this.onRestart();
        };
        
        Activity.onSaveInstanceState.overload('android.os.Bundle').implementation = function(outState) {
            var simpleName = getSimpleActivityName(this);
            log(3, getCurrentTime() + " Activity.onSaveInstanceState: " + simpleName);
            
            this.onSaveInstanceState(outState);
        };
        
        try {
            Activity.onBackPressed.implementation = function() {
                var simpleName = getSimpleActivityName(this);
                log(2, getCurrentTime() + " Activity.onBackPressed: " + simpleName);
                
                this.onBackPressed();
            };
        } catch (e) {
            // 可能在某些Android版本中不存在
        }
        
        // 监控Fragment生命周期（如果启用）
        if (config.monitorFragments) {
            try {
                var Fragment = Java.use("android.support.v4.app.Fragment") || 
                               Java.use("androidx.fragment.app.Fragment") || 
                               Java.use("android.app.Fragment");
                
                if (Fragment) {
                    // Fragment创建
                    Fragment.onAttach.overload('android.content.Context').implementation = function(context) {
                        try {
                            var fragmentName = this.getClass().getName();
                            var simpleName = fragmentName.substring(fragmentName.lastIndexOf(".") + 1);
                            
                            log(3, getCurrentTime() + " Fragment.onAttach: " + simpleName);
                            
                            // 将Fragment添加到Activity的列表中
                            try {
                                var activity = this.getActivity();
                                if (activity) {
                                    var activityName = activity.getClass().getName();
                                    if (!stats.fragmentsInActivity[activityName]) {
                                        stats.fragmentsInActivity[activityName] = [];
                                    }
                                    if (stats.fragmentsInActivity[activityName].indexOf(fragmentName) === -1) {
                                        stats.fragmentsInActivity[activityName].push(fragmentName);
                                    }
                                }
                            } catch (e) {
                                // 可能Fragment尚未关联到Activity
                            }
                        } catch (e) {
                            log(1, "监控Fragment.onAttach失败: " + e);
                        }
                        
                        return this.onAttach(context);
                    };
                    
                    // Fragment视图创建
                    Fragment.onCreateView.implementation = function() {
                        try {
                            var fragmentName = this.getClass().getName();
                            var simpleName = fragmentName.substring(fragmentName.lastIndexOf(".") + 1);
                            
                            log(3, getCurrentTime() + " Fragment.onCreateView: " + simpleName);
                        } catch (e) {
                            log(1, "监控Fragment.onCreateView失败: " + e);
                        }
                        
                        return this.onCreateView.apply(this, arguments);
                    };
                    
                    // Fragment销毁
                    Fragment.onDestroy.implementation = function() {
                        try {
                            var fragmentName = this.getClass().getName();
                            var simpleName = fragmentName.substring(fragmentName.lastIndexOf(".") + 1);
                            
                            log(3, getCurrentTime() + " Fragment.onDestroy: " + simpleName);
                            
                            // 从Activity的列表中移除Fragment
                            try {
                                var activity = this.getActivity();
                                if (activity) {
                                    var activityName = activity.getClass().getName();
                                    if (stats.fragmentsInActivity[activityName]) {
                                        var index = stats.fragmentsInActivity[activityName].indexOf(fragmentName);
                                        if (index !== -1) {
                                            stats.fragmentsInActivity[activityName].splice(index, 1);
                                        }
                                    }
                                }
                            } catch (e) {
                                // Fragment可能已从Activity分离
                            }
                        } catch (e) {
                            log(1, "监控Fragment.onDestroy失败: " + e);
                        }
                        
                        return this.onDestroy();
                    };
                }
            } catch (e) {
                log(1, "监控Fragment生命周期失败: " + e);
                config.monitorFragments = false;
            }
        }
        
        // 定期打印统计信息
        setInterval(function() {
            if (Object.keys(stats.activityCounts).length === 0) return;
            
            var activityStats = "Activity访问统计:";
            for (var activity in stats.activityCounts) {
                var simpleName = activity.substring(activity.lastIndexOf(".") + 1);
                activityStats += "\n    " + simpleName + ": " + stats.activityCounts[activity] + "次";
                
                // 添加关联的Fragment信息
                if (config.monitorFragments && stats.fragmentsInActivity[activity] && stats.fragmentsInActivity[activity].length > 0) {
                    var fragments = stats.fragmentsInActivity[activity].map(function(f) {
                        return f.substring(f.lastIndexOf(".") + 1);
                    });
                    activityStats += " (Fragments: " + fragments.join(", ") + ")";
                }
            }
            
            log(2, activityStats);
            
            // 显示当前Activity栈
            if (stats.activityStack.length > 0) {
                var stackInfo = "当前Activity栈 (从底到顶):";
                for (var i = 0; i < stats.activityStack.length; i++) {
                    var activityName = stats.activityStack[i];
                    var simpleName = activityName.substring(activityName.lastIndexOf(".") + 1);
                    stackInfo += "\n    " + (i + 1) + ". " + simpleName;
                }
                log(2, stackInfo);
            }
            
            // 显示页面流转统计
            if (config.showPageTransitionFlow && Object.keys(stats.transitions).length > 0) {
                var flowInfo = "页面流转统计:";
                for (var source in stats.transitions) {
                    for (var target in stats.transitions[source]) {
                        flowInfo += "\n    " + source + " -> " + target + ": " + stats.transitions[source][target] + "次";
                    }
                }
                log(2, flowInfo);
            }
        }, 30000); // 每30秒打印一次
        
        log(2, "Activity生命周期监控已启动" + (config.monitorFragments ? " (含Fragment监控)" : ""));
    });
})(); 