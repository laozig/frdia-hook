/**
 * UI渲染性能监控脚本
 * 
 * 功能：监控Android应用的UI渲染性能
 * 作用：分析UI卡顿原因、优化渲染性能、定位UI问题
 * 适用：UI性能分析、卡顿问题排查
 */

// 等待Java虚拟机加载完成
Java.perform(function() {
    console.log("[*] UI渲染性能监控脚本已启动");

    // 全局配置
    var config = {
        // 是否显示详细日志
        verbose: true,
        // 是否打印调用堆栈
        printStack: true,
        // 是否监控View的绘制过程
        monitorViewDraw: true,
        // 是否监控布局过程
        monitorLayout: true,
        // 是否监控测量过程
        monitorMeasure: true,
        // 是否监控动画
        monitorAnimation: true,
        // 是否监控Choreographer帧回调
        monitorChoreographer: true,
        // 是否记录时间戳
        recordTimestamp: true,
        // 性能警告阈值（毫秒）
        performanceThreshold: 16
    };

    // 记录性能数据
    var performanceData = {
        drawTimes: {},
        layoutTimes: {},
        measureTimes: {},
        frameTimes: [],
        jankCount: 0
    };

    // 记录开始时间
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
     * 工具函数：记录执行时间
     */
    function recordExecutionTime(category, name, time) {
        if (category === "draw") {
            performanceData.drawTimes[name] = performanceData.drawTimes[name] || [];
            performanceData.drawTimes[name].push(time);
        } else if (category === "layout") {
            performanceData.layoutTimes[name] = performanceData.layoutTimes[name] || [];
            performanceData.layoutTimes[name].push(time);
        } else if (category === "measure") {
            performanceData.measureTimes[name] = performanceData.measureTimes[name] || [];
            performanceData.measureTimes[name].push(time);
        } else if (category === "frame") {
            performanceData.frameTimes.push(time);
            
            // 检测卡顿
            if (time > config.performanceThreshold) {
                performanceData.jankCount++;
                console.log(formatTimestamp() + "[!] 检测到卡顿: " + time.toFixed(2) + "ms (阈值: " + config.performanceThreshold + "ms)");
            }
        }
    }

    /**
     * 工具函数：打印性能统计
     */
    function printPerformanceStats() {
        console.log("\n[*] UI渲染性能统计:");
        
        // 打印帧率统计
        var frameCount = performanceData.frameTimes.length;
        if (frameCount > 0) {
            var totalFrameTime = 0;
            var maxFrameTime = 0;
            
            for (var i = 0; i < frameCount; i++) {
                totalFrameTime += performanceData.frameTimes[i];
                maxFrameTime = Math.max(maxFrameTime, performanceData.frameTimes[i]);
            }
            
            var avgFrameTime = totalFrameTime / frameCount;
            var fps = 1000 / avgFrameTime;
            
            console.log("    帧率统计:");
            console.log("        平均帧时间: " + avgFrameTime.toFixed(2) + "ms");
            console.log("        估计FPS: " + fps.toFixed(2));
            console.log("        最大帧时间: " + maxFrameTime.toFixed(2) + "ms");
            console.log("        卡顿次数: " + performanceData.jankCount + " / " + frameCount + " 帧");
            console.log("        卡顿率: " + ((performanceData.jankCount / frameCount) * 100).toFixed(2) + "%");
        }
        
        // 打印绘制时间统计
        console.log("\n    绘制时间统计 (Top 5):");
        printTopPerformers(performanceData.drawTimes, 5);
        
        // 打印布局时间统计
        console.log("\n    布局时间统计 (Top 5):");
        printTopPerformers(performanceData.layoutTimes, 5);
        
        // 打印测量时间统计
        console.log("\n    测量时间统计 (Top 5):");
        printTopPerformers(performanceData.measureTimes, 5);
    }

    /**
     * 工具函数：打印性能最差的组件
     */
    function printTopPerformers(timeData, count) {
        // 计算每个组件的平均时间
        var averages = [];
        for (var name in timeData) {
            var times = timeData[name];
            var total = 0;
            for (var i = 0; i < times.length; i++) {
                total += times[i];
            }
            var avg = total / times.length;
            averages.push({name: name, avg: avg, count: times.length, max: Math.max.apply(null, times)});
        }
        
        // 按平均时间排序
        averages.sort(function(a, b) {
            return b.avg - a.avg;
        });
        
        // 打印前N个
        for (var i = 0; i < Math.min(count, averages.length); i++) {
            var item = averages[i];
            console.log("        " + item.name + ": 平均" + item.avg.toFixed(2) + "ms, 最大" + item.max.toFixed(2) + "ms, 调用" + item.count + "次");
        }
        
        if (averages.length === 0) {
            console.log("        无数据");
        }
    }

    /**
     * 一、监控View的绘制过程
     */
    if (config.monitorViewDraw) {
        try {
            var View = Java.use("android.view.View");
            
            // 监控onDraw方法
            View.onDraw.implementation = function(canvas) {
                var viewName = this.getClass().getName();
                var startDrawTime = new Date().getTime();
                
                // 调用原始方法
                this.onDraw(canvas);
                
                var endDrawTime = new Date().getTime();
                var drawTime = endDrawTime - startDrawTime;
                
                // 记录执行时间
                recordExecutionTime("draw", viewName, drawTime);
                
                // 如果绘制时间超过阈值，打印警告
                if (drawTime > config.performanceThreshold) {
                    console.log(formatTimestamp() + "[!] 绘制时间过长: " + viewName + " 耗时: " + drawTime + "ms");
                    
                    if (config.printStack) {
                        console.log("    调用堆栈:\n    " + getStackTrace());
                    }
                } else if (config.verbose) {
                    console.log(formatTimestamp() + "[+] 绘制: " + viewName + " 耗时: " + drawTime + "ms");
                }
            };
            
            // 监控dispatchDraw方法
            View.dispatchDraw.implementation = function(canvas) {
                var viewName = this.getClass().getName();
                var startDrawTime = new Date().getTime();
                
                // 调用原始方法
                this.dispatchDraw(canvas);
                
                var endDrawTime = new Date().getTime();
                var drawTime = endDrawTime - startDrawTime;
                
                // 记录执行时间
                recordExecutionTime("draw", viewName + ".dispatchDraw", drawTime);
                
                // 如果绘制时间超过阈值，打印警告
                if (drawTime > config.performanceThreshold) {
                    console.log(formatTimestamp() + "[!] 分发绘制时间过长: " + viewName + " 耗时: " + drawTime + "ms");
                    
                    if (config.printStack) {
                        console.log("    调用堆栈:\n    " + getStackTrace());
                    }
                } else if (config.verbose) {
                    console.log(formatTimestamp() + "[+] 分发绘制: " + viewName + " 耗时: " + drawTime + "ms");
                }
            };
            
            console.log("[+] View绘制过程监控设置完成");
        } catch (e) {
            console.log("[-] View绘制过程监控设置失败: " + e);
        }
    }

    /**
     * 二、监控布局过程
     */
    if (config.monitorLayout) {
        try {
            var View = Java.use("android.view.View");
            
            // 监控onLayout方法
            View.onLayout.implementation = function(changed, left, top, right, bottom) {
                var viewName = this.getClass().getName();
                var startLayoutTime = new Date().getTime();
                
                // 调用原始方法
                this.onLayout(changed, left, top, right, bottom);
                
                var endLayoutTime = new Date().getTime();
                var layoutTime = endLayoutTime - startLayoutTime;
                
                // 记录执行时间
                recordExecutionTime("layout", viewName, layoutTime);
                
                // 如果布局时间超过阈值，打印警告
                if (layoutTime > config.performanceThreshold) {
                    console.log(formatTimestamp() + "[!] 布局时间过长: " + viewName + " 耗时: " + layoutTime + "ms");
                    
                    if (config.printStack) {
                        console.log("    调用堆栈:\n    " + getStackTrace());
                    }
                } else if (config.verbose) {
                    console.log(formatTimestamp() + "[+] 布局: " + viewName + " 耗时: " + layoutTime + "ms");
                }
            };
            
            // 监控layout方法
            View.layout.implementation = function(l, t, r, b) {
                var viewName = this.getClass().getName();
                var startLayoutTime = new Date().getTime();
                
                // 调用原始方法
                var result = this.layout(l, t, r, b);
                
                var endLayoutTime = new Date().getTime();
                var layoutTime = endLayoutTime - startLayoutTime;
                
                // 记录执行时间
                recordExecutionTime("layout", viewName + ".layout", layoutTime);
                
                // 如果布局时间超过阈值，打印警告
                if (layoutTime > config.performanceThreshold) {
                    console.log(formatTimestamp() + "[!] layout方法时间过长: " + viewName + " 耗时: " + layoutTime + "ms");
                    
                    if (config.printStack) {
                        console.log("    调用堆栈:\n    " + getStackTrace());
                    }
                } else if (config.verbose) {
                    console.log(formatTimestamp() + "[+] layout方法: " + viewName + " 耗时: " + layoutTime + "ms");
                }
                
                return result;
            };
            
            console.log("[+] 布局过程监控设置完成");
        } catch (e) {
            console.log("[-] 布局过程监控设置失败: " + e);
        }
    }

    /**
     * 三、监控测量过程
     */
    if (config.monitorMeasure) {
        try {
            var View = Java.use("android.view.View");
            
            // 监控onMeasure方法
            View.onMeasure.implementation = function(widthMeasureSpec, heightMeasureSpec) {
                var viewName = this.getClass().getName();
                var startMeasureTime = new Date().getTime();
                
                // 调用原始方法
                this.onMeasure(widthMeasureSpec, heightMeasureSpec);
                
                var endMeasureTime = new Date().getTime();
                var measureTime = endMeasureTime - startMeasureTime;
                
                // 记录执行时间
                recordExecutionTime("measure", viewName, measureTime);
                
                // 如果测量时间超过阈值，打印警告
                if (measureTime > config.performanceThreshold) {
                    console.log(formatTimestamp() + "[!] 测量时间过长: " + viewName + " 耗时: " + measureTime + "ms");
                    
                    if (config.printStack) {
                        console.log("    调用堆栈:\n    " + getStackTrace());
                    }
                } else if (config.verbose) {
                    console.log(formatTimestamp() + "[+] 测量: " + viewName + " 耗时: " + measureTime + "ms");
                }
            };
            
            // 监控measure方法
            View.measure.implementation = function(widthMeasureSpec, heightMeasureSpec) {
                var viewName = this.getClass().getName();
                var startMeasureTime = new Date().getTime();
                
                // 调用原始方法
                var result = this.measure(widthMeasureSpec, heightMeasureSpec);
                
                var endMeasureTime = new Date().getTime();
                var measureTime = endMeasureTime - startMeasureTime;
                
                // 记录执行时间
                recordExecutionTime("measure", viewName + ".measure", measureTime);
                
                // 如果测量时间超过阈值，打印警告
                if (measureTime > config.performanceThreshold) {
                    console.log(formatTimestamp() + "[!] measure方法时间过长: " + viewName + " 耗时: " + measureTime + "ms");
                    
                    if (config.printStack) {
                        console.log("    调用堆栈:\n    " + getStackTrace());
                    }
                } else if (config.verbose) {
                    console.log(formatTimestamp() + "[+] measure方法: " + viewName + " 耗时: " + measureTime + "ms");
                }
                
                return result;
            };
            
            console.log("[+] 测量过程监控设置完成");
        } catch (e) {
            console.log("[-] 测量过程监控设置失败: " + e);
        }
    }

    /**
     * 四、监控动画
     */
    if (config.monitorAnimation) {
        try {
            // 监控ValueAnimator
            var ValueAnimator = Java.use("android.animation.ValueAnimator");
            ValueAnimator.setDuration.implementation = function(duration) {
                console.log(formatTimestamp() + "[+] 设置动画时长: " + duration + "ms");
                
                if (config.printStack && config.verbose) {
                    console.log("    调用堆栈:\n    " + getStackTrace());
                }
                
                return this.setDuration(duration);
            };
            
            // 监控ObjectAnimator
            var ObjectAnimator = Java.use("android.animation.ObjectAnimator");
            ObjectAnimator.setTarget.implementation = function(target) {
                var targetClass = target.getClass().getName();
                console.log(formatTimestamp() + "[+] 设置动画目标: " + targetClass);
                
                if (config.printStack && config.verbose) {
                    console.log("    调用堆栈:\n    " + getStackTrace());
                }
                
                return this.setTarget(target);
            };
            
            console.log("[+] 动画监控设置完成");
        } catch (e) {
            console.log("[-] 动画监控设置失败: " + e);
        }
    }

    /**
     * 五、监控Choreographer帧回调
     */
    if (config.monitorChoreographer) {
        try {
            var Choreographer = Java.use("android.view.Choreographer");
            var SystemClock = Java.use("android.os.SystemClock");
            
            // 获取Choreographer实例
            var instance = Choreographer.getInstance();
            
            // 创建帧回调
            var FrameCallback = Java.use("android.view.Choreographer$FrameCallback");
            var FrameCallbackImpl = Java.registerClass({
                name: "com.frida.FrameCallback",
                implements: [FrameCallback],
                fields: {
                    lastFrameTimeNanos: "long"
                },
                methods: {
                    doFrame: function(frameTimeNanos) {
                        // 计算帧间隔
                        if (this.lastFrameTimeNanos.value !== 0) {
                            var intervalNanos = frameTimeNanos - this.lastFrameTimeNanos.value;
                            var intervalMs = intervalNanos / 1000000;
                            
                            // 记录帧时间
                            recordExecutionTime("frame", "frame", intervalMs);
                            
                            if (config.verbose) {
                                console.log(formatTimestamp() + "[+] 帧间隔: " + intervalMs.toFixed(2) + "ms");
                            }
                        }
                        
                        // 更新上一帧时间
                        this.lastFrameTimeNanos.value = frameTimeNanos;
                        
                        // 继续监听下一帧
                        instance.postFrameCallback(this);
                    }
                }
            });
            
            // 创建回调实例并注册
            var callback = FrameCallbackImpl.$new();
            callback.lastFrameTimeNanos.value = 0;
            instance.postFrameCallback(callback);
            
            console.log("[+] Choreographer帧回调监控设置完成");
        } catch (e) {
            console.log("[-] Choreographer帧回调监控设置失败: " + e);
        }
    }

    /**
     * 六、定期打印性能统计
     */
    setInterval(function() {
        printPerformanceStats();
    }, 10000); // 每10秒打印一次统计

    /**
     * 修改配置的函数
     */
    global.setUIConfig = function(newConfig) {
        for (var key in newConfig) {
            if (config.hasOwnProperty(key)) {
                config[key] = newConfig[key];
                console.log("[+] UI监控配置已更新: " + key + " = " + newConfig[key]);
            }
        }
    };

    console.log("[*] UI渲染性能监控脚本已加载");
    console.log("[*] 使用方法:");
    console.log("    setUIConfig({key: value}) - 修改配置");
    console.log("    例如: setUIConfig({verbose: false}) - 关闭详细日志");
}); 