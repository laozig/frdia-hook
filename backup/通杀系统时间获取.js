/*
 * 脚本名称：通杀系统时间获取.js
 * 功能：自动监控应用中的系统时间获取、时间戳生成、日期操作等相关API
 * 适用场景：时间校验分析、时间戳欺骗、时间依赖机制分析、有效期检测
 * 使用方法：
 *   1. frida -U -f 包名 -l 通杀系统时间获取.js --no-pause
 *   2. 查看控制台输出，获取时间获取信息
 * 启动方式说明：
 *   - -U 代表使用USB连接的设备
 *   - -f 代表以spawn方式启动目标应用（推荐，可以捕获启动阶段的时间检测）
 *   - --no-pause 指示Frida不要暂停应用执行，保证App正常运行
 *   - 也可使用 -F 以attach方式附加到已运行的进程
 * 参数说明：
 *   - 包名：目标应用的包名，如com.example.app
 * 监控函数说明：
 *   - System.currentTimeMillis(): 获取系统当前时间的毫秒值
 *   - System.nanoTime(): 获取高精度纳秒时间
 *   - java.util.Date相关: 日期和时间操作
 *   - Calendar相关: 日历和时间操作
 *   - TimeZone相关: 时区处理
 *   - Native层time()和gettimeofday(): 底层时间获取
 * 时间API用途：
 *   - 应用许可证和试用期检测
 *   - 基于时间的安全令牌生成与验证
 *   - 证书有效期验证
 *   - 定时执行任务
 *   - 时间敏感操作的日志记录
 * 输出内容：
 *   - 函数调用: 显示调用的时间相关API
 *   - 时间值: 系统返回的实际时间值
 *   - 格式化时间: 转换为可读格式的时间
 *   - 调用位置: 获取时间的代码位置信息
 * 实际应用场景：
 *   - 分析应用时间检测机制
 *   - 绕过基于时间的限制
 *   - 理解时间相关安全措施
 *   - 调试定时功能问题
 * 注意事项：
 *   - 某些加固应用需配合反检测脚本
 *   - 频繁的时间API调用会产生大量日志
 *   - 建议与时间修改工具配合使用来验证时间依赖功能
 */

// 通杀系统时间获取
Java.perform(function () {
    // 辅助函数：格式化日期对象为可读字符串
    function formatDate(date) {
        try {
            var SimpleDateFormat = Java.use('java.text.SimpleDateFormat');
            var sdf = SimpleDateFormat.$new("yyyy-MM-dd HH:mm:ss.SSS");
            return sdf.format(date);
        } catch (e) {
            return date.toString();
        }
    }
    
    // 辅助函数：将时间戳格式化为可读时间
    function formatTimestamp(timestamp) {
        var date = Java.use("java.util.Date").$new(timestamp);
        return formatDate(date);
    }
    
    // 辅助函数：获取调用堆栈的简短表示
    function getStackShort() {
        return Java.use("android.util.Log").getStackTraceString(
            Java.use("java.lang.Exception").$new()).split('\n').slice(2, 5).join('\n    ');
    }
    
    //======== Java层时间API监控 =========
    
    // 监控System.currentTimeMillis
    var System = Java.use('java.lang.System');
    System.currentTimeMillis.implementation = function () {
        var t = this.currentTimeMillis();
        console.log('[*] System.currentTimeMillis: ' + t);
        console.log('    格式化时间: ' + formatTimestamp(t));
        console.log('    调用堆栈: \n    ' + getStackShort());
        return t;
    };
    
    // 监控System.nanoTime
    System.nanoTime.implementation = function () {
        var t = this.nanoTime();
        console.log('[*] System.nanoTime: ' + t + ' ns');
        // 纳秒值过大，只显示毫秒部分
        console.log('    毫秒部分: ' + Math.floor(t / 1000000) + ' ms');
        return t;
    };
    
    //===== java.util.Date类监控 =====
    var Date = Java.use('java.util.Date');
    
    // 无参数构造函数 - 创建当前时间的Date对象
    Date.$init.overload().implementation = function () {
        var d = this.$init();
        console.log('[*] new Date(): ' + formatDate(this));
        console.log('    时间戳: ' + this.getTime());
        console.log('    调用堆栈: \n    ' + getStackShort());
        return d;
    };
    
    // 监控Date(long)构造函数 - 从时间戳创建Date对象
    Date.$init.overload('long').implementation = function (time) {
        var d = this.$init(time);
        console.log('[*] new Date(' + time + '): ' + formatDate(this));
        console.log('    调用堆栈: \n    ' + getStackShort());
        return d;
    };
    
    // 监控Date.getTime方法
    Date.getTime.implementation = function () {
        var time = this.getTime();
        console.log('[*] Date.getTime: ' + time);
        console.log('    日期: ' + formatDate(this));
        return time;
    };
    
    // 监控Date.setTime方法
    Date.setTime.implementation = function (time) {
        console.log('[*] Date.setTime(' + time + ')');
        console.log('    格式化时间: ' + formatTimestamp(time));
        console.log('    调用堆栈: \n    ' + getStackShort());
        return this.setTime(time);
    };
    
    //===== Calendar类监控 =====
    try {
        var Calendar = Java.use('java.util.Calendar');
        var GregorianCalendar = Java.use('java.util.GregorianCalendar');
        
        // 监控Calendar.getInstance静态方法
        Calendar.getInstance.overload().implementation = function () {
            var calendar = this.getInstance();
            var time = calendar.getTimeInMillis();
            console.log('[*] Calendar.getInstance(): ' + time);
            console.log('    格式化时间: ' + formatTimestamp(time));
            console.log('    调用堆栈: \n    ' + getStackShort());
            return calendar;
        };
        
        // 监控Calendar.getTimeInMillis方法
        Calendar.getTimeInMillis.implementation = function () {
            var time = this.getTimeInMillis();
            console.log('[*] Calendar.getTimeInMillis: ' + time);
            console.log('    格式化时间: ' + formatTimestamp(time));
            return time;
        };
        
        // 监控Calendar.setTimeInMillis方法
        Calendar.setTimeInMillis.implementation = function (time) {
            console.log('[*] Calendar.setTimeInMillis(' + time + ')');
            console.log('    格式化时间: ' + formatTimestamp(time));
            console.log('    调用堆栈: \n    ' + getStackShort());
            return this.setTimeInMillis(time);
        };
        
        // 监控GregorianCalendar构造函数
        GregorianCalendar.$init.overload().implementation = function () {
            var gc = this.$init();
            var time = this.getTimeInMillis();
            console.log('[*] new GregorianCalendar(): ' + time);
            console.log('    格式化时间: ' + formatTimestamp(time));
            return gc;
        };
        
        // 监控设置年月日的构造函数
        GregorianCalendar.$init.overload('int', 'int', 'int').implementation = function (year, month, day) {
            var gc = this.$init(year, month, day);
            console.log('[*] new GregorianCalendar(' + year + ',' + month + ',' + day + ')');
            console.log('    格式化时间: ' + formatDate(this.getTime()));
            console.log('    调用堆栈: \n    ' + getStackShort());
            return gc;
        };
    } catch (e) {
        console.log("[-] Calendar类监控失败: " + e);
    }
    
    //===== TimeZone类监控 =====
    try {
        var TimeZone = Java.use('java.util.TimeZone');
        
        // 监控TimeZone.getDefault方法
        TimeZone.getDefault.implementation = function () {
            var tz = this.getDefault();
            console.log('[*] TimeZone.getDefault: ' + tz.getID());
            console.log('    显示名称: ' + tz.getDisplayName());
            console.log('    时差(毫秒): ' + tz.getRawOffset());
            return tz;
        };
        
        // 监控TimeZone.getTimeZone方法
        TimeZone.getTimeZone.overload('java.lang.String').implementation = function (id) {
            var tz = this.getTimeZone(id);
            console.log('[*] TimeZone.getTimeZone(' + id + ')');
            return tz;
        };
    } catch (e) {
        console.log("[-] TimeZone类监控失败: " + e);
    }
    
    //===== Native层时间函数监控 =====
    try {
        // 监控C标准库中的time函数
        // 函数原型: time_t time(time_t *tloc);
        var timePtr = Module.findExportByName(null, 'time');
        if (timePtr) {
            Interceptor.attach(timePtr, {
                onLeave: function (retval) {
                    var time = retval.toInt32();
                    console.log('[*] Native time() 返回: ' + time);
                    console.log('    格式化时间: ' + new Date(time * 1000).toString());
                }
            });
        }
        
        // 监控gettimeofday函数
        // 函数原型: int gettimeofday(struct timeval *tv, struct timezone *tz);
        var gettimeofdayPtr = Module.findExportByName(null, 'gettimeofday');
        if (gettimeofdayPtr) {
            Interceptor.attach(gettimeofdayPtr, {
                onEnter: function (args) {
                    this.tvPtr = args[0]; // struct timeval *tv
                },
                onLeave: function (retval) {
                    if (this.tvPtr) {
                        var seconds = Memory.readU32(this.tvPtr);
                        var microseconds = Memory.readU32(this.tvPtr.add(4));
                        console.log('[*] Native gettimeofday() 返回: ' + seconds + '.' + microseconds + ' 秒');
                        console.log('    格式化时间: ' + new Date(seconds * 1000 + Math.floor(microseconds / 1000)).toString());
                    }
                }
            });
        }
        
        // 监控clock_gettime函数
        // 函数原型: int clock_gettime(clockid_t clk_id, struct timespec *tp);
        var clockGettimePtr = Module.findExportByName(null, 'clock_gettime');
        if (clockGettimePtr) {
            Interceptor.attach(clockGettimePtr, {
                onEnter: function (args) {
                    this.clockId = args[0].toInt32(); // clockid_t
                    this.tsPtr = args[1]; // struct timespec *
                },
                onLeave: function (retval) {
                    if (this.tsPtr) {
                        var seconds = Memory.readU32(this.tsPtr);
                        var nanoseconds = Memory.readU32(this.tsPtr.add(4));
                        var clockType = "未知";
                        switch (this.clockId) {
                            case 0: clockType = "CLOCK_REALTIME"; break;
                            case 1: clockType = "CLOCK_MONOTONIC"; break;
                            case 2: clockType = "CLOCK_PROCESS_CPUTIME_ID"; break;
                            case 3: clockType = "CLOCK_THREAD_CPUTIME_ID"; break;
                        }
                        console.log('[*] Native clock_gettime(' + clockType + ') 返回: ' + 
                                  seconds + '.' + nanoseconds + ' 秒');
                        
                        if (this.clockId === 0) { // 只有CLOCK_REALTIME是实际时间
                            console.log('    格式化时间: ' + new Date(seconds * 1000 + Math.floor(nanoseconds / 1000000)).toString());
                        }
                    }
                }
            });
        }
    } catch (e) {
        console.log("[-] Native层函数监控失败: " + e);
    }
    
    console.log("[*] 系统时间获取监控已启动");
    console.log("[*] 监控范围: System时间API, Date类, Calendar类, TimeZone类和Native时间函数");
}); 