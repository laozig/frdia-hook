/**
 * 定位信息模拟脚本
 * 
 * 功能：模拟Android应用中的GPS位置信息
 * 作用：欺骗应用获取到的位置信息，提供自定义的经纬度
 * 适用：测试LBS应用，绕过地理位置限制，保护隐私
 */

// 等待Java虚拟机加载完成
Java.perform(function() {
    console.log("[*] 定位信息模拟脚本已启动");

    // 默认模拟位置（北京天安门广场）
    var mockLatitude = 39.9087;   // 纬度
    var mockLongitude = 116.3976; // 经度
    var mockAltitude = 430.0;     // 海拔（米）
    var mockAccuracy = 10.0;      // 精度（米）
    var mockSpeed = 0.0;          // 速度（米/秒）
    var mockBearing = 0.0;        // 方向（度）
    var mockTime = 0;             // 时间戳，0表示使用系统当前时间
    var mockProvider = "gps";     // 位置提供者

    console.log("[+] 默认模拟位置设置为: 纬度=" + mockLatitude + ", 经度=" + mockLongitude);

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
     * 一、拦截LocationManager
     * 这是Android中获取位置信息的主要类
     */
    var LocationManager = Java.use("android.location.LocationManager");
    
    // 拦截getLastKnownLocation方法
    LocationManager.getLastKnownLocation.overload("java.lang.String").implementation = function(provider) {
        console.log("\n[+] LocationManager.getLastKnownLocation");
        console.log("    提供者: " + provider);
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        // 创建模拟位置对象
        var Location = Java.use("android.location.Location");
        var mockLocation = Location.$new(provider);
        
        // 设置模拟位置信息
        mockLocation.setLatitude(mockLatitude);
        mockLocation.setLongitude(mockLongitude);
        mockLocation.setAltitude(mockAltitude);
        mockLocation.setAccuracy(mockAccuracy);
        mockLocation.setSpeed(mockSpeed);
        mockLocation.setBearing(mockBearing);
        
        // 设置时间戳
        var currentTime = mockTime === 0 ? Java.use("java.lang.System").currentTimeMillis() : mockTime;
        mockLocation.setTime(currentTime);
        mockLocation.setElapsedRealtimeNanos(currentTime * 1000000);
        
        console.log("    [已模拟] 返回位置: 纬度=" + mockLatitude + ", 经度=" + mockLongitude);
        
        return mockLocation;
    };
    
    // 拦截requestLocationUpdates方法，用于持续监听位置变化
    var requestLocationUpdatesOverloads = [
        "java.lang.String, long, float, android.location.LocationListener",
        "java.lang.String, long, float, android.location.LocationListener, android.os.Looper",
        "java.lang.String, long, float, android.app.PendingIntent"
    ];
    
    for (var i = 0; i < requestLocationUpdatesOverloads.length; i++) {
        try {
            LocationManager.requestLocationUpdates.overload(requestLocationUpdatesOverloads[i]).implementation = function() {
                console.log("\n[+] LocationManager.requestLocationUpdates");
                console.log("    提供者: " + arguments[0]);
                console.log("    最小时间间隔: " + arguments[1] + " 毫秒");
                console.log("    最小距离变化: " + arguments[2] + " 米");
                console.log("    调用堆栈:\n    " + getStackTrace());
                
                // 如果是LocationListener，我们需要立即发送一个模拟位置
                if (arguments.length >= 4 && arguments[3] != null && requestLocationUpdatesOverloads[i].indexOf("LocationListener") !== -1) {
                    var listener = arguments[3];
                    var provider = arguments[0];
                    
                    // 创建模拟位置对象
                    var Location = Java.use("android.location.Location");
                    var mockLocation = Location.$new(provider);
                    
                    // 设置模拟位置信息
                    mockLocation.setLatitude(mockLatitude);
                    mockLocation.setLongitude(mockLongitude);
                    mockLocation.setAltitude(mockAltitude);
                    mockLocation.setAccuracy(mockAccuracy);
                    mockLocation.setSpeed(mockSpeed);
                    mockLocation.setBearing(mockBearing);
                    
                    // 设置时间戳
                    var currentTime = mockTime === 0 ? Java.use("java.lang.System").currentTimeMillis() : mockTime;
                    mockLocation.setTime(currentTime);
                    mockLocation.setElapsedRealtimeNanos(currentTime * 1000000);
                    
                    // 延迟100毫秒后发送位置更新，模拟真实情况
                    setTimeout(function() {
                        Java.scheduleOnMainThread(function() {
                            try {
                                listener.onLocationChanged(mockLocation);
                                console.log("    [已模拟] 发送位置更新: 纬度=" + mockLatitude + ", 经度=" + mockLongitude);
                            } catch (e) {
                                console.log("    [错误] 发送位置更新失败: " + e);
                            }
                        });
                    }, 100);
                }
                
                // 调用原始方法
                var result;
                if (arguments.length === 4) {
                    result = this.requestLocationUpdates(arguments[0], arguments[1], arguments[2], arguments[3]);
                } else if (arguments.length === 5) {
                    result = this.requestLocationUpdates(arguments[0], arguments[1], arguments[2], arguments[3], arguments[4]);
                }
                
                return result;
            };
        } catch (e) {
            console.log("[-] 无法拦截 requestLocationUpdates(" + requestLocationUpdatesOverloads[i] + "): " + e);
        }
    }

    /**
     * 二、拦截LocationListener
     * 用于接收位置更新的回调接口
     */
    var LocationListener = Java.use("android.location.LocationListener");
    
    // 拦截onLocationChanged方法
    LocationListener.onLocationChanged.implementation = function(location) {
        // 获取原始位置信息
        var originalLatitude = location.getLatitude();
        var originalLongitude = location.getLongitude();
        
        console.log("\n[+] LocationListener.onLocationChanged");
        console.log("    原始位置: 纬度=" + originalLatitude + ", 经度=" + originalLongitude);
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        // 修改位置信息
        location.setLatitude(mockLatitude);
        location.setLongitude(mockLongitude);
        location.setAltitude(mockAltitude);
        location.setAccuracy(mockAccuracy);
        
        console.log("    [已修改] 位置信息: 纬度=" + mockLatitude + ", 经度=" + mockLongitude);
        
        // 调用原始方法
        this.onLocationChanged(location);
    };

    /**
     * 三、拦截FusedLocationProviderClient
     * Google Play Services中的位置服务API
     */
    try {
        var FusedLocationProviderClient = Java.use("com.google.android.gms.location.FusedLocationProviderClient");
        
        // 拦截getLastLocation方法
        FusedLocationProviderClient.getLastLocation.implementation = function() {
            console.log("\n[+] FusedLocationProviderClient.getLastLocation");
            console.log("    调用堆栈:\n    " + getStackTrace());
            
            // 创建Task对象
            var Tasks = Java.use("com.google.android.gms.tasks.Tasks");
            var Location = Java.use("android.location.Location");
            
            // 创建模拟位置对象
            var mockLocation = Location.$new(mockProvider);
            mockLocation.setLatitude(mockLatitude);
            mockLocation.setLongitude(mockLongitude);
            mockLocation.setAltitude(mockAltitude);
            mockLocation.setAccuracy(mockAccuracy);
            mockLocation.setSpeed(mockSpeed);
            mockLocation.setBearing(mockBearing);
            
            // 设置时间戳
            var currentTime = mockTime === 0 ? Java.use("java.lang.System").currentTimeMillis() : mockTime;
            mockLocation.setTime(currentTime);
            mockLocation.setElapsedRealtimeNanos(currentTime * 1000000);
            
            console.log("    [已模拟] 返回位置: 纬度=" + mockLatitude + ", 经度=" + mockLongitude);
            
            // 返回包含模拟位置的Task
            return Tasks.forResult(mockLocation);
        };
        
        console.log("[+] FusedLocationProviderClient拦截设置完成");
    } catch (e) {
        console.log("[-] FusedLocationProviderClient可能未被使用: " + e);
    }

    /**
     * 四、拦截LocationCallback
     * Google Play Services中接收位置更新的回调
     */
    try {
        var LocationCallback = Java.use("com.google.android.gms.location.LocationCallback");
        var LocationResult = Java.use("com.google.android.gms.location.LocationResult");
        
        // 拦截onLocationResult方法
        LocationCallback.onLocationResult.implementation = function(locationResult) {
            console.log("\n[+] LocationCallback.onLocationResult");
            console.log("    调用堆栈:\n    " + getStackTrace());
            
            // 创建模拟位置
            var Location = Java.use("android.location.Location");
            var mockLocation = Location.$new(mockProvider);
            mockLocation.setLatitude(mockLatitude);
            mockLocation.setLongitude(mockLongitude);
            mockLocation.setAltitude(mockAltitude);
            mockLocation.setAccuracy(mockAccuracy);
            mockLocation.setSpeed(mockSpeed);
            mockLocation.setBearing(mockBearing);
            
            // 设置时间戳
            var currentTime = mockTime === 0 ? Java.use("java.lang.System").currentTimeMillis() : mockTime;
            mockLocation.setTime(currentTime);
            mockLocation.setElapsedRealtimeNanos(currentTime * 1000000);
            
            // 创建包含模拟位置的LocationResult
            var ArrayList = Java.use("java.util.ArrayList");
            var locationList = ArrayList.$new();
            locationList.add(mockLocation);
            
            var mockLocationResult = LocationResult.create(locationList);
            
            console.log("    [已模拟] 位置结果: 纬度=" + mockLatitude + ", 经度=" + mockLongitude);
            
            // 调用原始方法，传入模拟的LocationResult
            this.onLocationResult(mockLocationResult);
        };
        
        console.log("[+] LocationCallback拦截设置完成");
    } catch (e) {
        console.log("[-] LocationCallback可能未被使用: " + e);
    }

    /**
     * 五、提供修改模拟位置的API
     * 可以通过Frida控制台动态修改模拟位置
     */
    function setMockLocation(latitude, longitude, altitude, accuracy, speed, bearing, time, provider) {
        mockLatitude = latitude !== undefined ? latitude : mockLatitude;
        mockLongitude = longitude !== undefined ? longitude : mockLongitude;
        mockAltitude = altitude !== undefined ? altitude : mockAltitude;
        mockAccuracy = accuracy !== undefined ? accuracy : mockAccuracy;
        mockSpeed = speed !== undefined ? speed : mockSpeed;
        mockBearing = bearing !== undefined ? bearing : mockBearing;
        mockTime = time !== undefined ? time : mockTime;
        mockProvider = provider !== undefined ? provider : mockProvider;
        
        console.log("\n[+] 模拟位置已更新:");
        console.log("    纬度: " + mockLatitude);
        console.log("    经度: " + mockLongitude);
        console.log("    海拔: " + mockAltitude + " 米");
        console.log("    精度: " + mockAccuracy + " 米");
        console.log("    速度: " + mockSpeed + " 米/秒");
        console.log("    方向: " + mockBearing + " 度");
        console.log("    提供者: " + mockProvider);
    }
    
    // 导出API到全局
    global.setMockLocation = setMockLocation;
    
    console.log("[*] 定位信息模拟设置完成");
    console.log("[*] 使用方法: 调用 setMockLocation(latitude, longitude) 修改模拟位置");
    console.log("[*] 示例: setMockLocation(31.2304, 121.4737) // 上海");
}); 