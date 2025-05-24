/*
 * 脚本名称：监控广播接收.js
 * 功能：监控Android广播注册、发送和接收
 * 
 * 适用场景：
 *   - 分析应用间通信机制
 *   - 发现隐藏的广播接收器
 *   - 逆向应用内部通信逻辑
 *   - 理解应用的事件响应机制
 *   - 安全审计中发现潜在漏洞
 *
 * 使用方法：
 *   1. frida -U -f 目标应用包名 -l 监控广播接收.js --no-pause
 *   2. 或者 frida -U --attach-pid 目标进程PID -l 监控广播接收.js
 *   3. 查看控制台输出，分析广播的注册、发送和接收情况
 *
 * 启动方式说明：
 *   - -U: 使用USB连接的设备
 *   - -f: 指定以spawn方式启动的应用包名
 *   - --attach-pid: 附加到已运行的进程
 *   - --no-pause: 注入后不暂停应用执行
 *
 * 输出内容：
 *   - 广播注册：显示接收器类名和过滤的Action列表
 *   - 广播接收：显示接收到的广播Action和Extra数据
 *   - 广播发送：显示发送广播的Action和目标组件
 *
 * 注意事项：
 *   - 部分系统广播可能数量较大，建议关注特定Action
 *   - 可以根据需要修改脚本，只监控特定包名的广播
 *   - 对于动态注册的广播接收器特别有用
 */

Java.perform(function () {
    console.log("[*] 广播监控已启动");
    
    // 监控广播注册
    var Context = Java.use('android.content.Context');
    Context.registerReceiver.overload('android.content.BroadcastReceiver', 'android.content.IntentFilter').implementation = function (receiver, filter) {
        var result = this.registerReceiver(receiver, filter);
        
        // 打印广播注册信息
        console.log("[*] 注册广播接收器:");
        console.log("    接收器: " + receiver.getClass().getName());
        
        // 获取过滤器详情
        var filterInfo = "    过滤器: [";
        for (var i = 0; i < filter.countActions(); i++) {
            filterInfo += filter.getAction(i);
            if (i < filter.countActions() - 1) filterInfo += ", ";
        }
        filterInfo += "]";
        console.log(filterInfo);
        
        // 获取调用堆栈
        console.log("    调用堆栈:\n    " + 
            Java.use("android.util.Log").getStackTraceString(
                Java.use("java.lang.Exception").$new()).split('\n').slice(2, 5).join('\n    '));
        
        return result;
    };
    
    // 增加带权限参数的重载版本
    Context.registerReceiver.overload('android.content.BroadcastReceiver', 'android.content.IntentFilter', 'java.lang.String', 'android.os.Handler').implementation = function (receiver, filter, permission, scheduler) {
        var result = this.registerReceiver(receiver, filter, permission, scheduler);
        
        console.log("[*] 注册带权限的广播接收器:");
        console.log("    接收器: " + receiver.getClass().getName());
        console.log("    权限: " + permission);
        
        return result;
    };
    
    // 监控广播接收
    var BroadcastReceiver = Java.use('android.content.BroadcastReceiver');
    BroadcastReceiver.onReceive.implementation = function (context, intent) {
        console.log("[*] 接收到广播:");
        
        // 获取广播Action
        var action = intent.getAction();
        console.log("    Action: " + action);
        
        // 获取广播数据
        try {
            var extras = intent.getExtras();
            if (extras) {
                var keys = extras.keySet();
                if (keys.size() > 0) {
                    console.log("    Extra数据:");
                    var iterator = keys.iterator();
                    while (iterator.hasNext()) {
                        var key = iterator.next();
                        var value = extras.get(key);
                        console.log("      " + key + " = " + value);
                    }
                }
            }
        } catch (e) {
            console.log("    无法获取Extra数据: " + e);
        }
        
        // 获取接收器类名
        console.log("    接收器: " + this.getClass().getName());
        
        return this.onReceive(context, intent);
    };
    
    // 监控广播发送
    Context.sendBroadcast.overload('android.content.Intent').implementation = function (intent) {
        console.log("[*] 发送广播:");
        console.log("    Action: " + intent.getAction());
        
        // 打印组件信息
        var component = intent.getComponent();
        if (component) {
            console.log("    目标组件: " + component.getPackageName() + "/" + component.getClassName());
        }
        
        return this.sendBroadcast(intent);
    };
    
    // 监控有序广播
    Context.sendOrderedBroadcast.overload('android.content.Intent', 'java.lang.String').implementation = function (intent, receiverPermission) {
        console.log("[*] 发送有序广播:");
        console.log("    Action: " + intent.getAction());
        if (receiverPermission) {
            console.log("    接收权限: " + receiverPermission);
        }
        
        return this.sendOrderedBroadcast(intent, receiverPermission);
    };
}); 