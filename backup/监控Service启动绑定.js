/*
 * 脚本名称：监控Service启动绑定.js
 * 功能描述：监控Android应用中Service组件的启动和绑定操作，追踪应用服务调用
 * 
 * 适用场景：
 *   - 分析应用中的后台服务行为
 *   - 发现隐藏的服务组件
 *   - 理解应用组件间的通信机制
 *   - 监控应用中关键服务的启动条件
 *   - 逆向分析应用功能架构
 *
 * 使用方法：
 *   1. frida -U -f 目标应用包名 -l 监控Service启动绑定.js --no-pause
 *   2. 或者 frida -U --attach-pid 目标进程PID -l 监控Service启动绑定.js
 *   3. 操作应用，观察控制台输出的服务启动和绑定信息
 *
 * 启动方式说明：
 *   - -U: 使用USB连接的设备
 *   - -f: 指定以spawn方式启动的应用包名
 *   - --attach-pid: 附加到已运行的进程
 *   - --no-pause: 注入后不暂停应用执行
 *
 * 工作原理：
 *   Hook android.content.Context类的startService和bindService方法，
 *   这些方法是Android系统用于启动和绑定服务的标准API。
 *   每当应用调用这些方法时，脚本会记录传递的Intent对象，
 *   从而可以分析服务组件的启动参数和目标服务信息。
 */

// 监控Service启动与绑定
Java.perform(function () {
    var Context = Java.use('android.content.Context');
    
    // 监控服务启动
    Context.startService.implementation = function (intent) {
        // 提取服务信息
        var serviceInfo = "";
        try {
            var component = intent.getComponent();
            if (component) {
                serviceInfo = component.getPackageName() + "/" + component.getClassName();
            } else {
                serviceInfo = "隐式Intent启动";
            }
        } catch (e) {
            serviceInfo = "无法解析Intent";
        }
        
        console.log('[*] 启动Service: ' + serviceInfo);
        console.log('    Intent详情: ' + intent);
        
        // 可选：打印调用堆栈
        // console.log('    调用堆栈: \n    ' + 
        //     Java.use("android.util.Log").getStackTraceString(
        //     Java.use("java.lang.Exception").$new()).split('\n').slice(2, 5).join('\n    '));
        
        // 调用原始方法并返回结果
        return this.startService(intent);
    };
    
    // 监控服务绑定
    Context.bindService.implementation = function (intent, conn, flags) {
        // 提取服务信息
        var serviceInfo = "";
        try {
            var component = intent.getComponent();
            if (component) {
                serviceInfo = component.getPackageName() + "/" + component.getClassName();
            } else {
                serviceInfo = "隐式Intent绑定";
            }
            // 提取绑定标志
            var flagsInfo = "";
            if ((flags & 1) != 0) flagsInfo += "BIND_AUTO_CREATE ";
            if ((flags & 128) != 0) flagsInfo += "BIND_NOT_FOREGROUND ";
            if ((flags & 1024) != 0) flagsInfo += "BIND_IMPORTANT ";
        } catch (e) {
            serviceInfo = "无法解析Intent";
        }
        
        console.log('[*] 绑定Service: ' + serviceInfo);
        console.log('    Intent详情: ' + intent);
        console.log('    绑定标志: ' + flags + ' (' + flagsInfo + ')');
        
        // 调用原始方法并返回结果
        return this.bindService(intent, conn, flags);
    };
    
    console.log('[*] Service监控已启动');
}); 