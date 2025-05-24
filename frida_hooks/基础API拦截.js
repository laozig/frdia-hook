/**
 * 基础API拦截脚本
 * 
 * 功能：拦截Android应用中常见的基础API调用
 * 作用：查看应用调用了哪些关键API，帮助理解应用行为
 */

// 等待Java虚拟机加载完成
Java.perform(function() {
    console.log("[*] 基础API拦截脚本已启动");

    /**
     * Toast消息拦截
     * 拦截应用中的Toast提示信息
     */
    var Toast = Java.use("android.widget.Toast");
    Toast.makeText.overload('android.content.Context', 'java.lang.CharSequence', 'int').implementation = function(context, message, duration) {
        console.log("[+] Toast消息: " + message.toString());
        return this.makeText(context, message, duration);
    };

    /**
     * Log日志拦截
     * 拦截应用中的日志输出
     */
    var Log = Java.use("android.util.Log");
    
    // 拦截Log.v()
    Log.v.overload('java.lang.String', 'java.lang.String').implementation = function(tag, message) {
        console.log("[+] Log.v(): " + tag + " -> " + message);
        return this.v(tag, message);
    };
    
    // 拦截Log.d()
    Log.d.overload('java.lang.String', 'java.lang.String').implementation = function(tag, message) {
        console.log("[+] Log.d(): " + tag + " -> " + message);
        return this.d(tag, message);
    };
    
    // 拦截Log.i()
    Log.i.overload('java.lang.String', 'java.lang.String').implementation = function(tag, message) {
        console.log("[+] Log.i(): " + tag + " -> " + message);
        return this.i(tag, message);
    };
    
    // 拦截Log.w()
    Log.w.overload('java.lang.String', 'java.lang.String').implementation = function(tag, message) {
        console.log("[+] Log.w(): " + tag + " -> " + message);
        return this.w(tag, message);
    };
    
    // 拦截Log.e()
    Log.e.overload('java.lang.String', 'java.lang.String').implementation = function(tag, message) {
        console.log("[+] Log.e(): " + tag + " -> " + message);
        return this.e(tag, message);
    };

    /**
     * Intent拦截
     * 拦截应用中的Intent操作，包括启动Activity、Service等
     */
    var Intent = Java.use("android.content.Intent");
    Intent.getStringExtra.implementation = function(name) {
        var value = this.getStringExtra(name);
        console.log("[+] Intent.getStringExtra: " + name + " -> " + value);
        return value;
    };

    /**
     * Activity生命周期拦截
     * 监控Activity的创建、启动、暂停、恢复等生命周期事件
     */
    var Activity = Java.use("android.app.Activity");
    
    Activity.onCreate.overload('android.os.Bundle').implementation = function(bundle) {
        console.log("[+] Activity.onCreate: " + this.getClass().getName());
        return this.onCreate(bundle);
    };
    
    Activity.onStart.implementation = function() {
        console.log("[+] Activity.onStart: " + this.getClass().getName());
        return this.onStart();
    };
    
    Activity.onResume.implementation = function() {
        console.log("[+] Activity.onResume: " + this.getClass().getName());
        return this.onResume();
    };
    
    Activity.onPause.implementation = function() {
        console.log("[+] Activity.onPause: " + this.getClass().getName());
        return this.onPause();
    };
    
    Activity.onStop.implementation = function() {
        console.log("[+] Activity.onStop: " + this.getClass().getName());
        return this.onStop();
    };
    
    Activity.onDestroy.implementation = function() {
        console.log("[+] Activity.onDestroy: " + this.getClass().getName());
        return this.onDestroy();
    };

    /**
     * 按钮点击事件拦截
     * 监控按钮的点击事件
     */
    var View = Java.use("android.view.View");
    View.setOnClickListener.implementation = function(listener) {
        console.log("[+] 设置点击监听器: " + this.toString());
        return this.setOnClickListener(listener);
    };

    /**
     * 系统信息获取拦截
     * 监控应用获取设备信息的行为
     */
    var TelephonyManager = Java.use("android.telephony.TelephonyManager");
    
    // 拦截获取设备ID
    if (TelephonyManager.getDeviceId) {
        TelephonyManager.getDeviceId.overload().implementation = function() {
            var deviceId = this.getDeviceId();
            console.log("[+] 获取设备ID: " + deviceId);
            return deviceId;
        };
    }
    
    // 拦截获取SIM卡序列号
    if (TelephonyManager.getSimSerialNumber) {
        TelephonyManager.getSimSerialNumber.overload().implementation = function() {
            var simSerial = this.getSimSerialNumber();
            console.log("[+] 获取SIM卡序列号: " + simSerial);
            return simSerial;
        };
    }
    
    // 拦截获取IMEI
    if (TelephonyManager.getImei) {
        TelephonyManager.getImei.overload().implementation = function() {
            var imei = this.getImei();
            console.log("[+] 获取IMEI: " + imei);
            return imei;
        };
    }

    /**
     * 剪贴板操作拦截
     * 监控应用对剪贴板的读写操作
     */
    var ClipboardManager = Java.use("android.content.ClipboardManager");
    
    // 拦截剪贴板设置
    if (ClipboardManager.setPrimaryClip) {
        ClipboardManager.setPrimaryClip.implementation = function(clip) {
            console.log("[+] 设置剪贴板内容: " + clip.toString());
            return this.setPrimaryClip(clip);
        };
    }
    
    // 拦截剪贴板获取
    if (ClipboardManager.getPrimaryClip) {
        ClipboardManager.getPrimaryClip.implementation = function() {
            var clip = this.getPrimaryClip();
            console.log("[+] 获取剪贴板内容: " + (clip ? clip.toString() : "null"));
            return clip;
        };
    }

    console.log("[*] 基础API拦截设置完成");
}); 