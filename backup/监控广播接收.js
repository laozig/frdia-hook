// 监控BroadcastReceiver注册与接收
Java.perform(function () {
    var Context = Java.use('android.content.Context');
    Context.registerReceiver.overload('android.content.BroadcastReceiver', 'android.content.IntentFilter').implementation = function (receiver, filter) {
        console.log('[*] 注册广播接收器: ' + receiver + ', 过滤器: ' + filter);
        return this.registerReceiver(receiver, filter);
    };
    var BroadcastReceiver = Java.use('android.content.BroadcastReceiver');
    BroadcastReceiver.onReceive.implementation = function (context, intent) {
        console.log('[*] 接收到广播: ' + intent.getAction());
        return this.onReceive(context, intent);
    };
}); 