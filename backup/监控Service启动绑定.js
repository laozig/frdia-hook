// 监控Service启动与绑定
Java.perform(function () {
    var Context = Java.use('android.content.Context');
    Context.startService.implementation = function (intent) {
        console.log('[*] 启动Service: ' + intent);
        return this.startService(intent);
    };
    Context.bindService.implementation = function (intent, conn, flags) {
        console.log('[*] 绑定Service: ' + intent);
        return this.bindService(intent, conn, flags);
    };
}); 