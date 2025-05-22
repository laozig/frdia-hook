// Hook 日志输出，监控和可选阻断日志（Log.d、Log.e、Log.i、Log.w、Log.v）
// 作用：监控所有日志输出内容，可用于分析日志或阻断日志输出，防止日志泄露敏感信息。
Java.perform(function () {
    try {
        var Log = Java.use('android.util.Log');
        ['d', 'e', 'i', 'w', 'v'].forEach(function (level) {
            Log[level].overloads.forEach(function (overload) {
                overload.implementation = function () {
                    var args = Array.prototype.slice.call(arguments);
                    // 输出日志内容
                    console.log('[*] Log.' + level + ' called:', JSON.stringify(args));
                    // return 0; // 若需阻断日志输出，取消注释
                    return overload.apply(this, arguments);
                };
            });
        });
    } catch (e) {
        console.log('[!] hook_log_methods error:', e);
    }
}); 