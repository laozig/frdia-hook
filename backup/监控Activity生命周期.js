// Hook Activity 的 onResume 和 onPause 方法，监控页面切换
Java.perform(function () {
    try {
        var Activity = Java.use("android.app.Activity");
        Activity.onResume.implementation = function () {
            console.log("[*] Activity.onResume: " + this.getClass().getName());
            this.onResume();
        };
        Activity.onPause.implementation = function () {
            console.log("[*] Activity.onPause: " + this.getClass().getName());
            this.onPause();
        };
    } catch (e) {
        console.log('[!] hook_activity_lifecycle error:', e);
    }
}); 