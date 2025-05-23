// 通杀绕过多开检测
Java.perform(function () {
    var Application = Java.use('android.app.Application');
    Application.getPackageName.implementation = function () {
        var pkg = this.getPackageName();
        if (pkg && (pkg.indexOf('clone') !== -1 || pkg.indexOf('multi') !== -1)) {
            console.log('[*] 多开检测拦截: ' + pkg + ' (返回主包名)');
            return 'com.example.app';
        }
        return pkg;
    };
    var Process = Java.use('android.os.Process');
    Process.myPid.implementation = function () {
        var pid = this.myPid();
        console.log('[*] 多开检测拦截: myPid = ' + pid);
        return pid;
    };
}); 