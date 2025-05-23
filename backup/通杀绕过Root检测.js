// 通杀绕过Root检测
Java.perform(function () {
    var File = Java.use('java.io.File');
    File.exists.implementation = function () {
        var path = this.getAbsolutePath();
        if (path.indexOf('su') !== -1 || path.indexOf('busybox') !== -1 || path.indexOf('magisk') !== -1 || path.indexOf('root') !== -1) {
            console.log('[*] Root检测拦截: ' + path + ' (返回false)');
            return false;
        }
        return this.exists();
    };
}); 