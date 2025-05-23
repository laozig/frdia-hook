// 通杀绕过沙箱检测
Java.perform(function () {
    var System = Java.use('java.lang.System');
    System.getProperty.overload('java.lang.String').implementation = function (key) {
        if (key && (key.indexOf('virtualapp') !== -1 || key.indexOf('sandbox') !== -1 || key.indexOf('isolate') !== -1)) {
            console.log('[*] 沙箱检测拦截: ' + key + ' (返回空)');
            return '';
        }
        return this.getProperty(key);
    };
}); 