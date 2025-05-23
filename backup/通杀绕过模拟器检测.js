// 通杀绕过模拟器检测
Java.perform(function () {
    var System = Java.use('java.lang.System');
    System.getProperty.overload('java.lang.String').implementation = function (key) {
        if (key && (key.indexOf('vbox') !== -1 || key.indexOf('qemu') !== -1 || key.indexOf('genymotion') !== -1 || key.indexOf('ro.product') !== -1)) {
            console.log('[*] 模拟器检测拦截: ' + key + ' (返回空)');
            return '';
        }
        return this.getProperty(key);
    };
}); 