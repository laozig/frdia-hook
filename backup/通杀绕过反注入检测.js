// 通杀绕过反注入检测
Java.perform(function () {
    var StringCls = Java.use('java.lang.String');
    StringCls.indexOf.overload('java.lang.String').implementation = function (str) {
        if (str && (str.indexOf('substrate') !== -1 || str.indexOf('inject') !== -1)) {
            console.log('[*] 反注入检测拦截: ' + str + ' (返回-1)');
            return -1;
        }
        return this.indexOf(str);
    };
}); 