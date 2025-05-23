// 通杀绕过Frida检测
Java.perform(function () {
    var StringCls = Java.use('java.lang.String');
    StringCls.contains.implementation = function (str) {
        if (str && (str.indexOf('frida') !== -1 || str.indexOf('gum-js-loop') !== -1)) {
            console.log('[*] Frida检测拦截: ' + str + ' (返回false)');
            return false;
        }
        return this.contains(str);
    };
    StringCls.indexOf.overload('java.lang.String').implementation = function (str) {
        if (str && (str.indexOf('frida') !== -1 || str.indexOf('gum-js-loop') !== -1)) {
            console.log('[*] Frida检测拦截: ' + str + ' (返回-1)');
            return -1;
        }
        return this.indexOf(str);
    };
}); 