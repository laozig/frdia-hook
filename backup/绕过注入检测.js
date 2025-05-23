// Hook 反注入检测，绕过常见注入检测方法
// 作用：拦截字符串查找，绕过对 xposed、substrate、frida 等注入框架的检测。
Java.perform(function () {
    try {
        var StringCls = Java.use('java.lang.String');
        StringCls.indexOf.overload('java.lang.String').implementation = function (str) {
            // 检查是否为注入检测关键字
            if (str && (str.indexOf('xposed') !== -1 || str.indexOf('substrate') !== -1 || str.indexOf('frida') !== -1)) {
                console.log("[*] String.indexOf called for inject detection: " + str + " (return -1)");
                return -1;
            }
            return this.indexOf(str);
        };
    } catch (e) {
        console.log('[!] hook_inject_detection error:', e);
    }
}); 