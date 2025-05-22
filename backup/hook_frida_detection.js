// Hook 反Frida检测，绕过常见 Frida 检测方法
Java.perform(function () {
    var String = Java.use('java.lang.String');
    String.contains.implementation = function (str) {
        if (str && (str.indexOf('frida') !== -1 || str.indexOf('gum-js-loop') !== -1)) {
            console.log("[*] String.contains called for Frida detection: " + str + " (return false)");
            return false;
        }
        return this.contains(str);
    };
}); 