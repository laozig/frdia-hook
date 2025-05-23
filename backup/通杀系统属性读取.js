// 通杀系统属性读取
Java.perform(function () {
    var System = Java.use('java.lang.System');
    System.getProperty.overload('java.lang.String').implementation = function (key) {
        console.log('[*] System.getProperty 读取: ' + key);
        return this.getProperty(key);
    };
});
Interceptor.attach(Module.findExportByName('libc.so', '__system_property_get'), {
    onEnter: function (args) {
        var key = args[0].readCString();
        console.log('[*] __system_property_get 读取: ' + key);
    },
    onLeave: function (retval) {}
}); 