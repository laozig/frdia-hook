// dump_动态注册native.js
Interceptor.attach(Module.findExportByName(null, 'RegisterNatives'), {
    onEnter: function (args) {
        var env = args[0];
        var clazz = args[1];
        var methods = args[2];
        var count = args[3].toInt32();
        console.log('[*] RegisterNatives 动态注册native方法, 数量: ' + count);
        // 这里可进一步dump methods结构体内容
    }
}); 