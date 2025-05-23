// 通杀环境变量读取
Java.perform(function () {
    var System = Java.use('java.lang.System');
    System.getenv.overload('java.lang.String').implementation = function (key) {
        var value = this.getenv(key);
        console.log('[*] System.getenv 读取: ' + key + ' = ' + value);
        return value;
    };
}); 