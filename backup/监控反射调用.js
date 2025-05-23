// 监控反射调用
Java.perform(function () {
    var Method = Java.use('java.lang.reflect.Method');
    Method.invoke.implementation = function (obj, args) {
        console.log('[*] 反射调用: ' + this.getName());
        return this.invoke(obj, args);
    };
}); 