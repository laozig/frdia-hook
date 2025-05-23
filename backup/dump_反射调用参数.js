// dump_反射调用参数.js
Java.perform(function () {
    var Method = Java.use('java.lang.reflect.Method');
    Method.invoke.implementation = function (obj, args) {
        console.log('[*] 反射调用: ' + this.getName() + ' 参数: ' + args);
        var ret = this.invoke(obj, args);
        console.log('[*] 反射调用返回: ' + ret);
        return ret;
    };
}); 