// Hook Java 层的字段读写
// 作用：监控指定类的字段读写操作，获取字段的读取和修改值，用于追踪敏感数据。
Java.perform(function () {
    try {
        var TargetClass = Java.use("com.example.app.TargetClass");
        
        // 使用 Object.defineProperty 重新定义字段的读写操作
        Object.defineProperty(TargetClass, "targetField", {
            set: function (val) {
                console.log("[*] targetField set: " + val);
                this._targetField = val; // 保存原始值
            },
            get: function () {
                console.log("[*] targetField get: " + this._targetField);
                return this._targetField; // 返回原始值
            }
        });
    } catch (e) {
        console.log('[!] hook_field error:', e);
    }
}); 