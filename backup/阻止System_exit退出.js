// Hook System.exit，防止应用退出
Java.perform(function () {
    var System = Java.use("java.lang.System");
    System.exit.implementation = function (code) {
        console.log("[*] System.exit called, code: " + code + " (blocked)");
        // 不调用原始方法，阻止退出
    };
}); 