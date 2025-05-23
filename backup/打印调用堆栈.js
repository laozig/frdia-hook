// 打印当前调用堆栈
// 作用：获取当前代码执行的调用堆栈，用于分析程序执行流程和定位关键函数。
Java.perform(function () {
    try {
        var Exception = Java.use("java.lang.Exception");
        // 创建异常并获取堆栈信息
        console.log(Exception.$new().getStackTrace().toString());
    } catch (e) {
        console.log('[!] dump_stack error:', e);
    }
}); 