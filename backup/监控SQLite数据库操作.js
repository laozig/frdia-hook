/*
 * 脚本名称：监控SQLite数据库操作.js
 * 功能描述：监控应用对SQLite数据库的增删改查操作
 * 
 * 适用场景：
 *   - 分析应用的数据存储结构和逻辑
 *   - 追踪应用对敏感数据的处理流程
 *   - 发现应用存储的关键业务数据
 *   - 调试数据库相关问题
 *   - 分析应用的缓存策略和本地数据管理
 *
 * 使用方法：
 *   1. frida -U -f 目标应用包名 -l 监控SQLite数据库操作.js --no-pause
 *   2. 或者 frida -U --attach-pid 目标进程PID -l 监控SQLite数据库操作.js
 *   3. 操作应用，观察控制台输出的数据库操作信息
 *
 * 启动方式说明：
 *   - -U: 使用USB连接的设备
 *   - -f: 指定以spawn方式启动的应用包名
 *   - --attach-pid: 附加到已运行的进程
 *   - --no-pause: 注入后不暂停应用执行
 *
 * 工作原理：
 *   Hook android.database.sqlite.SQLiteDatabase类的增删改查方法，包括insert、update、delete和query。
 *   当应用执行数据库操作时，脚本会拦截这些调用并记录相关信息，如操作的表名等，
 *   从而揭示应用的数据存储结构和处理逻辑。
 *
 * 注意事项：
 *   - 可以扩展脚本以记录更详细的参数信息，如插入的值、查询条件等
 *   - 数据库文件通常位于/data/data/包名/databases/目录下
 *   - 某些应用可能使用加密数据库或自定义存储方式
 *   - 对于Room、GreenDAO等ORM框架，底层仍使用SQLiteDatabase，可以被此脚本监控
 *   - 可以结合adb命令导出数据库文件进行离线分析
 */

// 监控SQLite数据库操作
Java.perform(function () {
    var SQLiteDatabase = Java.use('android.database.sqlite.SQLiteDatabase');
    
    // 监控插入操作
    SQLiteDatabase.insert.implementation = function (table, nullColumnHack, values) {
        console.log('[*] SQLite 插入: ' + table);
        return this.insert(table, nullColumnHack, values);
    };
    
    // 监控更新操作
    SQLiteDatabase.update.implementation = function (table, values, whereClause, whereArgs) {
        console.log('[*] SQLite 更新: ' + table);
        return this.update(table, values, whereClause, whereArgs);
    };
    
    // 监控删除操作
    SQLiteDatabase.delete.implementation = function (table, whereClause, whereArgs) {
        console.log('[*] SQLite 删除: ' + table);
        return this.delete(table, whereClause, whereArgs);
    };
    
    // 监控查询操作
    SQLiteDatabase.query.overload('[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', 'java.lang.String').implementation = function (projection, selection, selectionArgs, groupBy, having, orderBy, limit) {
        console.log('[*] SQLite 查询');
        return this.query(projection, selection, selectionArgs, groupBy, having, orderBy, limit);
    };
}); 