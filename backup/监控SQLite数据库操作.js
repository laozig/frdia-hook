// 监控SQLite数据库操作
Java.perform(function () {
    var SQLiteDatabase = Java.use('android.database.sqlite.SQLiteDatabase');
    SQLiteDatabase.insert.implementation = function (table, nullColumnHack, values) {
        console.log('[*] SQLite 插入: ' + table);
        return this.insert(table, nullColumnHack, values);
    };
    SQLiteDatabase.update.implementation = function (table, values, whereClause, whereArgs) {
        console.log('[*] SQLite 更新: ' + table);
        return this.update(table, values, whereClause, whereArgs);
    };
    SQLiteDatabase.delete.implementation = function (table, whereClause, whereArgs) {
        console.log('[*] SQLite 删除: ' + table);
        return this.delete(table, whereClause, whereArgs);
    };
    SQLiteDatabase.query.overload('[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', 'java.lang.String').implementation = function (projection, selection, selectionArgs, groupBy, having, orderBy, limit) {
        console.log('[*] SQLite 查询');
        return this.query(projection, selection, selectionArgs, groupBy, having, orderBy, limit);
    };
}); 