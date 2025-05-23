// 监控ContentProvider的访问
Java.perform(function () {
    var ContentResolver = Java.use('android.content.ContentResolver');
    ContentResolver.query.overload('android.net.Uri', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String').implementation = function (uri, projection, selection, selectionArgs, sortOrder) {
        console.log('[*] ContentProvider 查询: ' + uri);
        return this.query(uri, projection, selection, selectionArgs, sortOrder);
    };
    ContentResolver.insert.implementation = function (uri, values) {
        console.log('[*] ContentProvider 插入: ' + uri);
        return this.insert(uri, values);
    };
    ContentResolver.delete.implementation = function (uri, selection, selectionArgs) {
        console.log('[*] ContentProvider 删除: ' + uri);
        return this.delete(uri, selection, selectionArgs);
    };
    ContentResolver.update.implementation = function (uri, values, selection, selectionArgs) {
        console.log('[*] ContentProvider 更新: ' + uri);
        return this.update(uri, values, selection, selectionArgs);
    };
}); 