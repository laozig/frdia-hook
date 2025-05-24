/**
 * SQLite数据库操作拦截脚本
 * 
 * 功能：拦截Android应用中的SQLite数据库操作
 * 作用：监控应用对数据库的读写操作，分析数据存储方式
 * 适用：分析应用数据存储逻辑，敏感信息存储位置
 */

// 等待Java虚拟机加载完成
Java.perform(function() {
    console.log("[*] SQLite数据库操作拦截脚本已启动");

    /**
     * 工具函数：获取调用堆栈
     */
    function getStackTrace() {
        var Exception = Java.use("java.lang.Exception");
        var exception = Exception.$new();
        var stackTrace = exception.getStackTrace();
        exception.$dispose();
        
        var stack = [];
        for (var i = 0; i < stackTrace.length; i++) {
            var element = stackTrace[i];
            var className = element.getClassName();
            var methodName = element.getMethodName();
            var fileName = element.getFileName();
            var lineNumber = element.getLineNumber();
            
            // 过滤掉Frida相关的堆栈
            if (className.indexOf("com.frida") === -1) {
                stack.push(className + "." + methodName + "(" + fileName + ":" + lineNumber + ")");
            }
            
            // 只获取前10个堆栈元素
            if (stack.length >= 10) break;
        }
        
        return stack.join("\n    ");
    }

    /**
     * 工具函数：打印SQL查询参数
     */
    function printSqlArgs(sql, bindArgs) {
        if (!bindArgs) return sql;
        
        try {
            var sqlCopy = String(sql);
            
            // 替换所有?占位符为实际参数值
            for (var i = 0; i < bindArgs.length; i++) {
                var value = bindArgs[i];
                var stringValue;
                
                if (value === null) {
                    stringValue = "NULL";
                } else if (typeof value === "number") {
                    stringValue = value.toString();
                } else if (typeof value === "string") {
                    stringValue = "'" + value + "'";
                } else if (Array.isArray(value)) {
                    stringValue = "[" + value.join(", ") + "]";
                } else {
                    stringValue = "'" + value.toString() + "'";
                }
                
                sqlCopy = sqlCopy.replace("?", stringValue);
            }
            
            return sqlCopy;
        } catch (e) {
            return sql + " [参数解析失败: " + e + "]";
        }
    }

    /**
     * 工具函数：打印Cursor结果
     */
    function printCursorResults(cursor, maxRows) {
        if (!cursor) return "空结果";
        maxRows = maxRows || 10;
        
        try {
            var results = [];
            var columnCount = cursor.getColumnCount();
            var rowCount = cursor.getCount();
            
            // 获取列名
            var columns = [];
            for (var i = 0; i < columnCount; i++) {
                columns.push(cursor.getColumnName(i));
            }
            
            // 获取行数据
            var position = cursor.getPosition();
            cursor.moveToPosition(-1);
            var rowNum = 0;
            
            while (cursor.moveToNext() && rowNum < maxRows) {
                var row = {};
                for (var i = 0; i < columnCount; i++) {
                    var columnName = columns[i];
                    var columnType = cursor.getType(i);
                    var value;
                    
                    // 根据列类型获取值
                    switch (columnType) {
                        case 0: // FIELD_TYPE_NULL
                            value = null;
                            break;
                        case 1: // FIELD_TYPE_INTEGER
                            value = cursor.getLong(i);
                            break;
                        case 2: // FIELD_TYPE_FLOAT
                            value = cursor.getDouble(i);
                            break;
                        case 3: // FIELD_TYPE_STRING
                            value = cursor.getString(i);
                            break;
                        case 4: // FIELD_TYPE_BLOB
                            value = "[BLOB数据]";
                            break;
                        default:
                            value = "[未知类型]";
                    }
                    
                    row[columnName] = value;
                }
                
                results.push(row);
                rowNum++;
            }
            
            // 恢复原始位置
            cursor.moveToPosition(position);
            
            var output = "查询结果 (" + rowCount + " 行, 显示前 " + Math.min(maxRows, rowCount) + " 行):\n";
            output += JSON.stringify(results, null, 2);
            return output;
        } catch (e) {
            return "无法读取结果: " + e;
        }
    }

    /**
     * 一、拦截SQLiteDatabase
     * 这是Android中最常用的数据库操作类
     */
    var SQLiteDatabase = Java.use("android.database.sqlite.SQLiteDatabase");
    
    // 拦截数据库打开
    SQLiteDatabase.openOrCreateDatabase.overload("java.io.File", "android.database.sqlite.SQLiteDatabase$CursorFactory").implementation = function(file, factory) {
        var path = file.getAbsolutePath();
        console.log("\n[+] SQLiteDatabase.openOrCreateDatabase");
        console.log("    数据库路径: " + path);
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        return this.openOrCreateDatabase(file, factory);
    };
    
    SQLiteDatabase.openOrCreateDatabase.overload("java.lang.String", "android.database.sqlite.SQLiteDatabase$CursorFactory", "android.database.DatabaseErrorHandler").implementation = function(path, factory, errorHandler) {
        console.log("\n[+] SQLiteDatabase.openOrCreateDatabase");
        console.log("    数据库路径: " + path);
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        return this.openOrCreateDatabase(path, factory, errorHandler);
    };
    
    // 拦截数据库关闭
    SQLiteDatabase.close.implementation = function() {
        console.log("\n[+] SQLiteDatabase.close");
        console.log("    数据库路径: " + this.getPath());
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        return this.close();
    };
    
    // 拦截查询操作
    SQLiteDatabase.query.overload(
        "[Ljava.lang.String;", "java.lang.String", "[Ljava.lang.String;", "java.lang.String", 
        "java.lang.String", "java.lang.String", "java.lang.String", "java.lang.String", "android.os.CancellationSignal"
    ).implementation = function(tables, selection, selectionArgs, groupBy, having, orderBy, limit, cancellationSignal) {
        console.log("\n[+] SQLiteDatabase.query");
        console.log("    数据库路径: " + this.getPath());
        console.log("    表: " + JSON.stringify(tables));
        console.log("    查询条件: " + selection);
        console.log("    参数: " + JSON.stringify(selectionArgs));
        console.log("    分组: " + groupBy);
        console.log("    分组条件: " + having);
        console.log("    排序: " + orderBy);
        console.log("    限制: " + limit);
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        var cursor = this.query(tables, selection, selectionArgs, groupBy, having, orderBy, limit, cancellationSignal);
        console.log("    " + printCursorResults(cursor));
        
        return cursor;
    };
    
    // 拦截execSQL操作
    SQLiteDatabase.execSQL.overload("java.lang.String").implementation = function(sql) {
        console.log("\n[+] SQLiteDatabase.execSQL");
        console.log("    数据库路径: " + this.getPath());
        console.log("    SQL: " + sql);
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        return this.execSQL(sql);
    };
    
    SQLiteDatabase.execSQL.overload("java.lang.String", "[Ljava.lang.Object;").implementation = function(sql, bindArgs) {
        console.log("\n[+] SQLiteDatabase.execSQL (带参数)");
        console.log("    数据库路径: " + this.getPath());
        console.log("    SQL: " + printSqlArgs(sql, bindArgs));
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        return this.execSQL(sql, bindArgs);
    };
    
    // 拦截insert操作
    SQLiteDatabase.insert.overload("java.lang.String", "java.lang.String", "android.content.ContentValues").implementation = function(table, nullColumnHack, values) {
        console.log("\n[+] SQLiteDatabase.insert");
        console.log("    数据库路径: " + this.getPath());
        console.log("    表: " + table);
        
        // 打印ContentValues
        if (values) {
            var valuesMap = {};
            var keySet = values.keySet();
            var keySetIterator = keySet.iterator();
            
            while (keySetIterator.hasNext()) {
                var key = keySetIterator.next();
                var value = values.get(key);
                valuesMap[key] = value ? value.toString() : "null";
            }
            
            console.log("    值: " + JSON.stringify(valuesMap, null, 2));
        } else {
            console.log("    值: null");
        }
        
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        return this.insert(table, nullColumnHack, values);
    };
    
    // 拦截update操作
    SQLiteDatabase.update.overload("java.lang.String", "android.content.ContentValues", "java.lang.String", "[Ljava.lang.String;").implementation = function(table, values, whereClause, whereArgs) {
        console.log("\n[+] SQLiteDatabase.update");
        console.log("    数据库路径: " + this.getPath());
        console.log("    表: " + table);
        console.log("    条件: " + whereClause);
        console.log("    条件参数: " + JSON.stringify(whereArgs));
        
        // 打印ContentValues
        if (values) {
            var valuesMap = {};
            var keySet = values.keySet();
            var keySetIterator = keySet.iterator();
            
            while (keySetIterator.hasNext()) {
                var key = keySetIterator.next();
                var value = values.get(key);
                valuesMap[key] = value ? value.toString() : "null";
            }
            
            console.log("    更新值: " + JSON.stringify(valuesMap, null, 2));
        } else {
            console.log("    更新值: null");
        }
        
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        return this.update(table, values, whereClause, whereArgs);
    };
    
    // 拦截delete操作
    SQLiteDatabase.delete.overload("java.lang.String", "java.lang.String", "[Ljava.lang.String;").implementation = function(table, whereClause, whereArgs) {
        console.log("\n[+] SQLiteDatabase.delete");
        console.log("    数据库路径: " + this.getPath());
        console.log("    表: " + table);
        console.log("    条件: " + whereClause);
        console.log("    条件参数: " + JSON.stringify(whereArgs));
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        return this.delete(table, whereClause, whereArgs);
    };
    
    // 拦截rawQuery操作
    SQLiteDatabase.rawQuery.overload("java.lang.String", "[Ljava.lang.String;").implementation = function(sql, selectionArgs) {
        console.log("\n[+] SQLiteDatabase.rawQuery");
        console.log("    数据库路径: " + this.getPath());
        console.log("    SQL: " + printSqlArgs(sql, selectionArgs));
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        var cursor = this.rawQuery(sql, selectionArgs);
        console.log("    " + printCursorResults(cursor));
        
        return cursor;
    };

    /**
     * 二、拦截SQLiteOpenHelper
     * 这是Android中常用的数据库帮助类
     */
    var SQLiteOpenHelper = Java.use("android.database.sqlite.SQLiteOpenHelper");
    
    // 拦截getWritableDatabase方法
    SQLiteOpenHelper.getWritableDatabase.implementation = function() {
        console.log("\n[+] SQLiteOpenHelper.getWritableDatabase");
        console.log("    数据库名称: " + this.getDatabaseName());
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        return this.getWritableDatabase();
    };
    
    // 拦截getReadableDatabase方法
    SQLiteOpenHelper.getReadableDatabase.implementation = function() {
        console.log("\n[+] SQLiteOpenHelper.getReadableDatabase");
        console.log("    数据库名称: " + this.getDatabaseName());
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        return this.getReadableDatabase();
    };
    
    // 拦截onCreate方法
    SQLiteOpenHelper.onCreate.implementation = function(db) {
        console.log("\n[+] SQLiteOpenHelper.onCreate");
        console.log("    数据库名称: " + this.getDatabaseName());
        console.log("    数据库路径: " + db.getPath());
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        return this.onCreate(db);
    };
    
    // 拦截onUpgrade方法
    SQLiteOpenHelper.onUpgrade.implementation = function(db, oldVersion, newVersion) {
        console.log("\n[+] SQLiteOpenHelper.onUpgrade");
        console.log("    数据库名称: " + this.getDatabaseName());
        console.log("    数据库路径: " + db.getPath());
        console.log("    旧版本: " + oldVersion);
        console.log("    新版本: " + newVersion);
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        return this.onUpgrade(db, oldVersion, newVersion);
    };

    /**
     * 三、拦截ContentValues
     * 用于数据库插入和更新操作的值容器
     */
    var ContentValues = Java.use("android.content.ContentValues");
    
    // 拦截put方法
    ContentValues.put.overload("java.lang.String", "java.lang.String").implementation = function(key, value) {
        console.log("\n[+] ContentValues.put(String)");
        console.log("    键: " + key);
        console.log("    值: " + value);
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        return this.put(key, value);
    };
    
    ContentValues.put.overload("java.lang.String", "java.lang.Integer").implementation = function(key, value) {
        console.log("\n[+] ContentValues.put(Integer)");
        console.log("    键: " + key);
        console.log("    值: " + value);
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        return this.put(key, value);
    };
    
    ContentValues.put.overload("java.lang.String", "java.lang.Long").implementation = function(key, value) {
        console.log("\n[+] ContentValues.put(Long)");
        console.log("    键: " + key);
        console.log("    值: " + value);
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        return this.put(key, value);
    };
    
    ContentValues.put.overload("java.lang.String", "java.lang.Boolean").implementation = function(key, value) {
        console.log("\n[+] ContentValues.put(Boolean)");
        console.log("    键: " + key);
        console.log("    值: " + value);
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        return this.put(key, value);
    };
    
    ContentValues.put.overload("java.lang.String", "[B").implementation = function(key, value) {
        console.log("\n[+] ContentValues.put(byte[])");
        console.log("    键: " + key);
        console.log("    值: [二进制数据]");
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        return this.put(key, value);
    };

    /**
     * 四、拦截Cursor操作
     * 用于遍历数据库查询结果
     */
    var Cursor = Java.use("android.database.Cursor");
    
    // 拦截moveToFirst方法
    Cursor.moveToFirst.implementation = function() {
        var result = this.moveToFirst();
        console.log("\n[+] Cursor.moveToFirst");
        console.log("    结果: " + result);
        
        if (result) {
            try {
                var columnNames = this.getColumnNames();
                console.log("    列名: " + JSON.stringify(columnNames));
            } catch (e) {}
        }
        
        return result;
    };
    
    // 拦截moveToNext方法
    Cursor.moveToNext.implementation = function() {
        var result = this.moveToNext();
        
        if (result) {
            try {
                var position = this.getPosition();
                if (position <= 5) { // 只记录前几条数据，避免日志过多
                    console.log("\n[+] Cursor.moveToNext");
                    console.log("    位置: " + position);
                    
                    // 尝试获取当前行的数据
                    var columnCount = this.getColumnCount();
                    var rowData = {};
                    
                    for (var i = 0; i < columnCount; i++) {
                        var columnName = this.getColumnName(i);
                        var columnType = this.getType(i);
                        var value;
                        
                        switch (columnType) {
                            case 0: // FIELD_TYPE_NULL
                                value = null;
                                break;
                            case 1: // FIELD_TYPE_INTEGER
                                value = this.getLong(i);
                                break;
                            case 2: // FIELD_TYPE_FLOAT
                                value = this.getDouble(i);
                                break;
                            case 3: // FIELD_TYPE_STRING
                                value = this.getString(i);
                                break;
                            case 4: // FIELD_TYPE_BLOB
                                value = "[BLOB数据]";
                                break;
                            default:
                                value = "[未知类型]";
                        }
                        
                        rowData[columnName] = value;
                    }
                    
                    console.log("    数据: " + JSON.stringify(rowData));
                }
            } catch (e) {}
        }
        
        return result;
    };
    
    // 拦截getString方法
    Cursor.getString.implementation = function(columnIndex) {
        var result = this.getString(columnIndex);
        
        try {
            var position = this.getPosition();
            if (position <= 5) { // 只记录前几条数据，避免日志过多
                var columnName = this.getColumnName(columnIndex);
                console.log("\n[+] Cursor.getString");
                console.log("    位置: " + position);
                console.log("    列名: " + columnName);
                console.log("    列索引: " + columnIndex);
                console.log("    值: " + result);
            }
        } catch (e) {}
        
        return result;
    };

    /**
     * 五、拦截Room数据库操作（如果使用）
     */
    try {
        var RoomDatabase = Java.use("androidx.room.RoomDatabase");
        
        // 拦截查询编译器
        var RoomSQLiteQuery = Java.use("androidx.room.RoomSQLiteQuery");
        RoomSQLiteQuery.acquire.implementation = function(sql, argCount) {
            console.log("\n[+] Room.acquire");
            console.log("    SQL: " + sql);
            console.log("    参数数量: " + argCount);
            console.log("    调用堆栈:\n    " + getStackTrace());
            
            return this.acquire(sql, argCount);
        };
        
        // 拦截绑定参数方法
        RoomSQLiteQuery.bindString.implementation = function(index, value) {
            console.log("\n[+] Room.bindString");
            console.log("    索引: " + index);
            console.log("    值: " + value);
            
            return this.bindString(index, value);
        };
        
        RoomSQLiteQuery.bindLong.implementation = function(index, value) {
            console.log("\n[+] Room.bindLong");
            console.log("    索引: " + index);
            console.log("    值: " + value);
            
            return this.bindLong(index, value);
        };
        
        console.log("[+] Room数据库拦截设置完成");
    } catch (e) {
        console.log("[-] Room数据库可能未被使用: " + e);
    }

    /**
     * 六、拦截Realm数据库操作（如果使用）
     */
    try {
        var Realm = Java.use("io.realm.Realm");
        
        // 拦截获取Realm实例
        Realm.getInstance.overload("io.realm.RealmConfiguration").implementation = function(config) {
            console.log("\n[+] Realm.getInstance");
            console.log("    配置: " + config);
            console.log("    调用堆栈:\n    " + getStackTrace());
            
            return this.getInstance(config);
        };
        
        // 拦截where查询
        Realm.where.implementation = function(clazz) {
            console.log("\n[+] Realm.where");
            console.log("    类: " + clazz.getName());
            console.log("    调用堆栈:\n    " + getStackTrace());
            
            return this.where(clazz);
        };
        
        // 拦截插入/更新操作
        Realm.insert.implementation = function(object) {
            console.log("\n[+] Realm.insert");
            console.log("    对象: " + object.toString());
            console.log("    类: " + object.getClass().getName());
            console.log("    调用堆栈:\n    " + getStackTrace());
            
            return this.insert(object);
        };
        
        Realm.insertOrUpdate.implementation = function(object) {
            console.log("\n[+] Realm.insertOrUpdate");
            console.log("    对象: " + object.toString());
            console.log("    类: " + object.getClass().getName());
            console.log("    调用堆栈:\n    " + getStackTrace());
            
            return this.insertOrUpdate(object);
        };
        
        console.log("[+] Realm数据库拦截设置完成");
    } catch (e) {
        console.log("[-] Realm数据库可能未被使用: " + e);
    }

    console.log("[*] SQLite数据库操作拦截设置完成");
}); 