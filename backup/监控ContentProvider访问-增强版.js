/*
 * 脚本名称：监控ContentProvider访问-增强版.js
 * 功能：全面监控Android应用的ContentProvider访问，跟踪数据读写操作和权限检查
 * 适用场景：
 *   - 分析应用数据访问行为
 *   - 检测潜在的数据泄露
 *   - 理解数据存储机制
 *   - 分析ContentProvider的查询模式
 * 使用方法：
 *   1. frida -U -f 包名 -l 监控ContentProvider访问-增强版.js --no-pause
 *   2. 查看控制台输出，分析ContentProvider访问行为
 * 启动方式说明：
 *   - -U 代表使用USB连接的设备
 *   - -f 代表以spawn方式启动目标应用
 *   - --no-pause 指示Frida不要暂停应用执行
 * 支持特性：
 *   - 监控所有ContentProvider操作（查询、插入、更新、删除）
 *   - 分析传输的数据内容
 *   - 识别敏感URI访问
 *   - 调用堆栈追踪
 *   - 访问统计和统计分析
 *   - 支持查询参数的详细显示
 */

(function() {
    // 全局配置
    var config = {
        logLevel: 2,                // 0:关闭 1:错误 2:基本信息 3:详细
        printStack: true,           // 是否打印调用堆栈
        maxStackDepth: 5,           // 最大堆栈深度
        showQueryParameters: true,  // 是否显示查询参数
        maxValuesToShow: 5,         // 最大显示的ContentValues键值对数
        detectSensitiveData: true,  // 检测敏感数据
        monitorBinders: false,      // 是否监控低级Binder操作（高级选项）
        filterSystemAccess: true    // 过滤系统应用的访问
    };
    
    // 统计信息
    var stats = {
        queries: 0,
        inserts: 0,
        updates: 0,
        deletes: 0,
        byUri: {}
    };
    
    // 敏感URI列表
    var sensitiveUris = [
        "content://sms",
        "content://contacts",
        "content://call_log",
        "content://browser/bookmarks",
        "content://media/external",
        "content://com.android.calendar",
        "content://downloads",
        "content://user_dictionary"
    ];
    
    // 辅助函数：日志输出
    function log(level, message) {
        if (level <= config.logLevel) {
            var prefix = "";
            switch (level) {
                case 1: prefix = "[!] "; break;
                case 2: prefix = "[*] "; break;
                case 3: prefix = "[+] "; break;
            }
            console.log(prefix + message);
        }
    }
    
    // 辅助函数：获取调用堆栈
    function getStackTrace() {
        if (!config.printStack) return "";
        
        try {
            var exception = Java.use("java.lang.Exception").$new();
            var stackElements = exception.getStackTrace();
            var limit = Math.min(stackElements.length, config.maxStackDepth);
            
            var stack = "\n    调用堆栈:";
            for (var i = 0; i < limit; i++) {
                var element = stackElements[i];
                var className = element.getClassName();
                
                // 过滤掉ContentResolver和系统类
                if (config.filterSystemAccess && 
                    (className.indexOf("android.content.ContentResolver") === 0 || 
                     className.indexOf("com.android.internal") === 0)) {
                    continue;
                }
                
                stack += "\n        " + className + "." + 
                         element.getMethodName() + "(" + 
                         (element.getFileName() != null ? element.getFileName() : "Unknown Source") + ":" + 
                         element.getLineNumber() + ")";
            }
            return stack;
        } catch (e) {
            return "\n    调用堆栈获取失败: " + e;
        }
    }
    
    // 辅助函数：检查是否为敏感URI
    function isSensitiveUri(uri) {
        if (!uri) return false;
        
        var uriStr = uri.toString();
        for (var i = 0; i < sensitiveUris.length; i++) {
            if (uriStr.indexOf(sensitiveUris[i]) === 0) {
                return true;
            }
        }
        return false;
    }
    
    // 辅助函数：格式化ContentValues对象
    function formatContentValues(values) {
        if (!values) return "null";
        
        try {
            var keySet = values.keySet();
            var keysArray = [];
            var iterator = keySet.iterator();
            while (iterator.hasNext()) {
                keysArray.push(iterator.next().toString());
            }
            
            var result = "";
            var count = 0;
            var limit = Math.min(keysArray.length, config.maxValuesToShow);
            
            for (var i = 0; i < limit; i++) {
                var key = keysArray[i];
                try {
                    var value = values.get(key);
                    if (value !== null) {
                        result += "\n        " + key + " = " + value.toString();
                    } else {
                        result += "\n        " + key + " = null";
                    }
                    count++;
                } catch (e) {
                    result += "\n        " + key + " = <无法读取>";
                }
            }
            
            // 如果有更多键值对
            if (keysArray.length > config.maxValuesToShow) {
                result += "\n        ... (共 " + keysArray.length + " 个字段)";
            }
            
            return result;
        } catch (e) {
            return "<解析ContentValues失败: " + e + ">";
        }
    }
    
    // 辅助函数：格式化选择条件
    function formatSelection(selection, selectionArgs) {
        if (!selection) return "无";
        
        var result = selection;
        
        // 如果有选择参数，尝试格式化查询语句
        if (selectionArgs && selectionArgs.length > 0) {
            result += " [参数: ";
            for (var i = 0; i < selectionArgs.length; i++) {
                if (i > 0) result += ", ";
                result += "'" + selectionArgs[i] + "'";
            }
            result += "]";
        }
        
        return result;
    }
    
    // 辅助函数：格式化投影字段
    function formatProjection(projection) {
        if (!projection) return "所有字段";
        
        try {
            var fields = [];
            for (var i = 0; i < projection.length; i++) {
                fields.push(projection[i]);
            }
            return fields.join(", ");
        } catch (e) {
            return "<解析投影字段失败: " + e + ">";
        }
    }
    
    // 辅助函数：更新URI统计信息
    function updateUriStats(uri, operation) {
        var uriStr = uri.toString();
        
        if (!stats.byUri[uriStr]) {
            stats.byUri[uriStr] = {
                query: 0,
                insert: 0,
                update: 0,
                delete: 0
            };
        }
        
        stats.byUri[uriStr][operation]++;
    }
    
    // 辅助函数：分析查询结果
    function analyzeQueryResult(cursor) {
        if (!cursor || cursor.getCount() === 0) return "无结果";
        
        try {
            var count = cursor.getCount();
            var columns = cursor.getColumnCount();
            
            // 保存当前位置
            var position = cursor.getPosition();
            
            var sample = "";
            // 移动到第一行并读取示例数据
            if (cursor.moveToFirst()) {
                var rowSample = "\n        行1: {";
                
                // 限制显示的列数
                var colLimit = Math.min(columns, 3);
                for (var i = 0; i < colLimit; i++) {
                    try {
                        var colName = cursor.getColumnName(i);
                        var colValue;
                        
                        // 尝试根据列类型获取值
                        var type = cursor.getType(i);
                        switch (type) {
                            case 0: // FIELD_TYPE_NULL
                                colValue = "null";
                                break;
                            case 1: // FIELD_TYPE_INTEGER
                                colValue = cursor.getLong(i).toString();
                                break;
                            case 2: // FIELD_TYPE_FLOAT
                                colValue = cursor.getFloat(i).toString();
                                break;
                            case 3: // FIELD_TYPE_STRING
                                colValue = "'" + cursor.getString(i) + "'";
                                break;
                            case 4: // FIELD_TYPE_BLOB
                                colValue = "<BLOB>";
                                break;
                            default:
                                colValue = "<未知类型>";
                        }
                        
                        if (i > 0) rowSample += ", ";
                        rowSample += colName + ": " + colValue;
                    } catch (e) {
                        if (i > 0) rowSample += ", ";
                        rowSample += "列" + i + ": <访问错误>";
                    }
                }
                
                if (columns > 3) {
                    rowSample += ", ... (共" + columns + "列)";
                }
                
                rowSample += "}";
                sample += rowSample;
                
                // 如果有多行，添加提示
                if (count > 1) {
                    sample += "\n        ... (共" + count + "行)";
                }
            }
            
            // 恢复原来的位置
            cursor.moveToPosition(position);
            
            return "查询结果: " + count + "行, " + columns + "列" + sample;
        } catch (e) {
            return "查询结果: " + cursor.getCount() + "行 (无法读取详情: " + e + ")";
        }
    }

    Java.perform(function() {
        // 监控ContentResolver的主要操作
        var ContentResolver = Java.use("android.content.ContentResolver");
        
        // 1. 监控查询操作
        var queryOverloads = [
            ContentResolver.query.overload('android.net.Uri', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String'),
            ContentResolver.query.overload('android.net.Uri', '[Ljava.lang.String;', 'android.os.Bundle', 'android.os.CancellationSignal')
        ];
        
        queryOverloads[0].implementation = function(uri, projection, selection, selectionArgs, sortOrder) {
            stats.queries++;
            updateUriStats(uri, "query");
            
            var sensitive = isSensitiveUri(uri);
            var prefix = sensitive ? "[!] " : "[*] ";
            
            log(sensitive ? 1 : 2, prefix + "ContentProvider查询: " + uri);
            
            if (config.showQueryParameters) {
                log(2, "    投影字段: " + formatProjection(projection));
                log(2, "    查询条件: " + formatSelection(selection, selectionArgs));
                if (sortOrder) log(2, "    排序: " + sortOrder);
            }
            
            // 执行原始查询
            var cursor = this.query(uri, projection, selection, selectionArgs, sortOrder);
            
            // 分析查询结果
            if (cursor) {
                log(2, "    " + analyzeQueryResult(cursor));
            } else {
                log(2, "    查询结果: null");
            }
            
            if (config.printStack) {
                log(3, getStackTrace());
            }
            
            return cursor;
        };
        
        // 处理API 26+的新查询方法
        try {
            queryOverloads[1].implementation = function(uri, projection, queryArgs, cancellationSignal) {
                stats.queries++;
                updateUriStats(uri, "query");
                
                var sensitive = isSensitiveUri(uri);
                var prefix = sensitive ? "[!] " : "[*] ";
                
                log(sensitive ? 1 : 2, prefix + "ContentProvider查询(Bundle): " + uri);
                
                if (queryArgs) {
                    try {
                        log(3, "    查询参数Bundle: " + queryArgs.toString());
                    } catch (e) {}
                }
                
                // 执行原始查询
                var cursor = this.query(uri, projection, queryArgs, cancellationSignal);
                
                // 分析查询结果
                if (cursor) {
                    log(2, "    " + analyzeQueryResult(cursor));
                } else {
                    log(2, "    查询结果: null");
                }
                
                if (config.printStack) {
                    log(3, getStackTrace());
                }
                
                return cursor;
            };
        } catch (e) {
            // 可能在较老版本的Android上不支持
        }
        
        // 2. 监控插入操作
        ContentResolver.insert.implementation = function(uri, values) {
            stats.inserts++;
            updateUriStats(uri, "insert");
            
            var sensitive = isSensitiveUri(uri);
            var prefix = sensitive ? "[!] " : "[*] ";
            
            log(sensitive ? 1 : 2, prefix + "ContentProvider插入: " + uri);
            
            if (values) {
                log(2, "    插入数据:" + formatContentValues(values));
            }
            
            // 执行原始插入
            var result = this.insert(uri, values);
            
            if (result) {
                log(2, "    插入结果URI: " + result.toString());
            } else {
                log(2, "    插入失败");
            }
            
            if (config.printStack) {
                log(3, getStackTrace());
            }
            
            return result;
        };
        
        // 3. 监控更新操作
        ContentResolver.update.implementation = function(uri, values, selection, selectionArgs) {
            stats.updates++;
            updateUriStats(uri, "update");
            
            var sensitive = isSensitiveUri(uri);
            var prefix = sensitive ? "[!] " : "[*] ";
            
            log(sensitive ? 1 : 2, prefix + "ContentProvider更新: " + uri);
            
            if (values) {
                log(2, "    更新数据:" + formatContentValues(values));
            }
            
            log(2, "    更新条件: " + formatSelection(selection, selectionArgs));
            
            // 执行原始更新
            var count = this.update(uri, values, selection, selectionArgs);
            
            log(2, "    更新行数: " + count);
            
            if (config.printStack) {
                log(3, getStackTrace());
            }
            
            return count;
        };
        
        // 4. 监控删除操作
        ContentResolver.delete.implementation = function(uri, selection, selectionArgs) {
            stats.deletes++;
            updateUriStats(uri, "delete");
            
            var sensitive = isSensitiveUri(uri);
            var prefix = sensitive ? "[!] " : "[*] ";
            
            log(sensitive ? 1 : 2, prefix + "ContentProvider删除: " + uri);
            log(2, "    删除条件: " + formatSelection(selection, selectionArgs));
            
            // 执行原始删除
            var count = this.delete(uri, selection, selectionArgs);
            
            log(2, "    删除行数: " + count);
            
            if (config.printStack) {
                log(3, getStackTrace());
            }
            
            return count;
        };
        
        // 5. 可选：监控call操作
        try {
            ContentResolver.call.overload(
                'android.net.Uri', 
                'java.lang.String', 
                'java.lang.String', 
                'android.os.Bundle'
            ).implementation = function(uri, method, arg, extras) {
                var sensitive = isSensitiveUri(uri);
                var prefix = sensitive ? "[!] " : "[*] ";
                
                log(sensitive ? 1 : 2, prefix + "ContentProvider.call: " + uri);
                log(2, "    方法: " + method + ", 参数: " + arg);
                
                if (extras) {
                    try {
                        var keysIterator = extras.keySet().iterator();
                        var extrasInfo = [];
                        while (keysIterator.hasNext()) {
                            var key = keysIterator.next().toString();
                            extrasInfo.push(key);
                        }
                        if (extrasInfo.length > 0) {
                            log(3, "    Bundle包含键: " + extrasInfo.join(", "));
                        }
                    } catch (e) {}
                }
                
                // 执行原始call方法
                var result = this.call(uri, method, arg, extras);
                
                if (result) {
                    log(2, "    调用返回Bundle: " + result.toString());
                } else {
                    log(2, "    调用无返回值");
                }
                
                if (config.printStack) {
                    log(3, getStackTrace());
                }
                
                return result;
            };
        } catch (e) {
            // 某些Android版本可能不支持此重载
        }
        
        // 6. 可选：监控批量操作
        try {
            var ContentProviderOperation = Java.use("android.content.ContentProviderOperation");
            
            // 监控操作构建器
            ContentProviderOperation.newInsert.implementation = function(uri) {
                var sensitive = isSensitiveUri(uri);
                log(3, (sensitive ? "[!]" : "[+]") + " 创建ContentProviderOperation.newInsert: " + uri);
                return this.newInsert(uri);
            };
            
            ContentProviderOperation.newUpdate.implementation = function(uri) {
                var sensitive = isSensitiveUri(uri);
                log(3, (sensitive ? "[!]" : "[+]") + " 创建ContentProviderOperation.newUpdate: " + uri);
                return this.newUpdate(uri);
            };
            
            ContentProviderOperation.newDelete.implementation = function(uri) {
                var sensitive = isSensitiveUri(uri);
                log(3, (sensitive ? "[!]" : "[+]") + " 创建ContentProviderOperation.newDelete: " + uri);
                return this.newDelete(uri);
            };
            
            // 监控批量操作执行
            var ContentResolver_applyBatch = ContentResolver.applyBatch;
            if (ContentResolver_applyBatch) {
                ContentResolver_applyBatch.implementation = function(authority, operations) {
                    log(2, "[*] 执行批量操作: " + authority);
                    log(2, "    操作数量: " + operations.size());
                    
                    if (config.printStack) {
                        log(3, getStackTrace());
                    }
                    
                    return this.applyBatch(authority, operations);
                };
            }
        } catch (e) {
            log(1, "监控ContentProviderOperation失败: " + e);
        }
        
        // 7. 如果启用，监控底层Binder操作
        if (config.monitorBinders) {
            try {
                var IContentProvider = Java.use("android.content.IContentProvider");
                
                if (IContentProvider.query) {
                    IContentProvider.query.overload(
                        'java.lang.String',
                        'android.net.Uri',
                        '[Ljava.lang.String;',
                        'java.lang.String',
                        '[Ljava.lang.String;',
                        'java.lang.String',
                        'android.os.ICancellationSignal'
                    ).implementation = function(callingPkg, uri, projection, selection, selectionArgs, sortOrder, cancellationSignal) {
                        log(3, "[+] IContentProvider.query Binder调用: " + uri + " (来自包: " + callingPkg + ")");
                        return this.query(callingPkg, uri, projection, selection, selectionArgs, sortOrder, cancellationSignal);
                    };
                }
            } catch (e) {
                log(1, "监控IContentProvider失败: " + e);
            }
        }
        
        // 定期输出统计信息
        setInterval(function() {
            if (stats.queries === 0 && stats.inserts === 0 && stats.updates === 0 && stats.deletes === 0) return;
            
            log(2, "ContentProvider访问统计: 查询(" + stats.queries + 
                 "), 插入(" + stats.inserts + 
                 "), 更新(" + stats.updates + 
                 "), 删除(" + stats.deletes + ")");
            
            // 找出最常访问的URI
            var uris = [];
            for (var uri in stats.byUri) {
                var uriStats = stats.byUri[uri];
                var total = uriStats.query + uriStats.insert + uriStats.update + uriStats.delete;
                uris.push({
                    uri: uri,
                    total: total,
                    stats: uriStats
                });
            }
            
            uris.sort(function(a, b) {
                return b.total - a.total;
            });
            
            var limit = Math.min(uris.length, 3);
            if (limit > 0) {
                log(2, "最常访问的ContentProvider:");
                
                for (var i = 0; i < limit; i++) {
                    var uriStat = uris[i];
                    var details = uriStat.uri + " (" + uriStat.total + "次): ";
                    details += "查询(" + uriStat.stats.query + "), ";
                    details += "插入(" + uriStat.stats.insert + "), ";
                    details += "更新(" + uriStat.stats.update + "), ";
                    details += "删除(" + uriStat.stats.delete + ")";
                    
                    log(2, "    " + details);
                }
            }
            
            // 统计敏感URI的访问
            var sensCount = 0;
            for (var i = 0; i < uris.length; i++) {
                if (isSensitiveUri(Java.use("android.net.Uri").parse(uris[i].uri))) {
                    sensCount += uris[i].total;
                }
            }
            
            if (sensCount > 0) {
                log(1, "敏感ContentProvider访问: " + sensCount + "次");
            }
        }, 15000); // 每15秒输出一次
        
        log(2, "ContentProvider访问监控已启动");
    });
})(); 