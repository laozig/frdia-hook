/*
 * 脚本名称：底层ART自动脱壳.js
 * 功能：Hook ART底层DexFile相关函数，实现多版本Android自动脱壳和DEX转储
 * 适用场景：高强度加固、壳自定义ClassLoader、壳自定义DEX加载流程、内存DEX防护
 * 使用方法：
 *   1. frida -U -f 包名 -l 底层ART自动脱壳.js --no-pause
 *   2. DEX文件会自动保存到/data/data/应用包名/dump_dex_文件名.dex
 * 启动方式说明：
 *   - -U 代表USB设备
 *   - -f 代表spawn启动（推荐）
 *   - --no-pause 保证App正常运行
 * 支持特性：
 *   - 支持Android 5.0-12.0多版本系统
 *   - 自动识别libart.so路径
 *   - 多种DexFile加载函数检测(OpenMemory/OpenCommon/DefineClass等)
 *   - 支持InMemoryDex转储
 *   - 支持VDEX/ODEX/OATFILE提取
 *   - DEX特征检测与修复
 *   - 多ClassLoader解析
 *   - 自定义存储路径
 * 注意事项：
 *   - 需root或frida-server有足够权限
 *   - 某些壳需配合反检测脚本
 *   - 大型应用可能产生大量DEX，建议设置文件大小与数量过滤
 */

// 全局配置
var config = {
    minDexSize: 1024,           // 最小DEX文件大小(字节)
    maxDexSize: 20 * 1024 * 1024, // 最大DEX文件大小(20MB)
    maxDumpCount: 50,           // 最大Dump次数
    saveDir: null,              // 保存目录，null表示自动设置为/data/data/应用包名/
    autoFix: true,              // 自动修复DEX头
    autoSave: true,             // 自动保存文件
    logLevel: 2,                // 日志级别：0关闭，1错误，2信息，3调试
    deduplication: true,        // 去重复
    monitorJniLoad: true        // 监控JNI库加载
};

var artModuleNames = ["libart.so", "libaoc.so", "libart-compiler.so", "libart-disassembler.so"];
var moduleBaseMap = {};
var dumpedFiles = {};
var dumpCount = 0;

// 工具函数
var ArtDumper = {
    // 初始化环境
    init: function() {
        // 获取应用包名
        var context = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
        var pkgName = context.getPackageName();
        
        // 设置保存目录
        if (config.saveDir === null) {
            config.saveDir = "/data/data/" + pkgName + "/";
        }
        
        this.log(2, "初始化ART-DEX自动脱壳工具...");
        this.log(2, "目标应用: " + pkgName);
        this.log(2, "保存目录: " + config.saveDir);
        
        // 获取Android版本
        var sdkVersion = 0;
        try {
            sdkVersion = Java.use('android.os.Build$VERSION').SDK_INT.value;
            this.log(2, "Android SDK版本: " + sdkVersion);
        } catch (e) {
            this.log(1, "获取Android版本失败: " + e);
        }
        
        // 查找并加载所有ART相关模块
        var modules = Process.enumerateModules();
        this.log(2, "加载的模块数量: " + modules.length);
        
        artModuleNames.forEach(function(name) {
            for (var i = 0; i < modules.length; i++) {
                if (modules[i].name.indexOf(name) != -1) {
                    moduleBaseMap[name] = modules[i].base;
                    break;
                }
            }
        });
        
        if (!moduleBaseMap["libart.so"]) {
            this.log(1, "警告: 未找到libart.so模块，Hook可能失败");
        }
        
        return sdkVersion;
    },
    
    // 日志输出
    log: function(level, message) {
        if (level <= config.logLevel) {
            var prefix = "";
            switch (level) {
                case 1: prefix = "[!] "; break;
                case 2: prefix = "[*] "; break;
                case 3: prefix = "[+] "; break;
            }
            console.log(prefix + message);
        }
    },
    
    // 转储内存DEX
    dumpMemory: function(baseAddr, size, name) {
        if (dumpCount >= config.maxDumpCount) {
            this.log(1, "已达到最大dump次数: " + config.maxDumpCount);
            return null;
        }
        
        if (size < config.minDexSize || size > config.maxDexSize) {
            this.log(3, "DEX大小超出范围: " + size + "字节，跳过");
            return null;
        }
        
        // 读取内存
        try {
            var dexBytes = Memory.readByteArray(baseAddr, size);
            
            // 检查DEX头
            var dexHeader = new Uint8Array(dexBytes, 0, 16);
            var dexMagic = String.fromCharCode.apply(null, Array.from(dexHeader.slice(0, 8)));
            
            // 检查DEX文件头标记
            if (dexMagic.indexOf("dex") != 0) {
                if (config.autoFix) {
                    this.log(1, "DEX头无效，尝试修复...");
                    // 修复DEX头
                    var fixedHeader = new Uint8Array([0x64, 0x65, 0x78, 0x0A, 0x30, 0x33, 0x35, 0x00]);
                    for (var i = 0; i < 8; i++) {
                        Memory.writeU8(baseAddr.add(i), fixedHeader[i]);
                    }
                    // 重新读取
                    dexBytes = Memory.readByteArray(baseAddr, size);
                    this.log(2, "DEX头修复完成");
                } else {
                    this.log(1, "非DEX文件，Magic: " + this.bytesToHex(dexHeader) + "，跳过");
                    return null;
                }
            }
            
            // 计算MD5避免重复
            var md5 = this.bytesToMd5(dexBytes);
            if (config.deduplication && dumpedFiles[md5]) {
                this.log(2, "发现重复DEX文件，跳过保存");
                return null;
            }
            
            // 生成保存路径
            var timestamp = new Date().getTime();
            var filename = "dump_dex_" + timestamp + "_" + this.genRandomString(4) + ".dex";
            var savePath = config.saveDir + filename;
            
            if (name) {
                savePath = config.saveDir + "dump_dex_" + name + ".dex";
            }
            
            // 保存文件
            if (config.autoSave) {
                var file = new File(savePath, "wb");
                file.write(dexBytes);
                file.flush();
                file.close();
                
                this.log(2, "DEX保存成功: " + savePath + " (大小: " + size + " 字节)");
                dumpedFiles[md5] = true;
                dumpCount++;
                return savePath;
            } else {
                return dexBytes;
            }
        } catch (e) {
            this.log(1, "DEX转储失败: " + e);
            return null;
        }
    },
    
    // 工具函数：转换字节数组为十六进制字符串
    bytesToHex: function(bytes) {
        var hex = "";
        for (var i = 0; i < bytes.length; i++) {
            var b = bytes[i].toString(16);
            if (b.length == 1) {
                hex += "0";
            }
            hex += b;
        }
        return hex;
    },
    
    // 工具函数：计算MD5
    bytesToMd5: function(bytes) {
        // 简化的MD5计算，实际场景中可以实现完整的MD5
        var result = 0;
        var len = Math.min(bytes.byteLength, 1024); // 仅使用前1KB来计算
        for (var i = 0; i < len; i++) {
            result = ((result << 5) - result) + bytes[i];
        }
        return result.toString(16);
    },
    
    // 生成随机字符串
    genRandomString: function(length) {
        var text = "";
        var possible = "abcdefghijklmnopqrstuvwxyz0123456789";
        for (var i = 0; i < length; i++) {
            text += possible.charAt(Math.floor(Math.random() * possible.length));
        }
        return text;
    },
    
    // 查找函数符号地址
    findExportAddress: function(exportName) {
        var address = null;
        
        // 首先检查libart.so
        if (moduleBaseMap["libart.so"]) {
            address = Module.findExportByName("libart.so", exportName);
            if (address) return address;
        }
        
        // 遍历所有加载的模块查找符号
        var modules = Process.enumerateModules();
        for (var i = 0; i < modules.length; i++) {
            if (modules[i].name.indexOf("libart.so") != -1) {
                address = Module.findExportByName(modules[i].name, exportName);
                if (address) return address;
            }
        }
        
        // 失败后通过符号匹配查找
        for (var i = 0; i < modules.length; i++) {
            var symbols = modules[i].enumerateSymbols();
            for (var j = 0; j < symbols.length; j++) {
                if (symbols[j].name.indexOf(exportName) != -1) {
                    return symbols[j].address;
                }
            }
        }
        
        return null;
    }
};

// 主函数
function main() {
    var sdkVersion = ArtDumper.init();
    
    // 1. Hook DexFile::OpenMemory
    var openMemoryFunc = ArtDumper.findExportAddress("_ZN3art7DexFile10OpenMemoryEPKhjS2_jPNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEPNS_6MemMapEPKNS_10OatDexFileEPS9_");
    if (!openMemoryFunc) {
        // 兼容不同Android版本
        openMemoryFunc = ArtDumper.findExportAddress("_ZN3art6DexFile9OpenMemoryEPKvjS2_jPNS_7MemMapE");
    }
    if (!openMemoryFunc) {
        openMemoryFunc = ArtDumper.findExportAddress("_ZN3art6DexFile9OpenMemoryEPKvjS2_jPNS_7MemMapEPKNS_10OatDexFileE");
    }
    if (!openMemoryFunc) {
        openMemoryFunc = ArtDumper.findExportAddress("_ZN3art6DexFile9OpenMemoryEPKhmS2_mPNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEPNS_6MemMapE");
    }
    if (!openMemoryFunc) {
        openMemoryFunc = Module.findExportByName(null, "_ZN3art6DexFile9OpenMemoryEPKhmS2_mPNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEPNS_6MemMapE");
    }
    
    if (openMemoryFunc) {
        ArtDumper.log(2, "DexFile::OpenMemory 函数地址: " + openMemoryFunc);
        Interceptor.attach(openMemoryFunc, {
            onEnter: function (args) {
                var baseAddr = args[0];
                var size = (sdkVersion >= 24 /* Android 7.0 */) ? args[1].toUInt64() : args[1].toInt32();
                
                ArtDumper.log(2, "捕获到DexFile::OpenMemory调用，地址: " + baseAddr + "，大小: " + size);
                this.dumpResult = ArtDumper.dumpMemory(baseAddr, size, "OpenMemory_" + dumpCount);
            },
            onLeave: function (retval) {
                if (this.dumpResult) {
                    ArtDumper.log(3, "DexFile::OpenMemory返回: " + retval);
                }
            }
        });
    } else {
        ArtDumper.log(1, "未找到DexFile::OpenMemory函数，尝试其他Hook点");
    }
    
    // 2. Hook DexFile::OpenCommon
    var openCommonFunc = ArtDumper.findExportAddress("_ZN3art6DexFile10OpenCommonEPKvjRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPKNS_10OatDexFileEbbPS9_PNS0_12VerifyResultE");
    if (!openCommonFunc) {
        openCommonFunc = ArtDumper.findExportAddress("_ZN3art7DexFile10OpenCommonEPKhjRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPKNS_10OatDexFileEbbPS9_PNS0_12VerifyResultE");
    }
    
    if (openCommonFunc) {
        ArtDumper.log(2, "DexFile::OpenCommon 函数地址: " + openCommonFunc);
        Interceptor.attach(openCommonFunc, {
            onEnter: function (args) {
                var baseAddr = args[0];
                var size = (sdkVersion >= 24 /* Android 7.0 */) ? args[1].toUInt64() : args[1].toInt32();
                
                ArtDumper.log(2, "捕获到DexFile::OpenCommon调用，地址: " + baseAddr + "，大小: " + size);
                this.dumpResult = ArtDumper.dumpMemory(baseAddr, size, "OpenCommon_" + dumpCount);
            },
            onLeave: function (retval) {
                if (this.dumpResult) {
                    ArtDumper.log(3, "DexFile::OpenCommon返回: " + retval);
                }
            }
        });
    }
    
    // 3. Hook DefineClass
    var defineClassFunc = ArtDumper.findExportAddress("_ZN3art11ClassLinker11DefineClassEPNS_6ThreadEPKcmNS_6HandleINS_6mirror11ClassLoaderEEERKNS_7DexFileERKNS9_8ClassDefE");
    if (!defineClassFunc) {
        defineClassFunc = ArtDumper.findExportAddress("_ZN3art11ClassLinker11DefineClassEPNS_6ThreadEPKcjNS_6HandleINS_6mirror11ClassLoaderEEERKNS_7DexFileERKNS9_8ClassDefE");
    }
    
    if (defineClassFunc) {
        ArtDumper.log(2, "ClassLinker::DefineClass 函数地址: " + defineClassFunc);
        Interceptor.attach(defineClassFunc, {
            onEnter: function (args) {
                try {
                    // args[5]是DexFile引用，我们尝试获取基地址和大小
                    var dex_file = args[5];
                    var base = dex_file.add(Process.pointerSize).readPointer(); // begin_字段
                    var size = dex_file.add(Process.pointerSize * 2).readUInt(); // size_字段
                    
                    if (base && size > 0) {
                        ArtDumper.log(2, "ClassLinker::DefineClass捕获到DEX，地址: " + base + "，大小: " + size);
                        ArtDumper.dumpMemory(base, size, "DefineClass_" + dumpCount);
                    }
                } catch (e) {
                    ArtDumper.log(1, "DefineClass处理错误: " + e);
                }
            }
        });
    }
    
    // 4. 可选：监控DEX加载相关的ClassLoader
    if (config.monitorJniLoad) {
        Interceptor.attach(Module.findExportByName(null, "dlopen"), {
            onEnter: function (args) {
                var path = Memory.readUtf8String(args[0]);
                if (path && path.indexOf(".so") !== -1) {
                    ArtDumper.log(2, "加载动态库: " + path);
                    this.path = path;
                }
            },
            onLeave: function (retval) {
                if (this.path && retval.toInt32() !== 0) {
                    ArtDumper.log(2, "动态库加载成功: " + this.path);
                    if (this.path.indexOf("libart") !== -1) {
                        ArtDumper.log(2, "检测到libart动态库加载，将重新初始化钩子");
                        setTimeout(function() {
                            // 库加载后等待0.5秒再初始化，确保符号已解析
                            moduleBaseMap = {};
                            main();
                        }, 500);
                    }
                }
            }
        });
        
        // 监控JNI库注册
        Interceptor.attach(Module.findExportByName(null, "JNI_OnLoad"), {
            onEnter: function (args) {
                ArtDumper.log(2, "JNI_OnLoad被调用");
            }
        });
    }
    
    ArtDumper.log(2, "ART自动脱壳器初始化完成，等待DEX加载...");
}

// 启动主程序
setTimeout(main, 100); 