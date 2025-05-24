/**
 * Android通用脱壳工具
 * 
 * 功能：自动检测并脱壳常见加固方案保护的Android应用
 * 作用：提取加固应用中的原始DEX文件
 * 适用：各类主流加固应用（腾讯乐固、爱加密、梆梆、360加固等）
 * 
 * 使用方法：
 * 1. frida -U -f 目标应用包名 -l 通用脱壳工具.js --no-pause
 * 2. 或者 frida -U --attach-pid 目标进程PID -l 通用脱壳工具.js
 */

(function() {
    // 配置选项
    const config = {
        // 是否自动保存提取的DEX文件
        autoSave: true,
        // 保存路径（相对于/data/data/应用包名/）
        savePath: "dump",
        // 是否显示详细日志
        verbose: true,
        // 是否监控所有类加载
        monitorAllClassLoading: false,
        // 是否监控JNI注册
        monitorJNIRegister: true,
        // 是否监控内存映射
        monitorMemoryMapping: true,
        // 是否监控文件操作
        monitorFileOperations: true,
        // 是否自动合并分段DEX
        autoMergeSplitDex: true,
        // 是否尝试修复损坏的DEX头
        tryFixDexHeader: true
    };

    // 全局变量
    let processName = "";
    let packageName = "";
    let dumpCount = 0;
    let dumpedDexSet = new Set();
    let lastMemScan = 0;

    // 颜色输出
    const colors = {
        reset: "\x1b[0m",
        red: "\x1b[31m",
        green: "\x1b[32m",
        yellow: "\x1b[33m",
        blue: "\x1b[34m",
        magenta: "\x1b[35m",
        cyan: "\x1b[36m",
        white: "\x1b[37m"
    };

    function colorLog(color, message) {
        console.log(colors[color] + message + colors.reset);
    }

    function logInfo(message) {
        colorLog("green", "[*] " + message);
    }

    function logWarn(message) {
        colorLog("yellow", "[!] " + message);
    }

    function logError(message) {
        colorLog("red", "[-] " + message);
    }

    function logSuccess(message) {
        colorLog("cyan", "[+] " + message);
    }

    function logDebug(message) {
        if (config.verbose) {
            colorLog("magenta", "[D] " + message);
        }
    }

    // 获取调用堆栈
    function getStackTrace() {
        return Java.use("android.util.Log").getStackTraceString(
            Java.use("java.lang.Throwable").$new()
        );
    }

    // 创建目录
    function ensureDirExists(path) {
        const File = Java.use("java.io.File");
        const dir = File.$new(path);
        if (!dir.exists()) {
            if (!dir.mkdirs()) {
                logError("创建目录失败: " + path);
                return false;
            }
        }
        return true;
    }

    // 保存DEX文件
    function saveDexFile(dexBytes, name) {
        try {
            const File = Java.use("java.io.File");
            const FileOutputStream = Java.use("java.io.FileOutputStream");
            
            // 确保目录存在
            const packageDir = "/data/data/" + packageName + "/" + config.savePath;
            if (!ensureDirExists(packageDir)) {
                return false;
            }
            
            // 创建文件
            const fileName = packageDir + "/" + name;
            const file = File.$new(fileName);
            
            // 写入文件
            const fos = FileOutputStream.$new(file);
            fos.write(dexBytes);
            fos.close();
            
            logSuccess("DEX已保存: " + fileName);
            return true;
        } catch (e) {
            logError("保存DEX文件失败: " + e);
            return false;
        }
    }

    // 检查是否为有效的DEX文件
    function isValidDex(bytes) {
        // DEX文件头魔数: dex\n035\0 或 dex\n036\0 或 dex\n037\0 或 dex\n038\0
        const dexMagic = [0x64, 0x65, 0x78, 0x0A, 0x30, 0x33]; // "dex\n03"
        
        if (bytes.length < 70) {
            return false;
        }
        
        // 检查DEX魔数
        for (let i = 0; i < 6; i++) {
            if (bytes[i] !== dexMagic[i]) {
                return false;
            }
        }
        
        // 检查第7个字节是5-8之间(DEX版本035-038)
        const versionByte = bytes[6];
        if (versionByte < 0x35 || versionByte > 0x38) {
            return false;
        }
        
        // 检查第8个字节是否为0
        if (bytes[7] !== 0) {
            return false;
        }
        
        return true;
    }

    // 尝试修复DEX头
    function tryFixDexHeader(bytes) {
        if (!config.tryFixDexHeader) {
            return bytes;
        }
        
        // 如果前8个字节不是DEX魔数，尝试修复
        if (!isValidDex(bytes)) {
            const dexMagic = [0x64, 0x65, 0x78, 0x0A, 0x30, 0x33, 0x35, 0x00]; // "dex\n035\0"
            const newBytes = new Uint8Array(bytes.length);
            
            // 复制原始数据
            for (let i = 0; i < bytes.length; i++) {
                newBytes[i] = bytes[i];
            }
            
            // 修复DEX头
            for (let i = 0; i < 8; i++) {
                newBytes[i] = dexMagic[i];
            }
            
            logWarn("尝试修复DEX头");
            return newBytes;
        }
        
        return bytes;
    }

    // 计算字节数组的MD5
    function md5(bytes) {
        try {
            const MessageDigest = Java.use("java.security.MessageDigest");
            const md = MessageDigest.getInstance("MD5");
            const digest = md.digest(bytes);
            
            let hexString = "";
            for (let i = 0; i < digest.length; i++) {
                const hex = (digest[i] & 0xFF).toString(16);
                hexString += (hex.length === 1 ? "0" : "") + hex;
            }
            return hexString;
        } catch (e) {
            logError("计算MD5失败: " + e);
            return "unknown";
        }
    }

    // 处理DEX数据
    function processDexData(dexBytes, source) {
        // 检查是否为有效的DEX
        if (!isValidDex(dexBytes)) {
            if (config.tryFixDexHeader) {
                dexBytes = tryFixDexHeader(dexBytes);
                if (!isValidDex(dexBytes)) {
                    logDebug("无效的DEX数据，跳过处理");
                    return;
                }
            } else {
                logDebug("无效的DEX数据，跳过处理");
                return;
            }
        }
        
        // 计算MD5避免重复保存
        const dexMd5 = md5(dexBytes);
        if (dumpedDexSet.has(dexMd5)) {
            logDebug("DEX已存在，跳过保存 (MD5: " + dexMd5 + ")");
            return;
        }
        
        dumpedDexSet.add(dexMd5);
        dumpCount++;
        
        // 构建文件名
        const fileName = "dumped_" + source + "_" + dumpCount + ".dex";
        
        // 保存DEX
        if (config.autoSave) {
            saveDexFile(dexBytes, fileName);
        }
        
        logSuccess("发现DEX [" + source + "] 大小: " + dexBytes.length + " 字节, MD5: " + dexMd5);
    }

    // 监控ClassLoader.defineClass
    function hookClassLoaderDefineClass() {
        try {
            const BaseDexClassLoader = Java.use("dalvik.system.BaseDexClassLoader");
            const DexFile = Java.use("dalvik.system.DexFile");
            const ByteBuffer = Java.use("java.nio.ByteBuffer");
            
            // Hook DexFile构造函数
            DexFile.$init.overload("java.nio.ByteBuffer", "java.lang.String").implementation = function(buffer, fileName) {
                logDebug("DexFile.$init(ByteBuffer, String) 被调用");
                
                try {
                    const dexBytes = Java.array('byte', buffer.array());
                    processDexData(dexBytes, "DexFile_ByteBuffer");
                } catch (e) {
                    logError("处理DexFile.$init ByteBuffer失败: " + e);
                }
                
                return this.$init(buffer, fileName);
            };
            
            // Hook InMemoryDexClassLoader (Android 8.0+)
            try {
                const InMemoryDexClassLoader = Java.use("dalvik.system.InMemoryDexClassLoader");
                
                InMemoryDexClassLoader.$init.overload("java.nio.ByteBuffer", "java.lang.ClassLoader").implementation = function(buffer, parent) {
                    logDebug("InMemoryDexClassLoader.$init(ByteBuffer, ClassLoader) 被调用");
                    
                    try {
                        const dexBytes = Java.array('byte', buffer.array());
                        processDexData(dexBytes, "InMemoryDexClassLoader");
                    } catch (e) {
                        logError("处理InMemoryDexClassLoader.$init失败: " + e);
                    }
                    
                    return this.$init(buffer, parent);
                };
                
                logSuccess("已Hook InMemoryDexClassLoader");
            } catch (e) {
                logDebug("InMemoryDexClassLoader不可用，可能是Android版本较低");
            }
            
            logSuccess("已Hook ClassLoader相关方法");
        } catch (e) {
            logError("Hook ClassLoader失败: " + e);
        }
    }

    // 监控常见加固方案的特定类
    function hookProtectionSpecificClasses() {
        try {
            // 腾讯乐固
            try {
                const TxAppEntry = Java.use("com.tencent.mobileqq.fe.TxAppEntry");
                TxAppEntry.loadTxCodeFromAsset.implementation = function(context, str) {
                    logWarn("检测到腾讯乐固加固: loadTxCodeFromAsset被调用");
                    const result = this.loadTxCodeFromAsset(context, str);
                    
                    // 扫描内存寻找DEX
                    setTimeout(function() {
                        scanMemoryForDex("TencentProtect");
                    }, 1000);
                    
                    return result;
                };
                logSuccess("已Hook腾讯乐固特定方法");
            } catch (e) {
                logDebug("未检测到腾讯乐固");
            }
            
            // 爱加密
            try {
                const AJMCore = Java.use("s.h.e.l.l.S");
                AJMCore.loadDex.implementation = function(context, str, i) {
                    logWarn("检测到爱加密加固: loadDex被调用");
                    const result = this.loadDex(context, str, i);
                    
                    // 扫描内存寻找DEX
                    setTimeout(function() {
                        scanMemoryForDex("ijiami");
                    }, 1000);
                    
                    return result;
                };
                logSuccess("已Hook爱加密特定方法");
            } catch (e) {
                logDebug("未检测到爱加密");
            }
            
            // 360加固
            try {
                const QihooStub = Java.use("com.qihoo.util.StubApp");
                QihooStub.getClassLoader.implementation = function(context) {
                    logWarn("检测到360加固: getClassLoader被调用");
                    const result = this.getClassLoader(context);
                    
                    // 扫描内存寻找DEX
                    setTimeout(function() {
                        scanMemoryForDex("Qihoo360");
                    }, 1000);
                    
                    return result;
                };
                logSuccess("已Hook 360加固特定方法");
            } catch (e) {
                logDebug("未检测到360加固");
            }
            
            // 梆梆加固
            try {
                const BangcleApplication = Java.use("com.secneo.apkwrapper.ApplicationWrapper");
                BangcleApplication.attachBaseContext.implementation = function(context) {
                    logWarn("检测到梆梆加固: attachBaseContext被调用");
                    const result = this.attachBaseContext(context);
                    
                    // 扫描内存寻找DEX
                    setTimeout(function() {
                        scanMemoryForDex("Bangcle");
                    }, 1000);
                    
                    return result;
                };
                logSuccess("已Hook梆梆加固特定方法");
            } catch (e) {
                logDebug("未检测到梆梆加固");
            }
            
            logSuccess("已Hook加固保护特定类");
        } catch (e) {
            logError("Hook加固保护特定类失败: " + e);
        }
    }

    // 监控Native库加载
    function hookNativeLibraryLoading() {
        try {
            const System = Java.use("java.lang.System");
            
            System.load.implementation = function(libPath) {
                logDebug("System.load: " + libPath);
                
                // 调用原始方法
                const result = this.load(libPath);
                
                // 如果是加固相关库，扫描内存
                if (libPath.indexOf("libshell") !== -1 || 
                    libPath.indexOf("libprotect") !== -1 || 
                    libPath.indexOf("libsecexe") !== -1 ||
                    libPath.indexOf("libDexHelper") !== -1 ||
                    libPath.indexOf("libjiagu") !== -1) {
                    
                    logWarn("检测到可能的加固保护库: " + libPath);
                    
                    // 延迟扫描内存，等待解密完成
                    setTimeout(function() {
                        scanMemoryForDex("NativeLib_" + libPath.split("/").pop());
                    }, 2000);
                }
                
                return result;
            };
            
            System.loadLibrary.implementation = function(libName) {
                logDebug("System.loadLibrary: " + libName);
                
                // 调用原始方法
                const result = this.loadLibrary(libName);
                
                // 如果是加固相关库，扫描内存
                if (libName.indexOf("shell") !== -1 || 
                    libName.indexOf("protect") !== -1 || 
                    libName.indexOf("secexe") !== -1 ||
                    libName.indexOf("DexHelper") !== -1 ||
                    libName.indexOf("jiagu") !== -1) {
                    
                    logWarn("检测到可能的加固保护库: " + libName);
                    
                    // 延迟扫描内存，等待解密完成
                    setTimeout(function() {
                        scanMemoryForDex("NativeLib_" + libName);
                    }, 2000);
                }
                
                return result;
            };
            
            logSuccess("已Hook Native库加载方法");
        } catch (e) {
            logError("Hook Native库加载失败: " + e);
        }
    }

    // 监控文件操作
    function hookFileOperations() {
        if (!config.monitorFileOperations) {
            return;
        }
        
        try {
            const FileInputStream = Java.use("java.io.FileInputStream");
            const FileOutputStream = Java.use("java.io.FileOutputStream");
            
            // 监控文件读取
            FileInputStream.$init.overload("java.io.File").implementation = function(file) {
                const path = file.getAbsolutePath();
                
                if (path.endsWith(".dex") || path.endsWith(".jar") || path.endsWith(".apk")) {
                    logDebug("读取文件: " + path);
                }
                
                return this.$init(file);
            };
            
            // 监控文件写入
            FileOutputStream.$init.overload("java.io.File", "boolean").implementation = function(file, append) {
                const path = file.getAbsolutePath();
                
                if (path.endsWith(".dex") || path.endsWith(".jar") || path.endsWith(".apk") || 
                    path.indexOf("/data/data/") !== -1) {
                    logDebug("写入文件: " + path + " (append: " + append + ")");
                    
                    // 延迟检查文件内容是否为DEX
                    setTimeout(function() {
                        checkFileForDex(path);
                    }, 1000);
                }
                
                return this.$init(file, append);
            };
            
            logSuccess("已Hook文件操作方法");
        } catch (e) {
            logError("Hook文件操作失败: " + e);
        }
    }

    // 检查文件是否为DEX
    function checkFileForDex(filePath) {
        try {
            const File = Java.use("java.io.File");
            const FileInputStream = Java.use("java.io.FileInputStream");
            const ByteArrayOutputStream = Java.use("java.io.ByteArrayOutputStream");
            
            const file = File.$new(filePath);
            if (!file.exists() || !file.canRead()) {
                return;
            }
            
            const fis = FileInputStream.$new(file);
            const baos = ByteArrayOutputStream.$new();
            
            // 读取文件内容
            const buffer = Java.array('byte', new Array(4096).fill(0));
            let bytesRead;
            while ((bytesRead = fis.read(buffer)) !== -1) {
                baos.write(buffer, 0, bytesRead);
            }
            
            fis.close();
            
            // 检查是否为DEX
            const fileBytes = baos.toByteArray();
            if (isValidDex(fileBytes)) {
                logWarn("发现文件中的DEX: " + filePath);
                processDexData(fileBytes, "File_" + filePath.split("/").pop());
            }
        } catch (e) {
            logDebug("检查文件失败: " + e);
        }
    }

    // 扫描内存寻找DEX
    function scanMemoryForDex(source) {
        // 避免频繁扫描
        const now = Date.now();
        if (now - lastMemScan < 5000) {
            logDebug("跳过内存扫描，距离上次扫描时间过短");
            return;
        }
        lastMemScan = now;
        
        try {
            logInfo("开始扫描内存寻找DEX...");
            
            // 使用Runtime.getRuntime().exec执行命令
            const Runtime = Java.use("java.lang.Runtime");
            const Process = Java.use("java.lang.Process");
            const BufferedReader = Java.use("java.io.BufferedReader");
            const InputStreamReader = Java.use("java.io.InputStreamReader");
            
            // 获取进程的内存映射
            const process = Runtime.getRuntime().exec(["su", "-c", "cat /proc/" + Process.myPid() + "/maps"]);
            const reader = BufferedReader.$new(InputStreamReader.$new(process.getInputStream()));
            
            let line;
            let count = 0;
            
            while ((line = reader.readLine()) !== null) {
                // 查找可能包含DEX的内存区域
                if ((line.indexOf("rw") !== -1 || line.indexOf("r-x") !== -1) && 
                    line.indexOf("dalvik") === -1 &&
                    line.indexOf("libc.so") === -1) {
                    
                    const parts = line.split(" ");
                    const addrRange = parts[0].split("-");
                    
                    if (addrRange.length === 2) {
                        const startAddr = parseInt(addrRange[0], 16);
                        const endAddr = parseInt(addrRange[1], 16);
                        const size = endAddr - startAddr;
                        
                        // 只处理合理大小的内存块
                        if (size > 1024 * 1024 && size < 100 * 1024 * 1024) {
                            logDebug("扫描内存区域: " + line);
                            
                            // 读取内存区域
                            const cmd = "su -c dd if=/proc/" + Process.myPid() + "/mem bs=1 skip=" + 
                                  startAddr + " count=" + size + " 2>/dev/null | grep -a -c 'dex\\|036\\|035'";
                            
                            const grepProcess = Runtime.getRuntime().exec(["sh", "-c", cmd]);
                            const grepReader = BufferedReader.$new(InputStreamReader.$new(grepProcess.getInputStream()));
                            const grepResult = grepReader.readLine();
                            
                            if (grepResult && parseInt(grepResult) > 0) {
                                logWarn("发现可能包含DEX的内存区域: " + line);
                                
                                // 提取内存区域内容
                                const dumpCmd = "su -c dd if=/proc/" + Process.myPid() + "/mem bs=1 skip=" + 
                                      startAddr + " count=" + size + " of=/data/local/tmp/mem_dump_" + count + ".bin 2>/dev/null";
                                
                                Runtime.getRuntime().exec(["sh", "-c", dumpCmd]).waitFor();
                                
                                // 读取转储的内存
                                const File = Java.use("java.io.File");
                                const FileInputStream = Java.use("java.io.FileInputStream");
                                const ByteArrayOutputStream = Java.use("java.io.ByteArrayOutputStream");
                                
                                const dumpFile = File.$new("/data/local/tmp/mem_dump_" + count + ".bin");
                                if (dumpFile.exists()) {
                                    const fis = FileInputStream.$new(dumpFile);
                                    const baos = ByteArrayOutputStream.$new();
                                    
                                    const buffer = Java.array('byte', new Array(4096).fill(0));
                                    let bytesRead;
                                    while ((bytesRead = fis.read(buffer)) !== -1) {
                                        baos.write(buffer, 0, bytesRead);
                                    }
                                    
                                    fis.close();
                                    
                                    // 查找DEX魔数
                                    const memBytes = baos.toByteArray();
                                    findDexInMemory(memBytes, source + "_region" + count);
                                    
                                    // 删除临时文件
                                    dumpFile.delete();
                                }
                                
                                count++;
                            }
                            
                            grepReader.close();
                        }
                    }
                }
            }
            
            reader.close();
            logInfo("内存扫描完成，处理了 " + count + " 个内存区域");
            
        } catch (e) {
            logError("扫描内存失败: " + e);
        }
    }

    // 在内存块中查找DEX
    function findDexInMemory(memBytes, source) {
        const dexMagic = [0x64, 0x65, 0x78, 0x0A, 0x30, 0x33]; // "dex\n03"
        
        for (let i = 0; i < memBytes.length - 6; i++) {
            let found = true;
            for (let j = 0; j < 6; j++) {
                if (memBytes[i + j] !== dexMagic[j]) {
                    found = false;
                    break;
                }
            }
            
            if (found) {
                // 检查DEX版本
                const versionByte = memBytes[i + 6];
                if (versionByte >= 0x35 && versionByte <= 0x38 && memBytes[i + 7] === 0) {
                    // 找到DEX魔数
                    logWarn("在内存中找到DEX魔数，偏移: " + i);
                    
                    try {
                        // 读取DEX文件大小
                        const fileSize = 
                            (memBytes[i + 36] & 0xFF) |
                            ((memBytes[i + 37] & 0xFF) << 8) |
                            ((memBytes[i + 38] & 0xFF) << 16) |
                            ((memBytes[i + 39] & 0xFF) << 24);
                        
                        if (fileSize > 0 && fileSize < 100 * 1024 * 1024) {
                            logDebug("DEX文件大小: " + fileSize + " 字节");
                            
                            // 提取DEX数据
                            if (i + fileSize <= memBytes.length) {
                                const dexBytes = new Uint8Array(fileSize);
                                for (let k = 0; k < fileSize; k++) {
                                    dexBytes[k] = memBytes[i + k];
                                }
                                
                                processDexData(dexBytes, source);
                            }
                        }
                    } catch (e) {
                        logDebug("处理内存中的DEX失败: " + e);
                    }
                }
            }
        }
    }

    // 主函数
    function main() {
        Java.perform(function() {
            try {
                // 获取进程和包名信息
                const Process = Java.use("android.os.Process");
                const ActivityThread = Java.use("android.app.ActivityThread");
                
                const currentApplication = ActivityThread.currentApplication();
                if (currentApplication !== null) {
                    const context = currentApplication.getApplicationContext();
                    packageName = context.getPackageName();
                    processName = packageName;
                } else {
                    packageName = "unknown";
                    processName = "unknown";
                }
                
                logInfo("开始监控应用: " + packageName);
                
                // 设置各种Hook
                hookClassLoaderDefineClass();
                hookProtectionSpecificClasses();
                hookNativeLibraryLoading();
                hookFileOperations();
                
                // 初始扫描
                setTimeout(function() {
                    scanMemoryForDex("Initial");
                }, 5000);
                
                // 定期扫描
                setInterval(function() {
                    if (dumpCount === 0) {
                        scanMemoryForDex("Periodic");
                    }
                }, 30000);
                
                logSuccess("脱壳工具初始化完成");
                logInfo("等待应用运行并解密DEX...");
                
            } catch (e) {
                logError("初始化失败: " + e);
            }
        });
    }

    // 启动
    setTimeout(main, 1000);
})(); 