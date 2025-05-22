/**
 * Frida DEX脱壳模块
 * 提取内存中的DEX文件，支持多种加固壳的脱壳操作
 */

module.exports = function(userConfig, logger, utils) {
    const tag = "DUMPER";
    
    // 默认配置
    const defaultConfig = {
        outputDir: '/sdcard/frida_dumps/',       // 输出目录
        filterSystemClasses: true,                // 过滤系统类
        autoLoadClasses: true,                    // 自动加载所有类
        dumpClassLoaders: true,                   // 转储所有ClassLoader中的DEX
        dumpMemory: true,                         // 扫描内存中的DEX
        dumpOnClassLoad: true,                    // 在类加载时提取DEX
        minDexSize: 4096,                         // 最小DEX文件大小(字节)
        maxDexSize: 20 * 1024 * 1024,             // 最大DEX文件大小(20MB)
        memScanIntervalMs: 5000,                  // 内存扫描间隔(毫秒)
        supportedProtections: ['梆梆', '爱加密', '360加固', '腾讯乐固', 
                              '阿里聚安全', '百度加固', '娜迦', '盛大加固', 
                              '网秦加固', '几维安全', '通付盾', '瑞星加固',
                              'APKProtect', '顶像科技', '珊瑚灵御', '金丝雀',
                              '华为HMS加固', '华为安全', '海思加固', '新版爱加密',
                              '携程加固', '微信小程序加固', '字节跳动加固', '猎豹加固',
                              'OPPO加固', 'vivo加固'] // 支持的加固保护
    };
    
    // 合并用户配置
    const config = Object.assign({}, defaultConfig, userConfig || {});
    
    // 记录已提取的DEX文件，避免重复
    const extractedDexHashes = new Set();
    
    // 累计统计
    const stats = {
        dexFiles: 0,
        classFiles: 0,
        totalBytes: 0,
        startTime: new Date(),
        uniqueLoaders: new Set()
    };
    
    // 初始化模块
    function initialize() {
        logger.info(tag, "DEX脱壳模块初始化");
        logger.info(tag, `输出目录: ${config.outputDir}`);
        logger.info(tag, `支持的保护: ${config.supportedProtections.join(', ')}`);
        
        // 创建输出目录
        try {
            const outputDir = new File(config.outputDir);
            if (!outputDir.exists()) {
                const parentDir = new File(outputDir.getParent());
                if (!parentDir.exists()) {
                    parentDir.mkdirs();
                }
                outputDir.mkdir();
            }
            logger.info(tag, "输出目录创建成功");
        } catch (e) {
            logger.error(tag, "创建输出目录失败: " + e);
        }
        
        // 自动优化脱壳参数
        autoOptimizeParameters();
        
        // 开始监控
        Java.perform(setupHooks);
    }
    
    // 根据设备和应用情况自动优化脱壳参数
    function autoOptimizeParameters() {
        try {
            // 检测设备性能
            const ActivityThread = Java.use("android.app.ActivityThread");
            const Application = Java.use("android.app.Application");
            const Process = Java.use("android.os.Process");
            const Build = Java.use("android.os.Build");
            
            const memClass = ActivityThread.currentApplication() ? 
                             ActivityThread.currentApplication().getApplicationContext().getSystemService("activity").getMemoryClass() :
                             0;
            
            // 检测设备SDK版本
            const sdkVersion = Build.VERSION.SDK_INT.value;
            
            logger.debug(tag, `设备内存类: ${memClass}MB, SDK版本: ${sdkVersion}`);
            
            // 根据设备内存调整参数
            if (memClass < 128) {
                // 低内存设备
                logger.debug(tag, "检测到低内存设备，调整脱壳参数");
                config.maxDexSize = 10 * 1024 * 1024; // 减小到10MB
                config.memScanIntervalMs = 10000; // 增加到10秒
            } else if (memClass >= 256) {
                // 高内存设备
                logger.debug(tag, "检测到高内存设备，优化脱壳参数");
                config.maxDexSize = 50 * 1024 * 1024; // 增大到50MB
                config.memScanIntervalMs = 3000; // 减少到3秒
            }
            
            // Android 10 (API 29) 及以上版本需要特殊处理
            if (sdkVersion >= 29) {
                logger.debug(tag, "检测到Android 10+，调整扫描策略");
                // Android 10+对内存访问限制更严格，优化扫描策略
            }
            
            // 检测是否为特定类型的应用
            try {
                const appContext = ActivityThread.currentApplication().getApplicationContext();
                const packageName = appContext.getPackageName();
                
                // 判断是否为游戏引擎应用
                const isUnityApp = Java.classFactory.loader.findClass("com.unity3d.player.UnityPlayer") !== null;
                const isUnrealApp = packageName.includes("UE4") || Java.classFactory.loader.findClass("com.epicgames.ue4.GameActivity") !== null;
                
                if (isUnityApp) {
                    logger.debug(tag, "检测到Unity应用，优化Unity脱壳参数");
                    // Unity应用特殊处理
                    config.supportedProtections.push("Unity加密");
                }
                
                if (isUnrealApp) {
                    logger.debug(tag, "检测到虚幻引擎应用，优化虚幻脱壳参数");
                    // 虚幻引擎特殊处理
                }
                
            } catch (e) {
                logger.debug(tag, `应用类型检测失败: ${e}`);
            }
            
            logger.info(tag, `脱壳参数自动优化完成`);
        } catch (e) {
            logger.debug(tag, `自动优化脱壳参数失败: ${e}`);
        }
    }
    
    // 设置所有钩子函数
    function setupHooks() {
        logger.debug(tag, "正在设置脱壳钩子");
        
        if (config.dumpClassLoaders) {
            hookClassLoaders();
        }
        
        if (config.dumpOnClassLoad) {
            hookClassLoad();
        }
        
        if (config.autoLoadClasses) {
            setTimeout(forceLoadAllClasses, 3000);
        }
        
        if (config.dumpMemory) {
            // 延迟启动内存扫描，等待应用初始化
            setTimeout(function() {
                scanMemoryForDex();
                // 定期扫描内存
                setInterval(scanMemoryForDex, config.memScanIntervalMs);
            }, 5000);
        }
        
        // 针对特定保护的专用钩子
        setupSpecificProtectionHooks();
        
        logger.info(tag, "脱壳钩子设置完成");
    }
    
    // 针对主要ClassLoader进行Hook
    function hookClassLoaders() {
        try {
            // 1. 拦截BaseDexClassLoader创建
            const BaseDexClassLoader = Java.use("dalvik.system.BaseDexClassLoader");
            
            BaseDexClassLoader.$init.overload('java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.ClassLoader').implementation = function(dexPath, optimizedDirectory, librarySearchPath, parent) {
                const result = this.$init(dexPath, optimizedDirectory, librarySearchPath, parent);
                try {
                    logger.debug(tag, `ClassLoader创建: ${dexPath}`);
                    setTimeout(function() { dumpClassLoaderDex(this); }, 0);
                } catch (e) {
                    logger.error(tag, `处理ClassLoader创建时出错: ${e}`);
                }
                return result;
            };
            
            // 2. 拦截DexClassLoader创建
            try {
                const DexClassLoader = Java.use("dalvik.system.DexClassLoader");
                DexClassLoader.$init.overload('java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.ClassLoader').implementation = function(dexPath, optimizedDirectory, librarySearchPath, parent) {
                    const result = this.$init(dexPath, optimizedDirectory, librarySearchPath, parent);
                    try {
                        logger.debug(tag, `DexClassLoader创建: ${dexPath}`);
                        setTimeout(function() { dumpClassLoaderDex(this); }, 0);
                    } catch (e) {
                        logger.error(tag, `处理DexClassLoader创建时出错: ${e}`);
                    }
                    return result;
                };
            } catch (e) {
                logger.debug(tag, `DexClassLoader Hook失败: ${e}`);
            }
            
            // 3. 拦截InMemoryDexClassLoader (Android 8.0+)
            try {
                const InMemoryDexClassLoader = Java.use("dalvik.system.InMemoryDexClassLoader");
                // 有多个重载方法，尝试全部拦截
                InMemoryDexClassLoader.$init.overloads.forEach(function(overload) {
                    overload.implementation = function() {
                        const result = overload.apply(this, arguments);
                        try {
                            logger.debug(tag, "InMemoryDexClassLoader创建");
                            setTimeout(function() { dumpClassLoaderDex(this); }, 0);
                        } catch (e) {
                            logger.error(tag, `处理InMemoryDexClassLoader创建时出错: ${e}`);
                        }
                        return result;
                    };
                });
            } catch (e) {
                logger.debug(tag, `InMemoryDexClassLoader Hook失败: ${e}`);
            }
            
            logger.info(tag, "ClassLoader钩子设置成功");
        } catch (e) {
            logger.error(tag, `设置ClassLoader钩子失败: ${e}`);
        }
    }
    
    // Hook类加载过程
    function hookClassLoad() {
        try {
            const clazzClass = Java.use("java.lang.Class");
            
            clazzClass.forName.overload('java.lang.String', 'boolean', 'java.lang.ClassLoader').implementation = function(name, initialize, loader) {
                const clazz = this.forName(name, initialize, loader);
                try {
                    if (shouldProcessClass(name)) {
                        const classLoader = clazz.getClassLoader();
                        if (classLoader && !stats.uniqueLoaders.has(classLoader.toString())) {
                            stats.uniqueLoaders.add(classLoader.toString());
                            logger.debug(tag, `类加载: ${name} [从新的ClassLoader]`);
                            setTimeout(function() { dumpClassLoaderDex(classLoader); }, 0);
                        }
                    }
                } catch (e) {
                    logger.debug(tag, `处理类加载时出错 [${name}]: ${e}`);
                }
                return clazz;
            };
            
            // 监控LoadClass方法
            const classLoaderClass = Java.use("java.lang.ClassLoader");
            classLoaderClass.loadClass.overload('java.lang.String').implementation = function(name) {
                const clazz = this.loadClass(name);
                try {
                    if (shouldProcessClass(name) && !stats.uniqueLoaders.has(this.toString())) {
                        stats.uniqueLoaders.add(this.toString());
                        logger.debug(tag, `类加载: ${name} [使用loadClass]`);
                        setTimeout(function() { dumpClassLoaderDex(this); }, 0);
                    }
                } catch (e) {
                    logger.debug(tag, `处理loadClass时出错 [${name}]: ${e}`);
                }
                return clazz;
            };
            
            logger.info(tag, "类加载钩子设置成功");
        } catch (e) {
            logger.error(tag, `设置类加载钩子失败: ${e}`);
        }
    }
    
    // 从ClassLoader中转储DEX
    function dumpClassLoaderDex(classLoader) {
        try {
            if (!classLoader) {
                logger.debug(tag, "ClassLoader为null");
                return;
            }
            
            // 尝试使用反射获取pathList字段
            const clClass = classLoader.$className ? classLoader.getClass() : Java.use("java.lang.Object").getClass().call(classLoader);
            const pathListField = findField(clClass, "pathList");
            if (!pathListField) {
                logger.debug(tag, "pathList字段未找到");
                return;
            }
            
            pathListField.setAccessible(true);
            const pathList = pathListField.get(classLoader);
            if (!pathList) {
                logger.debug(tag, "pathList为null");
                return;
            }
            
            // 尝试获取dexElements数组
            const pathListClass = pathList.getClass();
            const dexElementsField = findField(pathListClass, "dexElements");
            if (!dexElementsField) {
                logger.debug(tag, "dexElements字段未找到");
                return;
            }
            
            dexElementsField.setAccessible(true);
            const dexElements = dexElementsField.get(pathList);
            if (!dexElements) {
                logger.debug(tag, "dexElements为null");
                return;
            }
            
            // 遍历dexElements数组
            const elementsCount = Java.use("java.lang.reflect.Array").getLength(dexElements);
            logger.debug(tag, `发现 ${elementsCount} 个DexElement`);
            
            for (let i = 0; i < elementsCount; i++) {
                try {
                    const element = Java.use("java.lang.reflect.Array").get(dexElements, i);
                    if (!element) continue;
                    
                    const elementClass = element.getClass();
                    
                    // 尝试获取dexFile字段
                    const dexFileField = findField(elementClass, "dexFile");
                    if (!dexFileField) {
                        logger.debug(tag, `元素 ${i} 没有dexFile字段`);
                        continue;
                    }
                    
                    dexFileField.setAccessible(true);
                    const dexFile = dexFileField.get(element);
                    if (!dexFile) continue;
                    
                    // 从DexFile中获取DEX字节码
                    const dexBytes = extractDexBytes(dexFile);
                    if (dexBytes && dexBytes.length > config.minDexSize && dexBytes.length < config.maxDexSize) {
                        const dexHash = Java.use("java.util.Arrays").hashCode(dexBytes);
                        if (!extractedDexHashes.has(dexHash)) {
                            extractedDexHashes.add(dexHash);
                            
                            const fileName = `${config.outputDir}classes_${String(stats.dexFiles + 1).padStart(2, '0')}.dex`;
                            if (saveDexToFile(dexBytes, fileName)) {
                                logger.info(tag, `提取DEX文件: ${fileName} [大小: ${dexBytes.length} 字节, 从ClassLoader]`);
                                stats.dexFiles++;
                                stats.totalBytes += dexBytes.length;
                            }
                        }
                    }
                } catch (elementError) {
                    logger.debug(tag, `处理DexElement ${i} 时出错: ${elementError}`);
                    // 继续处理下一个元素
                }
            }
        } catch (e) {
            logger.error(tag, `转储ClassLoader DEX时出错: ${e}`);
        }
    }
    
    // 通过反射寻找指定名称的字段
    function findField(clazz, fieldName) {
        try {
            let currentClass = clazz;
            while (currentClass) {
                try {
                    const field = currentClass.getDeclaredField(fieldName);
                    if (field) return field;
                } catch (e) {
                    // 字段不在当前类中，尝试父类
                }
                
                currentClass = currentClass.getSuperclass();
                if (!currentClass || currentClass.toString().includes("java.lang.Object")) {
                    break;
                }
            }
        } catch (e) {
            logger.debug(tag, `查找字段 ${fieldName} 时出错: ${e}`);
        }
        return null;
    }
    
    // 从DexFile对象提取DEX字节码
    function extractDexBytes(dexFile) {
        try {
            // 尝试使用反射获取mCookie或cookie字段
            const dexFileClass = dexFile.getClass();
            let cookieField = findField(dexFileClass, "mCookie");
            if (!cookieField) {
                cookieField = findField(dexFileClass, "cookie");
            }
            
            if (!cookieField) {
                logger.debug(tag, "无法找到cookie字段");
                return null;
            }
            
            cookieField.setAccessible(true);
            const cookie = cookieField.get(dexFile);
            if (!cookie) return null;
            
            // 尝试获取Native层DEX数据
            const RuntimeClass = Java.use("java.lang.Runtime");
            const VMStack = Java.use("dalvik.system.VMStack");
            
            const getMethodId = RuntimeClass.class.getDeclaredMethod("getRuntime");
            const nativeGetDexMethodId = dexFileClass.getDeclaredMethod("openDexFile", Java.use("java.lang.String").class);
            const tidyId = VMStack.class.getDeclaredMethod("getCallingClassLoader");
            
            getMethodId.setAccessible(true);
            nativeGetDexMethodId.setAccessible(true);
            tidyId.setAccessible(true);
            
            // 使用openMemory方法提取DEX字节
            const mem = dexFile.getClass().getDeclaredMethod("openMemory", Java.use("[B").class, Java.use("java.lang.String").class);
            mem.setAccessible(true);
            
            // 从内存中读取DEX文件头，确定文件大小
            const memory = new Uint8Array(1024);
            Java.use("java.lang.System").arraycopy(cookie, 0, memory, 0, 1024);
            
            // 检查DEX文件魔数 (dex\n035\0或dex\n036\0等)
            if (memory[0] !== 0x64 || memory[1] !== 0x65 || memory[2] !== 0x78 || memory[3] !== 0x0A) {
                logger.debug(tag, "非DEX文件头");
                return null;
            }
            
            // 读取DEX文件大小 (32位值位于偏移量32处)
            const fileSize = memory[32] | (memory[33] << 8) | (memory[34] << 16) | (memory[35] << 24);
            if (fileSize < config.minDexSize || fileSize > config.maxDexSize) {
                logger.debug(tag, `DEX文件大小不合理: ${fileSize}`);
                return null;
            }
            
            // 提取完整DEX
            const dexBytes = new Uint8Array(fileSize);
            Java.use("java.lang.System").arraycopy(cookie, 0, dexBytes, 0, fileSize);
            return dexBytes;
        } catch (e) {
            logger.debug(tag, `提取DEX字节码时出错: ${e}`);
            return null;
        }
    }
    
    // 保存DEX文件
    function saveDexToFile(dexBytes, fileName) {
        try {
            const file = new File(fileName);
            if (!file.exists()) {
                file.createNewFile();
            }
            
            const out = new FileOutputStream(file);
            out.write(dexBytes);
            out.flush();
            out.close();
            return true;
        } catch (e) {
            logger.error(tag, `保存DEX文件失败 [${fileName}]: ${e}`);
            return false;
        }
    }
    
    // 扫描内存中的DEX文件
    function scanMemoryForDex() {
        try {
            logger.debug(tag, "开始内存扫描...");
            
            // 获取进程映射文件
            const maps = new File("/proc/self/maps");
            if (!maps.exists() || !maps.canRead()) {
                logger.error(tag, "无法读取内存映射");
                return;
            }
            
            const scanner = new Scanner(maps);
            let line;
            
            while (scanner.hasNextLine()) {
                line = scanner.nextLine();
                
                // 查找可读的私有内存区域
                if (line.includes(" r") && line.includes("p ")) {
                    try {
                        const parts = line.trim().split(" ");
                        const addressRange = parts[0];
                        const addresses = addressRange.split("-");
                        
                        if (addresses.length === 2) {
                            const startAddress = Java.use("java.lang.Long").parseLong(addresses[0], 16);
                            const endAddress = Java.use("java.lang.Long").parseLong(addresses[1], 16);
                            const size = endAddress - startAddress;
                            
                            // 只检查合理大小的内存区域，避免过大分配
                            const MAX_SAFE_CHUNK = 10 * 1024 * 1024; // 10MB
                            if (size >= 1024 * 1024 && size <= 100 * 1024 * 1024) {
                                // 对较大内存区域分块处理，避免一次性分配过大内存
                                if (size > MAX_SAFE_CHUNK) {
                                    logger.debug(tag, `分块处理大内存区域: ${addressRange} (${Math.floor(size / (1024 * 1024))}MB)`);
                                    
                                    // 分块扫描
                                    for (let offset = 0; offset < size; offset += MAX_SAFE_CHUNK) {
                                        const chunkSize = Math.min(MAX_SAFE_CHUNK, size - offset);
                                        const chunkAddress = startAddress + offset;
                                        
                                        try {
                                            const memoryChunk = new Uint8Array(chunkSize);
                                            const success = dumpMemoryRegion(chunkAddress, memoryChunk, chunkSize);
                                            
                                            if (success) {
                                                extractDexFromMemory(memoryChunk, chunkSize);
                                            }
                                        } catch (chunkError) {
                                            logger.debug(tag, `处理内存块出错 [${offset}/${size}]: ${chunkError}`);
                                            // 继续处理下一块
                                        }
                                    }
                                } else {
                                    // 小内存区域直接处理
                                    const memoryDump = new Uint8Array(size);
                                    const success = dumpMemoryRegion(startAddress, memoryDump, size);
                                    
                                    if (success) {
                                        extractDexFromMemory(memoryDump, size);
                                    }
                                }
                            }
                        }
                    } catch (e) {
                        logger.debug(tag, `处理内存区域出错: ${e}`);
                        // 继续处理下一行
                    }
                }
            }
            
            scanner.close();
            logger.debug(tag, "内存扫描完成");
        } catch (e) {
            logger.error(tag, `内存扫描异常: ${e}`);
        }
    }
    
    // 转储特定内存区域
    function dumpMemoryRegion(address, buffer, size) {
        try {
            // 这里需要使用Native层方法读取内存
            // 在Frida中，可以使用Memory API
            Memory.readByteArray(ptr(address), buffer, size);
            return true;
        } catch (e) {
            logger.debug(tag, `读取内存区域失败 [${address}]: ${e}`);
            return false;
        }
    }
    
    // 从内存数据中提取DEX文件
    function extractDexFromMemory(memoryDump, size) {
        try {
            // DEX文件标识
            const dexMagic = [0x64, 0x65, 0x78, 0x0A];  // "dex\n"
            
            let offset = 0;
            while (offset < size - 4) {
                // 检查DEX文件头
                if (memoryDump[offset] === dexMagic[0] &&
                    memoryDump[offset + 1] === dexMagic[1] &&
                    memoryDump[offset + 2] === dexMagic[2] &&
                    memoryDump[offset + 3] === dexMagic[3]) {
                    
                    // 读取DEX文件大小
                    const fileSize = memoryDump[offset + 32] |
                                   (memoryDump[offset + 33] << 8) |
                                   (memoryDump[offset + 34] << 16) |
                                   (memoryDump[offset + 35] << 24);
                    
                    if (fileSize >= config.minDexSize && fileSize <= config.maxDexSize && offset + fileSize <= size) {
                        // 提取DEX文件
                        const dexBytes = new Uint8Array(fileSize);
                        for (let i = 0; i < fileSize; i++) {
                            dexBytes[i] = memoryDump[offset + i];
                        }
                        
                        // 验证文件完整性
                        if (isValidDex(dexBytes)) {
                            const dexHash = Java.use("java.util.Arrays").hashCode(dexBytes);
                            if (!extractedDexHashes.has(dexHash)) {
                                extractedDexHashes.add(dexHash);
                                
                                const fileName = `${config.outputDir}memory_${String(stats.dexFiles + 1).padStart(2, '0')}.dex`;
                                saveDexToFile(dexBytes, fileName);
                                
                                logger.info(tag, `提取DEX文件: ${fileName} [大小: ${fileSize} 字节, 从内存]`);
                                stats.dexFiles++;
                                stats.totalBytes += fileSize;
                            }
                        }
                    }
                    
                    // 跳过这个DEX文件
                    offset += Math.max(100, fileSize);
                } else {
                    offset++;
                }
            }
        } catch (e) {
            logger.debug(tag, `提取内存DEX出错: ${e}`);
        }
    }
    
    // 验证DEX文件有效性
    function isValidDex(dexBytes) {
        try {
            // 验证DEX魔数
            if (dexBytes[0] !== 0x64 || dexBytes[1] !== 0x65 ||
                dexBytes[2] !== 0x78 || dexBytes[3] !== 0x0A) {
                return false;
            }
            
            // 验证文件大小
            const fileSize = dexBytes[32] | (dexBytes[33] << 8) | 
                            (dexBytes[34] << 16) | (dexBytes[35] << 24);
            
            if (fileSize !== dexBytes.length) {
                return false;
            }
            
            // 检查其他DEX结构
            const headerSize = dexBytes[36] | (dexBytes[37] << 8) | 
                             (dexBytes[38] << 16) | (dexBytes[39] << 24);
            
            if (headerSize < 70 || headerSize > 1024) {
                return false;
            }
            
            return true;
        } catch (e) {
            return false;
        }
    }
    
    // 强制加载所有类
    function forceLoadAllClasses() {
        try {
            logger.debug(tag, "开始加载所有类...");
            
            // 获取已加载的所有类
            const ActivityThread = Java.use("android.app.ActivityThread");
            const currentApplication = ActivityThread.currentApplication();
            if (!currentApplication) {
                logger.debug(tag, "无法获取当前应用");
                return;
            }
            
            const context = currentApplication.getApplicationContext();
            const packageName = context.getPackageName();
            
            // 获取ClassLoader
            const classLoader = context.getClassLoader();
            if (!classLoader) {
                logger.debug(tag, "无法获取ClassLoader");
                return;
            }
            
            // 获取所有已声明的类名
            const DexFile = Java.use("dalvik.system.DexFile");
            const optimizedDir = context.getFilesDir().getParentFile().getPath() + "/cache";
            
            // 应用的APK路径
            const appInfo = context.getPackageManager().getApplicationInfo(packageName, 0);
            const sourceApk = appInfo.sourceDir;
            
            logger.debug(tag, `扫描APK中的类: ${sourceApk}`);
            const dexFile = DexFile.loadDex(sourceApk, optimizedDir + "/opt.dex", 0);
            const classNameEnum = dexFile.entries();
            
            let loadedCount = 0;
            while (classNameEnum.hasMoreElements()) {
                try {
                    const className = classNameEnum.nextElement();
                    
                    // 过滤系统类
                    if (config.filterSystemClasses && 
                        (className.startsWith("android.") || 
                         className.startsWith("java.") || 
                         className.startsWith("javax.") ||
                         className.startsWith("dalvik."))) {
                        continue;
                    }
                    
                    // 尝试加载类
                    try {
                        classLoader.loadClass(className);
                        loadedCount++;
                        
                        if (loadedCount % 100 === 0) {
                            logger.debug(tag, `已加载 ${loadedCount} 个类...`);
                        }
                    } catch (e) {
                        // 忽略加载失败的类
                    }
                } catch (e) {
                    // 忽略单个类处理错误
                }
            }
            
            logger.info(tag, `完成类加载，共加载 ${loadedCount} 个类`);
        } catch (e) {
            logger.error(tag, `强制类加载时出错: ${e}`);
        }
    }
    
    // 针对特定保护的专用钩子
    function setupSpecificProtectionHooks() {
        // 针对梆梆加固
        if (config.supportedProtections.includes("梆梆")) {
            try {
                // 梆梆加固常用类
                const targetClasses = [
                    "com.secneo.apkwrapper.AW",
                    "com.secneo.apkwrapper.H"
                ];
                
                targetClasses.forEach(className => {
                    try {
                        const clazz = Java.use(className);
                        
                        // 钩住所有方法
                        for (const methodName in clazz) {
                            if (typeof clazz[methodName] === 'function' && methodName !== '$init') {
                                const overloads = clazz[methodName].overloads;
                                if (overloads) {
                                    overloads.forEach(function(overload) {
                                        overload.implementation = function() {
                                            const result = overload.apply(this, arguments);
                                            
                                            logger.debug(tag, `梆梆加固API调用: ${className}.${methodName}`);
                                            setTimeout(function() { 
                                                dumpClassLoaderDex(Java.classFactory.loader); 
                                            }, 100);
                                            
                                            return result;
                                        };
                                    });
                                }
                            }
                        }
                        
                        logger.info(tag, `梆梆加固钩子设置成功: ${className}`);
                    } catch (e) {
                        logger.debug(tag, `梆梆加固类未找到: ${className}`);
                    }
                });
            } catch (e) {
                logger.debug(tag, `梆梆加固钩子设置失败: ${e}`);
            }
        }
        
        // 针对爱加密
        if (config.supportedProtections.includes("爱加密")) {
            try {
                const targetMethods = [
                    { class: "s.h.e.a.a", method: "d" },
                    { class: "s.h.e.a.a", method: "b" }
                ];
                
                targetMethods.forEach(target => {
                    try {
                        const clazz = Java.use(target.class);
                        clazz[target.method].overloads.forEach(function(overload) {
                            overload.implementation = function() {
                                const result = overload.apply(this, arguments);
                                
                                logger.debug(tag, `爱加密API调用: ${target.class}.${target.method}`);
                                setTimeout(function() { 
                                    dumpClassLoaderDex(Java.classFactory.loader); 
                                }, 100);
                                
                                return result;
                            };
                        });
                        
                        logger.info(tag, `爱加密钩子设置成功: ${target.class}.${target.method}`);
                    } catch (e) {
                        logger.debug(tag, `爱加密方法未找到: ${target.class}.${target.method}`);
                    }
                });
            } catch (e) {
                logger.debug(tag, `爱加密钩子设置失败: ${e}`);
            }
        }
        
        // 360加固
        if (config.supportedProtections.includes("360加固")) {
            try {
                const qihooClasses = [
                    "com.qihoo.util.StubApp",
                    "com.qihoo.helper.Stubp"
                ];
                
                qihooClasses.forEach(className => {
                    try {
                        const qihoo = Java.use(className);
                        qihoo.a.overloads.forEach(function(overload) {
                            overload.implementation = function() {
                                const result = overload.apply(this, arguments);
                                
                                logger.debug(tag, `360加固API调用: ${className}.a`);
                                setTimeout(function() { 
                                    dumpClassLoaderDex(Java.classFactory.loader); 
                                }, 100);
                                
                                return result;
                            };
                        });
                        
                        logger.info(tag, `360加固钩子设置成功: ${className}`);
                    } catch (e) {
                        logger.debug(tag, `360加固类未找到: ${className}`);
                    }
                });
            } catch (e) {
                logger.debug(tag, `360加固钩子设置失败: ${e}`);
            }
        }
        
        // 腾讯乐固
        if (config.supportedProtections.includes("腾讯乐固")) {
            try {
                const leguClasses = [
                    "com.tencent.StubShell.TxAppEntry",
                    "com.tencent.secureSDK.StubApplication"
                ];
                
                leguClasses.forEach(className => {
                    try {
                        const leguClass = Java.use(className);
                        
                        // 附加钩子到onCreate方法
                        leguClass.onCreate.implementation = function() {
                            const result = this.onCreate();
                            
                            logger.debug(tag, `腾讯乐固API调用: ${className}.onCreate`);
                            setTimeout(function() { 
                                dumpClassLoaderDex(Java.classFactory.loader);
                                // 腾讯乐固通常在应用启动后完成解密
                                forceLoadAllClasses();
                            }, 2000);
                            
                            return result;
                        };
                        
                        logger.info(tag, `腾讯乐固钩子设置成功: ${className}`);
                    } catch (e) {
                        logger.debug(tag, `腾讯乐固类未找到: ${className}`);
                    }
                });
            } catch (e) {
                logger.debug(tag, `腾讯乐固钩子设置失败: ${e}`);
            }
        }
        
        // 阿里聚安全
        if (config.supportedProtections.includes("阿里聚安全")) {
            try {
                const aliClasses = [
                    "com.alibaba.mobile.security.jaq.JaqApplication",
                    "com.alibaba.security.realidentity.SecureApplication",
                    "com.ali.mobisecenhance.StubApplication"
                ];
                
                aliClasses.forEach(className => {
                    try {
                        const aliClass = Java.use(className);
                        
                        // 附加钩子到attachBaseContext方法
                        if (aliClass.attachBaseContext) {
                            aliClass.attachBaseContext.overload('android.content.Context').implementation = function(context) {
                                const result = this.attachBaseContext(context);
                                
                                logger.debug(tag, `阿里聚安全API调用: ${className}.attachBaseContext`);
                                setTimeout(function() { 
                                    dumpClassLoaderDex(Java.classFactory.loader);
                                    forceLoadAllClasses();
                                }, 1000);
                                
                                return result;
                            };
                            logger.info(tag, `阿里聚安全钩子设置成功: ${className}.attachBaseContext`);
                        }
                        
                        // 附加钩子到onCreate方法
                        if (aliClass.onCreate) {
                            aliClass.onCreate.implementation = function() {
                                const result = this.onCreate();
                                
                                logger.debug(tag, `阿里聚安全API调用: ${className}.onCreate`);
                                setTimeout(function() { 
                                    dumpClassLoaderDex(Java.classFactory.loader);
                                }, 1000);
                                
                                return result;
                            };
                            logger.info(tag, `阿里聚安全钩子设置成功: ${className}.onCreate`);
                        }
                        
                    } catch (e) {
                        logger.debug(tag, `阿里聚安全类未找到: ${className}`);
                    }
                });
                
                // 钩住EMAS安全SDK
                try {
                    const emasSecurity = Java.use("com.alibaba.wireless.security.framework.SecurityGuardManager");
                    emasSecurity.getSecurityGuardManager.implementation = function() {
                        const result = this.getSecurityGuardManager();
                        
                        logger.debug(tag, "阿里安全SDK调用: SecurityGuardManager.getSecurityGuardManager");
                        dumpClassLoaderDex(Java.classFactory.loader);
                        
                        return result;
                    };
                    logger.info(tag, "阿里安全SDK钩子设置成功");
                } catch (e) {
                    logger.debug(tag, "阿里安全SDK类未找到");
                }
                
            } catch (e) {
                logger.debug(tag, `阿里聚安全钩子设置失败: ${e}`);
            }
        }
        
        // 百度加固
        if (config.supportedProtections.includes("百度加固")) {
            try {
                const baiduClasses = [
                    "com.baidu.protect.StubApplication",
                    "com.baidu.protect.A"
                ];
                
                baiduClasses.forEach(className => {
                    try {
                        const baiduClass = Java.use(className);
                        
                        // 附加钩子到attachBaseContext方法
                        if (baiduClass.attachBaseContext) {
                            baiduClass.attachBaseContext.overload('android.content.Context').implementation = function(context) {
                                const result = this.attachBaseContext(context);
                                
                                logger.debug(tag, `百度加固API调用: ${className}.attachBaseContext`);
                                setTimeout(function() { 
                                    dumpClassLoaderDex(Java.classFactory.loader);
                                }, 500);
                                
                                return result;
                            };
                            logger.info(tag, `百度加固钩子设置成功: ${className}.attachBaseContext`);
                        }
                        
                        // 针对特殊方法a
                        if (baiduClass.a && baiduClass.a.overloads) {
                            baiduClass.a.overloads.forEach(function(overload) {
                                overload.implementation = function() {
                                    const result = overload.apply(this, arguments);
                                    
                                    logger.debug(tag, `百度加固API调用: ${className}.a`);
                                    setTimeout(function() { 
                                        dumpClassLoaderDex(Java.classFactory.loader);
                                    }, 500);
                                    
                                    return result;
                                };
                            });
                            
                            logger.info(tag, `百度加固钩子设置成功: ${className}.a`);
                        }
                        
                    } catch (e) {
                        logger.debug(tag, `百度加固类未找到: ${className}`);
                    }
                });
            } catch (e) {
                logger.debug(tag, `百度加固钩子设置失败: ${e}`);
            }
        }
        
        // 娜迦加固(nagapt)
        if (config.supportedProtections.includes("娜迦")) {
            try {
                const nagaClasses = [
                    "com.nagapt.StubApp",
                    "com.nagapt.a.a"
                ];
                
                nagaClasses.forEach(className => {
                    try {
                        const nagaClass = Java.use(className);
                        
                        // 遍历所有方法
                        for (const methodName in nagaClass) {
                            if (typeof nagaClass[methodName] === 'function' && methodName !== '$init') {
                                const overloads = nagaClass[methodName].overloads;
                                if (overloads) {
                                    overloads.forEach(function(overload) {
                                        overload.implementation = function() {
                                            const result = overload.apply(this, arguments);
                                            
                                            logger.debug(tag, `娜迦加固API调用: ${className}.${methodName}`);
                                            setTimeout(function() { 
                                                dumpClassLoaderDex(Java.classFactory.loader); 
                                            }, 100);
                                            
                                            return result;
                                        };
                                    });
                                    
                                    logger.info(tag, `娜迦加固钩子设置成功: ${className}.${methodName}`);
                                }
                            }
                        }
                    } catch (e) {
                        logger.debug(tag, `娜迦加固类未找到: ${className}`);
                    }
                });
            } catch (e) {
                logger.debug(tag, `娜迦加固钩子设置失败: ${e}`);
            }
        }
        
        // 盛大加固
        if (config.supportedProtections.includes("盛大加固")) {
            try {
                const shenDaClasses = [
                    "com.shendu.ProxyApplication",
                    "com.shendu.SdApplication"
                ];
                
                shenDaClasses.forEach(className => {
                    try {
                        const sdClass = Java.use(className);
                        
                        // 附加钩子到attachBaseContext方法
                        if (sdClass.attachBaseContext) {
                            sdClass.attachBaseContext.overload('android.content.Context').implementation = function(context) {
                                const result = this.attachBaseContext(context);
                                
                                logger.debug(tag, `盛大加固API调用: ${className}.attachBaseContext`);
                                setTimeout(function() { 
                                    dumpClassLoaderDex(Java.classFactory.loader);
                                }, 500);
                                
                                return result;
                            };
                            logger.info(tag, `盛大加固钩子设置成功: ${className}.attachBaseContext`);
                        }
                    } catch (e) {
                        logger.debug(tag, `盛大加固类未找到: ${className}`);
                    }
                });
            } catch (e) {
                logger.debug(tag, `盛大加固钩子设置失败: ${e}`);
            }
        }
        
        // 网秦加固
        if (config.supportedProtections.includes("网秦加固")) {
            try {
                const nqClasses = [
                    "com.nqshield.NqApplication",
                    "com.netqin.shield.StubApp"
                ];
                
                nqClasses.forEach(className => {
                    try {
                        const nqClass = Java.use(className);
                        
                        // 附加钩子到attachBaseContext方法
                        if (nqClass.attachBaseContext) {
                            nqClass.attachBaseContext.overload('android.content.Context').implementation = function(context) {
                                const result = this.attachBaseContext(context);
                                
                                logger.debug(tag, `网秦加固API调用: ${className}.attachBaseContext`);
                                setTimeout(function() { 
                                    dumpClassLoaderDex(Java.classFactory.loader);
                                    forceLoadAllClasses();
                                }, 1000);
                                
                                return result;
                            };
                            logger.info(tag, `网秦加固钩子设置成功: ${className}.attachBaseContext`);
                        }
                    } catch (e) {
                        logger.debug(tag, `网秦加固类未找到: ${className}`);
                    }
                });
            } catch (e) {
                logger.debug(tag, `网秦加固钩子设置失败: ${e}`);
            }
        }
        
        // 几维安全
        if (config.supportedProtections.includes("几维安全")) {
            try {
                const keeweeClasses = [
                    "com.kiwisec.KiwiSecApplication",
                    "com.kiwisec.dexprotect.KiwiSecApplication"
                ];
                
                keeweeClasses.forEach(className => {
                    try {
                        const keeweeClass = Java.use(className);
                        
                        // 附加钩子到所有方法
                        for (const methodName in keeweeClass) {
                            if (typeof keeweeClass[methodName] === 'function' && methodName !== '$init') {
                                const overloads = keeweeClass[methodName].overloads;
                                if (overloads) {
                                    overloads.forEach(function(overload) {
                                        overload.implementation = function() {
                                            const result = overload.apply(this, arguments);
                                            
                                            logger.debug(tag, `几维安全API调用: ${className}.${methodName}`);
                                            setTimeout(function() { 
                                                dumpClassLoaderDex(Java.classFactory.loader); 
                                            }, 100);
                                            
                                            return result;
                                        };
                                    });
                                }
                            }
                        }
                        
                        logger.info(tag, `几维安全钩子设置成功: ${className}`);
                    } catch (e) {
                        logger.debug(tag, `几维安全类未找到: ${className}`);
                    }
                });
            } catch (e) {
                logger.debug(tag, `几维安全钩子设置失败: ${e}`);
            }
        }
        
        // 通付盾
        if (config.supportedProtections.includes("通付盾")) {
            try {
                const tfdClasses = [
                    "com.payegis.ProxyApplication",
                    "com.payegis.StubApp"
                ];
                
                tfdClasses.forEach(className => {
                    try {
                        const tfdClass = Java.use(className);
                        
                        // 附加钩子到attachBaseContext方法
                        if (tfdClass.attachBaseContext) {
                            tfdClass.attachBaseContext.overload('android.content.Context').implementation = function(context) {
                                const result = this.attachBaseContext(context);
                                
                                logger.debug(tag, `通付盾API调用: ${className}.attachBaseContext`);
                                setTimeout(function() { 
                                    dumpClassLoaderDex(Java.classFactory.loader);
                                }, 500);
                                
                                return result;
                            };
                            logger.info(tag, `通付盾钩子设置成功: ${className}.attachBaseContext`);
                        }
                    } catch (e) {
                        logger.debug(tag, `通付盾类未找到: ${className}`);
                    }
                });
            } catch (e) {
                logger.debug(tag, `通付盾钩子设置失败: ${e}`);
            }
        }
        
        // 瑞星加固
        if (config.supportedProtections.includes("瑞星加固")) {
            try {
                const rsClasses = [
                    "com.rising.RSProtect",
                    "com.rising.StubApp"
                ];
                
                rsClasses.forEach(className => {
                    try {
                        const rsClass = Java.use(className);
                        
                        // 附加钩子到初始化方法
                        if (rsClass.a && rsClass.a.overloads) {
                            rsClass.a.overloads.forEach(function(overload) {
                                overload.implementation = function() {
                                    const result = overload.apply(this, arguments);
                                    
                                    logger.debug(tag, `瑞星加固API调用: ${className}.a`);
                                    setTimeout(function() { 
                                        dumpClassLoaderDex(Java.classFactory.loader);
                                    }, 500);
                                    
                                    return result;
                                };
                            });
                            
                            logger.info(tag, `瑞星加固钩子设置成功: ${className}.a`);
                        }
                    } catch (e) {
                        logger.debug(tag, `瑞星加固类未找到: ${className}`);
                    }
                });
            } catch (e) {
                logger.debug(tag, `瑞星加固钩子设置失败: ${e}`);
            }
        }
        
        // APKProtect加固
        if (config.supportedProtections.includes("APKProtect")) {
            try {
                const apkpClasses = [
                    "com.apkprotect.ApkProtect",
                    "com.apkprotect.StubApp"
                ];
                
                apkpClasses.forEach(className => {
                    try {
                        const apkpClass = Java.use(className);
                        
                        // 附加钩子到所有方法
                        for (const methodName in apkpClass) {
                            if (typeof apkpClass[methodName] === 'function' && methodName !== '$init') {
                                const overloads = apkpClass[methodName].overloads;
                                if (overloads) {
                                    overloads.forEach(function(overload) {
                                        overload.implementation = function() {
                                            const result = overload.apply(this, arguments);
                                            
                                            logger.debug(tag, `APKProtect API调用: ${className}.${methodName}`);
                                            setTimeout(function() { 
                                                dumpClassLoaderDex(Java.classFactory.loader); 
                                            }, 100);
                                            
                                            return result;
                                        };
                                    });
                                }
                            }
                        }
                        
                        logger.info(tag, `APKProtect钩子设置成功: ${className}`);
                    } catch (e) {
                        logger.debug(tag, `APKProtect类未找到: ${className}`);
                    }
                });
            } catch (e) {
                logger.debug(tag, `APKProtect钩子设置失败: ${e}`);
            }
        }
        
        // 顶像科技
        if (config.supportedProtections.includes("顶像科技")) {
            try {
                const dvmClasses = [
                    "com.dx.CodeSafeApplication",
                    "com.dx.dxprotect.StubApp"
                ];
                
                dvmClasses.forEach(className => {
                    try {
                        const dvmClass = Java.use(className);
                        
                        // 附加钩子到attachBaseContext方法
                        if (dvmClass.attachBaseContext) {
                            dvmClass.attachBaseContext.overload('android.content.Context').implementation = function(context) {
                                const result = this.attachBaseContext(context);
                                
                                logger.debug(tag, `顶像科技API调用: ${className}.attachBaseContext`);
                                setTimeout(function() { 
                                    dumpClassLoaderDex(Java.classFactory.loader);
                                    forceLoadAllClasses();
                                }, 1000);
                                
                                return result;
                            };
                            logger.info(tag, `顶像科技钩子设置成功: ${className}.attachBaseContext`);
                        }
                    } catch (e) {
                        logger.debug(tag, `顶像科技类未找到: ${className}`);
                    }
                });
            } catch (e) {
                logger.debug(tag, `顶像科技钩子设置失败: ${e}`);
            }
        }
        
        // 珊瑚灵御
        if (config.supportedProtections.includes("珊瑚灵御")) {
            try {
                const coralClasses = [
                    "com.coral.StubApp",
                    "com.coral.protector.CoreApplication"
                ];
                
                coralClasses.forEach(className => {
                    try {
                        const coralClass = Java.use(className);
                        
                        // 附加钩子到attachBaseContext方法
                        if (coralClass.attachBaseContext) {
                            coralClass.attachBaseContext.overload('android.content.Context').implementation = function(context) {
                                const result = this.attachBaseContext(context);
                                
                                logger.debug(tag, `珊瑚灵御API调用: ${className}.attachBaseContext`);
                                setTimeout(function() { 
                                    dumpClassLoaderDex(Java.classFactory.loader);
                                    forceLoadAllClasses();
                                }, 1500);
                                
                                return result;
                            };
                            logger.info(tag, `珊瑚灵御钩子设置成功: ${className}.attachBaseContext`);
                        }
                    } catch (e) {
                        logger.debug(tag, `珊瑚灵御类未找到: ${className}`);
                    }
                });
            } catch (e) {
                logger.debug(tag, `珊瑚灵御钩子设置失败: ${e}`);
            }
        }
        
        // 金丝雀加固
        if (config.supportedProtections.includes("金丝雀")) {
            try {
                const canaryClasses = [
                    "com.canary.SafeApp",
                    "com.canary.StubApp"
                ];
                
                canaryClasses.forEach(className => {
                    try {
                        const canaryClass = Java.use(className);
                        
                        // 附加钩子到attachBaseContext方法
                        if (canaryClass.attachBaseContext) {
                            canaryClass.attachBaseContext.overload('android.content.Context').implementation = function(context) {
                                const result = this.attachBaseContext(context);
                                
                                logger.debug(tag, `金丝雀加固API调用: ${className}.attachBaseContext`);
                                setTimeout(function() { 
                                    dumpClassLoaderDex(Java.classFactory.loader);
                                }, 800);
                                
                                return result;
                            };
                            logger.info(tag, `金丝雀加固钩子设置成功: ${className}.attachBaseContext`);
                        }
                    } catch (e) {
                        logger.debug(tag, `金丝雀加固类未找到: ${className}`);
                    }
                });
            } catch (e) {
                logger.debug(tag, `金丝雀加固钩子设置失败: ${e}`);
            }
        }
        
        // 华为HMS加固
        if (config.supportedProtections.includes("华为HMS加固")) {
            try {
                const huaweiClasses = [
                    "com.huawei.hms.support.api.client.HmsClient",
                    "com.huawei.hms.support.api.opendevice.HmsOpenDeviceClient",
                    "com.huawei.hms.update.provider.UpdateProvider",
                    "com.huawei.hms.security.SecHmsApplication"
                ];
                
                huaweiClasses.forEach(className => {
                    try {
                        const huaweiClass = Java.use(className);
                        
                        // 附加钩子到所有方法
                        for (const methodName in huaweiClass) {
                            if (typeof huaweiClass[methodName] === 'function' && methodName !== '$init') {
                                const overloads = huaweiClass[methodName].overloads;
                                if (overloads) {
                                    overloads.forEach(function(overload) {
                                        overload.implementation = function() {
                                            const result = overload.apply(this, arguments);
                                            
                                            logger.debug(tag, `华为HMS调用: ${className}.${methodName}`);
                                            setTimeout(function() {
                                                dumpClassLoaderDex(Java.classFactory.loader);
                                            }, 300);
                                            
                                            return result;
                                        };
                                    });
                                }
                            }
                        }
                        
                        logger.info(tag, `华为HMS加固钩子设置成功: ${className}`);
                    } catch (e) {
                        logger.debug(tag, `华为HMS加固类未找到: ${className}`);
                    }
                });
            } catch (e) {
                logger.debug(tag, `华为HMS加固钩子设置失败: ${e}`);
            }
        }

        // 华为安全/华为加固
        if (config.supportedProtections.includes("华为安全")) {
            try {
                const huaweiSecClasses = [
                    "com.huawei.security.SecAppApplication",
                    "com.huawei.security.HwSecManager",
                    "com.huawei.secure.android.SecApp",
                    "com.huawei.secure.android.SecDex"
                ];
                
                huaweiSecClasses.forEach(className => {
                    try {
                        const huaweiSecClass = Java.use(className);
                        
                        // 附加钩子到attachBaseContext方法
                        if (huaweiSecClass.attachBaseContext) {
                            huaweiSecClass.attachBaseContext.overload('android.content.Context').implementation = function(context) {
                                const result = this.attachBaseContext(context);
                                
                                logger.debug(tag, `华为安全加固API调用: ${className}.attachBaseContext`);
                                setTimeout(function() { 
                                    dumpClassLoaderDex(Java.classFactory.loader);
                                    scanMemoryForDex();
                                }, 1000);
                                
                                return result;
                            };
                            logger.info(tag, `华为安全加固钩子设置成功: ${className}.attachBaseContext`);
                        }
                    } catch (e) {
                        logger.debug(tag, `华为安全加固类未找到: ${className}`);
                    }
                });
            } catch (e) {
                logger.debug(tag, `华为安全加固钩子设置失败: ${e}`);
            }
        }
        
        // 海思加固
        if (config.supportedProtections.includes("海思加固")) {
            try {
                const hiSiliconClasses = [
                    "com.hisilicon.hisec.HiSecureApplication",
                    "com.hisilicon.secruntime.SecDexLoader",
                    "com.hisilicon.secwrapper.SecWrapperApp"
                ];
                
                hiSiliconClasses.forEach(className => {
                    try {
                        const hiSiliconClass = Java.use(className);
                        
                        // 附加钩子到常用方法
                        if (hiSiliconClass.attachBaseContext) {
                            hiSiliconClass.attachBaseContext.overload('android.content.Context').implementation = function(context) {
                                const result = this.attachBaseContext(context);
                                
                                logger.debug(tag, `海思加固API调用: ${className}.attachBaseContext`);
                                setTimeout(function() { 
                                    dumpClassLoaderDex(Java.classFactory.loader);
                                }, 800);
                                
                                return result;
                            };
                            logger.info(tag, `海思加固钩子设置成功: ${className}.attachBaseContext`);
                        }
                        
                        // 钩住可能的加载方法
                        if (hiSiliconClass.loadDex) {
                            hiSiliconClass.loadDex.overloads.forEach(function(overload) {
                                overload.implementation = function() {
                                    const result = overload.apply(this, arguments);
                                    
                                    logger.debug(tag, `海思加固API调用: ${className}.loadDex`);
                                    setTimeout(function() { 
                                        dumpClassLoaderDex(Java.classFactory.loader);
                                        scanMemoryForDex(); 
                                    }, 500);
                                    
                                    return result;
                                };
                            });
                            logger.info(tag, `海思加固钩子设置成功: ${className}.loadDex`);
                        }
                    } catch (e) {
                        logger.debug(tag, `海思加固类未找到: ${className}`);
                    }
                });
            } catch (e) {
                logger.debug(tag, `海思加固钩子设置失败: ${e}`);
            }
        }
        
        // 新版爱加密 (ijiami)
        if (config.supportedProtections.includes("新版爱加密")) {
            try {
                const ijiamiClasses = [
                    "com.ijiami.sdk.ProxyApplication",
                    "com.shell.SuperApplication",
                    "com.shell.NativeApplication",
                    "com.ijiami.residmap.shell.DXApplication"
                ];
                
                ijiamiClasses.forEach(className => {
                    try {
                        const ijiamiClass = Java.use(className);
                        
                        // 附加钩子到attachBaseContext方法
                        if (ijiamiClass.attachBaseContext) {
                            ijiamiClass.attachBaseContext.overload('android.content.Context').implementation = function(context) {
                                const result = this.attachBaseContext(context);
                                
                                logger.debug(tag, `新版爱加密API调用: ${className}.attachBaseContext`);
                                setTimeout(function() { 
                                    dumpClassLoaderDex(Java.classFactory.loader);
                                }, 800);
                                
                                return result;
                            };
                            logger.info(tag, `新版爱加密钩子设置成功: ${className}.attachBaseContext`);
                        }
                        
                        // 附加钩子到onCreate方法
                        if (ijiamiClass.onCreate) {
                            ijiamiClass.onCreate.implementation = function() {
                                const result = this.onCreate();
                                
                                logger.debug(tag, `新版爱加密API调用: ${className}.onCreate`);
                                setTimeout(function() { 
                                    dumpClassLoaderDex(Java.classFactory.loader);
                                    forceLoadAllClasses();
                                }, 1500);
                                
                                return result;
                            };
                            logger.info(tag, `新版爱加密钩子设置成功: ${className}.onCreate`);
                        }
                    } catch (e) {
                        logger.debug(tag, `新版爱加密类未找到: ${className}`);
                    }
                });
            } catch (e) {
                logger.debug(tag, `新版爱加密钩子设置失败: ${e}`);
            }
        }
        
        // 携程加固
        if (config.supportedProtections.includes("携程加固")) {
            try {
                const ctripClasses = [
                    "com.ctrip.shield.ShieldApplication",
                    "com.ctrip.shield.wrapper.DelegateWrapper",
                    "com.ctrip.shield.wrapper.Shield"
                ];
                
                ctripClasses.forEach(className => {
                    try {
                        const ctripClass = Java.use(className);
                        
                        // 遍历类中的所有方法
                        for (const methodName in ctripClass) {
                            if (typeof ctripClass[methodName] === 'function' && methodName !== '$init') {
                                const overloads = ctripClass[methodName].overloads;
                                if (overloads) {
                                    overloads.forEach(function(overload) {
                                        overload.implementation = function() {
                                            const result = overload.apply(this, arguments);
                                            
                                            logger.debug(tag, `携程加固API调用: ${className}.${methodName}`);
                                            setTimeout(function() { 
                                                dumpClassLoaderDex(Java.classFactory.loader); 
                                            }, 500);
                                            
                                            return result;
                                        };
                                    });
                                }
                            }
                        }
                        
                        logger.info(tag, `携程加固钩子设置成功: ${className}`);
                    } catch (e) {
                        logger.debug(tag, `携程加固类未找到: ${className}`);
                    }
                });
            } catch (e) {
                logger.debug(tag, `携程加固钩子设置失败: ${e}`);
            }
        }
        
        // 微信小程序加固
        if (config.supportedProtections.includes("微信小程序加固")) {
            try {
                const wxClasses = [
                    "com.tencent.mm.app.MMApplicationImpl",
                    "com.tencent.mm.sdk.platformtools.Xg",  // 微信DEX加载类
                    "com.tencent.tinker.loader.TinkerLoader" // 微信Tinker相关
                ];
                
                wxClasses.forEach(className => {
                    try {
                        const wxClass = Java.use(className);
                        
                        // 拦截所有函数调用
                        for (const methodName in wxClass) {
                            if (typeof wxClass[methodName] === 'function' && methodName !== '$init') {
                                const overloads = wxClass[methodName].overloads;
                                if (overloads) {
                                    overloads.forEach(function(overload) {
                                        overload.implementation = function() {
                                            const result = overload.apply(this, arguments);
                                            
                                            logger.debug(tag, `微信小程序加固API调用: ${className}.${methodName}`);
                                            setTimeout(function() { 
                                                dumpClassLoaderDex(Java.classFactory.loader); 
                                            }, 500);
                                            
                                            return result;
                                        };
                                    });
                                }
                            }
                        }
                        
                        logger.info(tag, `微信小程序加固钩子设置成功: ${className}`);
                    } catch (e) {
                        logger.debug(tag, `微信小程序加固类未找到: ${className}`);
                    }
                });
            } catch (e) {
                logger.debug(tag, `微信小程序加固钩子设置失败: ${e}`);
            }
        }
        
        // 字节跳动加固
        if (config.supportedProtections.includes("字节跳动加固")) {
            try {
                const bytedanceClasses = [
                    "com.bytedance.frameworks.core.encrypt.EncryptUtil",
                    "com.bytedance.bdshield.BDShieldApplication",
                    "com.bytedance.frameworks.baselib.network.http.SSLCertManager",
                    "com.bytedance.shadowhook.ShadowHook",  // ByteDance非常重要的Hook框架类
                    "com.ss.sys.ces.a", // 字节跳动常用的加解密实现类名
                    "com.bytedance.frameworks.core.encrypt.TTEncryptUtils",
                    "com.bytedance.frameworks.core.decrypt.DecryptManager",
                    "com.bytedance.applog.AppLog",
                    "com.bytedance.common.launcher.Main" // 字节跳动启动器
                ];
                
                bytedanceClasses.forEach(className => {
                    try {
                        const bytedanceClass = Java.use(className);
                        
                        // 遍历类中的所有方法
                        for (const methodName in bytedanceClass) {
                            if (typeof bytedanceClass[methodName] === 'function' && methodName !== '$init') {
                                const overloads = bytedanceClass[methodName].overloads;
                                if (overloads) {
                                    overloads.forEach(function(overload) {
                                        overload.implementation = function() {
                                            const result = overload.apply(this, arguments);
                                            
                                            logger.debug(tag, `字节跳动加固API调用: ${className}.${methodName}`);
                                            setTimeout(function() { 
                                                dumpClassLoaderDex(Java.classFactory.loader);
                                                // 对某些重要方法执行额外的内存扫描
                                                if (methodName.includes("decrypt") || 
                                                    methodName.includes("init") || 
                                                    methodName.includes("load")) {
                                                    scanMemoryForDex(); 
                                                }
                                            }, 500);
                                            
                                            return result;
                                        };
                                    });
                                }
                            }
                        }
                        
                        logger.info(tag, `字节跳动加固钩子设置成功: ${className}`);
                    } catch (e) {
                        logger.debug(tag, `字节跳动加固类未找到: ${className}`);
                    }
                });
                
                // 特殊处理：字节跳动的抖音应用加载特定DEX的机制
                try {
                    const ssSecApplication = Java.use("com.ss.android.ugc.aweme.app.SSApplication");
                    if (ssSecApplication.attachBaseContext) {
                        ssSecApplication.attachBaseContext.overload('android.content.Context').implementation = function(context) {
                            const result = this.attachBaseContext(context);
                            
                            logger.debug(tag, "抖音应用加载: SSApplication.attachBaseContext");
                            setTimeout(function() { 
                                dumpClassLoaderDex(context.getClassLoader());
                                // 抖音加载DEX后，强制加载所有类以触发解密
                                forceLoadAllClasses();
                                // 延迟扫描内存
                                setTimeout(scanMemoryForDex, 3000);
                            }, 2000);
                            
                            return result;
                        };
                        logger.info(tag, "抖音应用钩子设置成功");
                    }
                    
                    // 针对抖音特有的类加载器
                    try {
                        const customLoader = Java.use("com.ss.android.ugc.aweme.lancet.g");
                        for (const methodName in customLoader) {
                            if (typeof customLoader[methodName] === 'function' && methodName !== '$init') {
                                const overloads = customLoader[methodName].overloads;
                                if (overloads) {
                                    overloads.forEach(function(overload) {
                                        overload.implementation = function() {
                                            const result = overload.apply(this, arguments);
                                            
                                            logger.debug(tag, `抖音自定义加载器调用: ${methodName}`);
                                            setTimeout(function() { 
                                                dumpClassLoaderDex(Java.classFactory.loader);
                                            }, 500);
                                            
                                            return result;
                                        };
                                    });
                                }
                            }
                        }
                        logger.info(tag, "抖音自定义加载器钩子设置成功");
                    } catch (e) {
                        logger.debug(tag, "抖音自定义加载器类未找到");
                    }
                    
                } catch (e) {
                    logger.debug(tag, "抖音应用类未找到");
                }
            } catch (e) {
                logger.debug(tag, `字节跳动加固钩子设置失败: ${e}`);
            }
        }
        
        // 猎豹加固
        if (config.supportedProtections.includes("猎豹加固")) {
            try {
                const cmClasses = [
                    "com.cheetah.shield.ShieldApplication",
                    "com.cleanmaster.security.CMSecurityManager"
                ];
                
                cmClasses.forEach(className => {
                    try {
                        const cmClass = Java.use(className);
                        
                        // 附加钩子到attachBaseContext方法
                        if (cmClass.attachBaseContext) {
                            cmClass.attachBaseContext.overload('android.content.Context').implementation = function(context) {
                                const result = this.attachBaseContext(context);
                                
                                logger.debug(tag, `猎豹加固API调用: ${className}.attachBaseContext`);
                                setTimeout(function() { 
                                    dumpClassLoaderDex(Java.classFactory.loader);
                                }, 800);
                                
                                return result;
                            };
                            logger.info(tag, `猎豹加固钩子设置成功: ${className}.attachBaseContext`);
                        }
                    } catch (e) {
                        logger.debug(tag, `猎豹加固类未找到: ${className}`);
                    }
                });
            } catch (e) {
                logger.debug(tag, `猎豹加固钩子设置失败: ${e}`);
            }
        }
        
        // OPPO加固
        if (config.supportedProtections.includes("OPPO加固")) {
            try {
                const oppoClasses = [
                    "com.nearme.security.SecShell",
                    "com.coloros.shield.ShieldApplication"
                ];
                
                oppoClasses.forEach(className => {
                    try {
                        const oppoClass = Java.use(className);
                        
                        // 附加钩子到attachBaseContext方法
                        if (oppoClass.attachBaseContext) {
                            oppoClass.attachBaseContext.overload('android.content.Context').implementation = function(context) {
                                const result = this.attachBaseContext(context);
                                
                                logger.debug(tag, `OPPO加固API调用: ${className}.attachBaseContext`);
                                setTimeout(function() { 
                                    dumpClassLoaderDex(Java.classFactory.loader);
                                }, 800);
                                
                                return result;
                            };
                            logger.info(tag, `OPPO加固钩子设置成功: ${className}.attachBaseContext`);
                        }
                    } catch (e) {
                        logger.debug(tag, `OPPO加固类未找到: ${className}`);
                    }
                });
            } catch (e) {
                logger.debug(tag, `OPPO加固钩子设置失败: ${e}`);
            }
        }
        
        // vivo加固
        if (config.supportedProtections.includes("vivo加固")) {
            try {
                const vivoClasses = [
                    "com.vivo.shield.ShieldApplication",
                    "com.bbk.security.SecurityApplication"
                ];
                
                vivoClasses.forEach(className => {
                    try {
                        const vivoClass = Java.use(className);
                        
                        // 附加钩子到attachBaseContext方法
                        if (vivoClass.attachBaseContext) {
                            vivoClass.attachBaseContext.overload('android.content.Context').implementation = function(context) {
                                const result = this.attachBaseContext(context);
                                
                                logger.debug(tag, `vivo加固API调用: ${className}.attachBaseContext`);
                                setTimeout(function() { 
                                    dumpClassLoaderDex(Java.classFactory.loader);
                                }, 800);
                                
                                return result;
                            };
                            logger.info(tag, `vivo加固钩子设置成功: ${className}.attachBaseContext`);
                        }
                    } catch (e) {
                        logger.debug(tag, `vivo加固类未找到: ${className}`);
                    }
                });
            } catch (e) {
                logger.debug(tag, `vivo加固钩子设置失败: ${e}`);
            }
        }

        // 增强的通用脱壳支持
        setupEnhancedUnpackingSupport();
    }
    
    // 增强的通用脱壳支持，适用于任何未知加固
    function setupEnhancedUnpackingSupport() {
        try {
            // 1. 钩住Application类
            const ApplicationClass = Java.use('android.app.Application');
            
            // 钩住attachBaseContext方法，这是大多数加固框架的入口点
            ApplicationClass.attachBaseContext.implementation = function (context) {
                const result = this.attachBaseContext(context);
                
                // 获取实际Application类名
                const appClassName = this.getClass().getName();
                if (!appClassName.startsWith("android.app.")) {
                    logger.debug(tag, `应用程序 attachBaseContext: ${appClassName}`);
                    
                    // 延迟转储，给加固框架时间解密DEX
                    setTimeout(function() { 
                        dumpClassLoaderDex(context.getClassLoader());
                        
                        // 尝试更全面地扫描内存
                        scanMemoryForDex();
                    }, 1000);
                }
                
                return result;
            };
            
            // 2. 钩住ClassLoader的loadClass方法
            // 这部分已在hookClassLoad()中实现
            
            // 3. 钩住常用反射方法，可能用于动态加载DEX
            const ReflectionClass = Java.use('java.lang.reflect.Method');
            
            // 钩住invoke方法
            ReflectionClass.invoke.implementation = function() {
                const result = this.invoke.apply(this, arguments);
                
                // 获取被调用的方法名称和类
                const methodName = this.getName();
                const className = this.getDeclaringClass().getName();
                
                // 关注可能与DEX加载相关的反射调用
                const suspiciousMethods = ["loadDex", "loadClass", "defineClass", "attachBaseContext", "doInBackground"];
                if (suspiciousMethods.some(m => methodName.includes(m))) {
                    logger.debug(tag, `可疑反射调用: ${className}.${methodName}`);
                    
                    setTimeout(function() {
                        dumpClassLoaderDex(Java.classFactory.loader);
                    }, 500);
                }
                
                return result;
            };
            
            logger.info(tag, "增强的通用脱壳支持设置成功");
            
            // 4. 设置定时任务，定期尝试扫描内存和转储
            const periodicDump = setInterval(function() {
                if (stats.dexFiles < 1) {  // 仅当还没有找到DEX文件时执行
                    logger.debug(tag, "执行定期DEX搜索...");
                    dumpClassLoaderDex(Java.classFactory.loader);
                    scanMemoryForDex();
                } else {
                    clearInterval(periodicDump);  // 找到DEX后停止定期搜索
                }
            }, 5000);  // 每5秒尝试一次
            
            // 5. 在应用开始稳定运行后尝试一次全面搜索
            setTimeout(function() {
                logger.debug(tag, "执行全面DEX搜索...");
                scanMemoryForDex();
                forceLoadAllClasses();
                
                // 显示统计信息
                setTimeout(showStats, 3000);
            }, 15000);  // 等待15秒
            
        } catch (e) {
            logger.error(tag, `设置增强脱壳支持失败: ${e}`);
        }
    }
    
    // 判断是否需要处理该类
    function shouldProcessClass(className) {
        if (!className) return false;
        
        // 过滤系统类
        if (config.filterSystemClasses && 
            (className.startsWith("android.") || 
             className.startsWith("java.") || 
             className.startsWith("javax.") ||
             className.startsWith("dalvik."))) {
            return false;
        }
        
        return true;
    }
    
    // 显示统计信息
    function showStats() {
        const endTime = new Date();
        const runTime = (endTime - stats.startTime) / 1000;
        
        logger.info(tag, "==== DEX提取统计信息 ====");
        logger.info(tag, `提取的DEX文件: ${stats.dexFiles}`);
        logger.info(tag, `提取的类文件: ${stats.classFiles}`);
        logger.info(tag, `总大小: ${Math.floor(stats.totalBytes / (1024 * 1024))} MB`);
        logger.info(tag, `唯一ClassLoader数: ${stats.uniqueLoaders.size}`);
        logger.info(tag, `运行时间: ${runTime.toFixed(2)} 秒`);
        logger.info(tag, `输出目录: ${config.outputDir}`);
        logger.info(tag, "=========================");
    }
    
    // 设置输出目录
    function setOutputDirectory(dirPath) {
        if (dirPath && dirPath.length > 0) {
            config.outputDir = dirPath;
            if (!config.outputDir.endsWith('/')) {
                config.outputDir += '/';
            }
            
            logger.debug(tag, `输出目录已设置为: ${config.outputDir}`);
        }
    }
    
    // 启用或禁用系统类过滤
    function setFilterSystemClasses(enabled) {
        config.filterSystemClasses = !!enabled;
        logger.debug(tag, `系统类过滤: ${config.filterSystemClasses ? '启用' : '禁用'}`);
    }
    
    // 设置DEX大小限制
    function setDexSizeLimit(min, max) {
        if (typeof min === 'number' && min > 0) {
            config.minDexSize = min;
        }
        
        if (typeof max === 'number' && max > config.minDexSize) {
            config.maxDexSize = max;
        }
        
        logger.debug(tag, `DEX大小限制: ${config.minDexSize} - ${config.maxDexSize} 字节`);
    }
    
    // 添加特定加固保护支持
    function addProtectionSupport(protectionName) {
        if (protectionName && !config.supportedProtections.includes(protectionName)) {
            config.supportedProtections.push(protectionName);
            logger.debug(tag, `添加加固保护支持: ${protectionName}`);
        }
    }
    
    // 初始化模块
    initialize();
    
    // 导出公共接口
    return {
        setOutputDirectory,
        setFilterSystemClasses,
        setDexSizeLimit,
        addProtectionSupport,
        showStats,
        // 新增API
        scanNow: function() {
            logger.info(tag, "手动触发内存扫描");
            scanMemoryForDex();
        },
        forceLoadClasses: function() {
            logger.info(tag, "手动触发类加载");
            forceLoadAllClasses();
        },
        enableProtection: function(protectionName, enabled) {
            if (typeof enabled !== 'boolean') enabled = true;
            
            if (enabled) {
                if (!config.supportedProtections.includes(protectionName)) {
                    config.supportedProtections.push(protectionName);
                    logger.info(tag, `启用 ${protectionName} 保护类型支持`);
                }
            } else {
                const index = config.supportedProtections.indexOf(protectionName);
                if (index !== -1) {
                    config.supportedProtections.splice(index, 1);
                    logger.info(tag, `禁用 ${protectionName} 保护类型支持`);
                }
            }
        },
        setScanInterval: function(intervalMs) {
            if (typeof intervalMs === 'number' && intervalMs > 1000) {
                config.memScanIntervalMs = intervalMs;
                logger.info(tag, `内存扫描间隔设置为 ${intervalMs} 毫秒`);
            }
        },
        getConfig: function() {
            return Object.assign({}, config);
        },
        resetStats: function() {
            stats.dexFiles = 0;
            stats.classFiles = 0;
            stats.totalBytes = 0;
            stats.startTime = new Date();
            stats.uniqueLoaders = new Set();
            extractedDexHashes.clear();
            logger.info(tag, "统计信息已重置");
        },
        getExtractedDexCount: function() {
            return stats.dexFiles;
        },
        isProtectionEnabled: function(protectionName) {
            return config.supportedProtections.includes(protectionName);
        }
    };
}; 