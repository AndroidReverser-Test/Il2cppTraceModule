# Il2cpp-Trace-Module
一个用于对unity il2cpp框架开发的安卓端手游进行trace的so模块


# 如何使用？
在要进行trace的手游的私有目录(即/data/data/包名/files/)下创建test_trace.txt文件，并向其中输入要trace的类名即可，类名的获取以PtraceIl2cppDumper这个项目dump下来的为准，输入样例如：echo "test_clazz_name" >> test_trace.txt, 推荐使用echo向文件输入要trace的类，程序是默认定时获取test_trace.txt文件的最后一行的内容来作为类名进行trace。然后再通过任意ptrace注入器将本项目编译生成的so注入至游戏进程后可在logcat中使用Test-Log进行过滤查看结果。

# 如何构建
克隆本项目后，使用androidStudio打开，然后等待项目配置自动完成，之后在本项目目录下使用gradlew :app:externalNativeBuildRelease命令进行编译，编译完成后会在<项目目录>\app\build\intermediates\cmake\release\obj\arm64-v8a下生成相应so文件。

# 已知的问题
部分游戏可能会在trace时崩溃，这与hook框架有关


# 感谢
[Zygisk-Il2CppDumper](https://github.com/Perfare/Zygisk-Il2CppDumper)
[Dobby](https://github.com/jmpews/Dobby)
[Android_InlineHook](https://github.com/zhuotong/Android_InlineHook)