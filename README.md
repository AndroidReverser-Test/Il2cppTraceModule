# Il2cpp-Trace-Module
一个用于对unity il2cpp框架开发的安卓端手游进行trace的so模块


# 如何使用？
首先要成功加载[Kernel-Trace](https://github.com/AndroidReverser-Test/Kernel-Trace)项目提供的kpm模块。
再将目标游戏的libil2cpp.so完整从内存中dump下并放到默认的/data/local/tmp/libil2cpp_fixed.so路径下(如果没有这样做将会触发从内存中dump libil2cpp.so到/data/data/包名/files/下)。
然后在要进行trace的手游的私有目录(即/data/data/包名/files/)下创建test_trace.txt文件，并向其中输入要trace的类名即可，类名的获取以[PtraceIl2cppDumper](https://github.com/AndroidReverser-Test/PtraceIl2cppDumper)这个项目dump下来的为准，输入样例如：echo "test_clazz_name" >> test_trace.txt, 推荐使用echo向文件输入要trace的类，程序是默认定时获取test_trace.txt文件的最后一行的内容来作为类名进行trace。然后再通过任意ptrace注入器将本项目编译生成的so注入至游戏进程后，查看[Kernel-Trace](https://github.com/AndroidReverser-Test/Kernel-Trace)的输出即可获取trace结果。

# 如何构建
克隆本项目后，使用androidStudio打开，然后等待项目配置自动完成，之后在本项目目录下使用gradlew :app:externalNativeBuildRelease命令进行编译，编译完成后会在<项目目录>\app\build\intermediates\cmake\release\obj\arm64-v8a下生成相应so文件。


# 感谢
[Zygisk-Il2CppDumper](https://github.com/Perfare/Zygisk-Il2CppDumper)