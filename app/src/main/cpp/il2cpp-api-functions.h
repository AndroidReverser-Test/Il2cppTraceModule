#ifndef DO_API_NO_RETURN
#define DO_API_NO_RETURN(r, n, p) DO_API(r,n,p)
#endif

DO_API(const MethodInfo*, il2cpp_class_get_methods, (void * klass, void* *iter));
DO_API(Il2CppManagedMemorySnapshot*, il2cpp_capture_memory_snapshot, ());
DO_API(void, il2cpp_free_captured_memory_snapshot, (Il2CppManagedMemorySnapshot * snapshot));
DO_API(const char*, il2cpp_method_get_name, (const MethodInfo * method));
DO_API(void, il2cpp_stop_gc_world, ());
DO_API(void, il2cpp_start_gc_world, ());