#include <dlfcn.h>
#include <fstream>
#include <cstdio>
#include <string>
#include <sstream>
#include <thread>
#include <map>
#include <fcntl.h>
#include <sys/mman.h>
#include "log.h"
#include "xdl.h"
#include "uprobe_trace_user.h"
#include "il2cpp_trace.h"

#define DO_API(r, n, p) r (*n) p

#include "il2cpp-api-functions.h"

#undef DO_API

char data_dir_path[PATH_MAX];
char module_path[PATH_MAX];
static uint64_t il2cpp_base = 0;
int hook_fun_num=0;
std::map<long,std::string> fun_name_dict;
unsigned long start_addrs[MAX_VMA_NUM];
unsigned long end_addrs[MAX_VMA_NUM];
unsigned long vma_base[MAX_VMA_NUM];
int vma_num=0;

void init_il2cpp_api(void *handle) {
#define DO_API(r, n, p) {                      \
    n = (r (*) p)xdl_sym(handle, #n, nullptr); \
    if(!n) {                                   \
        LOGW("api not found %s", #n);          \
    }                                          \
}

#include "il2cpp-api-functions.h"

#undef DO_API
}


int init_il2cpp_fun(){
    char* il2cpp_module_name = "libil2cpp.so";
    void *handle = xdl_open(il2cpp_module_name, 0);
    if (handle) {
        int flag = -1;
        init_il2cpp_api(handle);
        if(il2cpp_capture_memory_snapshot && il2cpp_start_gc_world && il2cpp_stop_gc_world && il2cpp_class_get_methods && il2cpp_method_get_name){
            flag = 0;
            Dl_info dlInfo;
            if (dladdr((void *) il2cpp_capture_memory_snapshot, &dlInfo)) {
                il2cpp_base = reinterpret_cast<uint64_t>(dlInfo.dli_fbase);
                strcpy(module_path,dlInfo.dli_fname);
                LOGD("il2cpp_base: 0x%llx", il2cpp_base);
                LOGD("module_path: %s", module_path);
            }
        }
        return flag;
    } else{
        LOGI("libil2cpp.so not found in thread %d", gettid());
    }
    return -1;
}

char* get_data_dir_path(){
    char data_dir_path[PATH_MAX];
    std::ifstream file("/proc/self/cmdline");
    if (!file.is_open()) {
        return "";
    }
    std::stringstream buffer;
    buffer << file.rdbuf(); // 读取文件内容到 stringstream
    snprintf(data_dir_path, PATH_MAX, "/data/data/%s",buffer.str().c_str());
    file.close();
    return data_dir_path;
}

char *get_trace_info(char *trace_file_path){
    FILE* file = fopen(trace_file_path, "r");
    if (!file) {
        LOGE("can not open:%s",trace_file_path);
        return NULL;
    }

    char buffer[1024];
    char last_line[1024];
    while (fgets(buffer, sizeof(buffer), file)){
        strcpy(last_line,buffer);
    }

    fclose(file);

    if (last_line == NULL || last_line[0] == '\0') {
        LOGE("can not get any trace item");
        return NULL;
    }

    return last_line;
}


void hook_all_fun(){
    for (auto it = fun_name_dict.begin(); it != fun_name_dict.end(); ++it) {
        unsigned long fun_offset = it->first;
        std::string fun_name = it->second;
        unsigned long fun_addr = il2cpp_base+fun_offset;
        unsigned long uprobe_offset;
        for (int i=0;i<vma_num;i++){
            if(fun_addr>start_addrs[i] && fun_addr<end_addrs[i]){
                uprobe_offset = fun_addr-start_addrs[i]+vma_base[i];
            }
        }

        uprobe_item_info *uprobe_item = (uprobe_item_info*)malloc(sizeof(uprobe_item_info));
        uprobe_item->uprobe_offset = uprobe_offset;
        uprobe_item->fun_offset = fun_offset;
        uprobe_item->fun_name = (char*)fun_name.c_str();
        int set_uprobe_ret = set_fun_info(uprobe_item);//发送hook请求

        if(set_uprobe_ret!=SET_TRACE_SUCCESS){
            LOGE("error set uprobe in fun_name:%s,fun_offset:0x%llx,uprobe_offset:%llx",fun_name.c_str(),fun_offset,uprobe_offset);
        }
    }
    LOGD("success hook fun num:%d",hook_fun_num);
}

void clear_all_hook(){
    int clear_ret = clear_all_uprobes();
    if(clear_ret!=SET_TRACE_SUCCESS){
        LOGE("clear all uprobes error");
    }
    LOGD("success clear all uprobes");
    hook_fun_num = 0;
    fun_name_dict.clear();
}


void check_all_methods(void *klass,char *clazzName) {
    void *iter = nullptr;
    long fun_offset;
    while (auto method = il2cpp_class_get_methods(klass, &iter)) {
        //TODO attribute
        if (method->methodPointer && hook_fun_num<MAX_HOOK_NUM) {
            fun_offset = (uint64_t)method->methodPointer - il2cpp_base;

            if(fun_name_dict.find(fun_offset) != fun_name_dict.end()){
                continue;
            }

            char full_name[MAX_FULL_NAME_LEN];
            auto method_name = il2cpp_method_get_name(method);
            snprintf(full_name,MAX_FULL_NAME_LEN,"%s::%s",clazzName,method_name);
            std::string mfull_name(full_name);
            fun_name_dict[fun_offset]=mfull_name;
            hook_fun_num++;
        }
    }
}

void trace_type_info(Il2CppMetadataType type_info,char *clazzName) {
    auto klass = reinterpret_cast<void *>(type_info.typeInfoAddress);
    check_all_methods(klass,clazzName);
}

bool init_vma(){
    FILE *f;
    char buf[256];
    f = fopen("/proc/self/maps","r");
    if(!f){
        return false;
    }
    while (fgets(buf,256,f)!=NULL){
        unsigned long tstart,tend,tbase;
        char permissions[5];
        int major,minor;
        unsigned long inode;
        char path[256];

        int fields = sscanf(buf,"%lx-%lx %4s %lx %x:%x %lu %s",&tstart,&tend,permissions,&tbase,&major,&minor,&inode,path);
        if(fields==8){
            if(strcmp(path,module_path)==0){
//                LOGD("start:%lx,end:%lx,permissions:%s,tbase:%lx\n",tstart,tend,permissions,tbase);
                start_addrs[vma_num] = tstart;
                end_addrs[vma_num] = tend;
                vma_base[vma_num] = tbase;
                vma_num++;
            }
        }

    }
    fclose(f);
    if(vma_num==0){
        return false;
    }
    return true;
}

void dump_so(){
    LOGD("start dump libil2cpp.so,base:%llx,end:%llx",il2cpp_base,end_addrs[vma_num-1]);
    char il2cpp_dump_path[PATH_MAX];
    sprintf(il2cpp_dump_path,"%s/files/libil2cpp_%llx_dump.so",data_dir_path,il2cpp_base);
    LOGD("il2cpp_dump_path:%s",il2cpp_dump_path);

    // 打开文件（创建并截断）
    int fd = open(il2cpp_dump_path, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR);
    if (fd == -1) {
        LOGE("Failed to open il2cpp_dump_path:%s",il2cpp_dump_path);
        return;
    }

    size_t total_written = 0;
    size_t remaining = end_addrs[vma_num-1] - il2cpp_base;
    char* current_ptr = (char*)il2cpp_base;
    char fill_buf[CHUNK_SIZE];
    memset(fill_buf,0,CHUNK_SIZE);

    // 分块写入，避免大内存一次性写入
    while (remaining > 0) {
        size_t chunk_size = (remaining > CHUNK_SIZE) ? CHUNK_SIZE : remaining;
        ssize_t written = write(fd, current_ptr, chunk_size);

        if (written <= 0) {
            LOGE("Write error at offset %zu", total_written);
            written = write(fd,fill_buf,chunk_size);
        }

        total_written += written;
        remaining -= written;
        current_ptr += written;
    }

    // 确保数据写入磁盘
    fsync(fd);
    close(fd);

    LOGD("success dump:%s",module_path);
}


void start_trace(char* data_dir_path){
    char trace_file_path[PATH_MAX];

    int init_ret = init_il2cpp_fun();
    if(init_ret == -1){
        LOGE("can not get some fun addr");
        return;
    }
    LOGD("success get il2cpp api fun");
    bool parse_ret = init_vma();
    if(!parse_ret){
        LOGE("can not get vma info");
        return;
    }

    if(access(Fix_Module_Path, F_OK) != 0){
        LOGE("Fix_Module_Path:%s not exit",Fix_Module_Path);
        dump_so();
        return;
    }

    trace_init_info *base_info = (trace_init_info*)malloc(sizeof(trace_init_info));
    base_info->module_base = il2cpp_base;
    base_info->uid = getuid();

    base_info->tfile_name = (char *)malloc(strlen(module_path) + 1);
    strcpy(base_info->tfile_name,module_path);

    base_info->fix_file_name = (char *)malloc(strlen(Fix_Module_Path) + 1);
    strcpy(base_info->fix_file_name,Fix_Module_Path);

    int sret = trace_init(base_info);

    if (sret!=SET_TRACE_SUCCESS){
        LOGE("init uprobe hook error");
        return;
    }
    LOGD("init uprobe hook success");


    strcpy(trace_file_path,data_dir_path);
    strcat(trace_file_path,"/files/test_trace.txt");
    LOGD("get trace_file_path:%s",trace_file_path);



    if (il2cpp_base!=0) {
        auto memorySnapshot = il2cpp_capture_memory_snapshot();
        auto all_type_infos_count = memorySnapshot->metadata.typeCount;
        auto all_type_infos = memorySnapshot->metadata.types;
        LOGD("all_typeCount:%d",all_type_infos_count);
        char tmp_info[240]="test";
        while (true){
            char test_info[240];
            strcpy(test_info,get_trace_info(trace_file_path));
            test_info[strlen(test_info)-1] = '\0';
            if(strcmp(tmp_info,test_info)==0){
                sleep(2);
                continue;
            } else{
                strcpy(tmp_info,test_info);
                //清除之前的hook
                il2cpp_stop_gc_world();
                clear_all_hook();
                il2cpp_start_gc_world();
            }


            if(strstr(tmp_info,".dll")){
                LOGD("hook all methods of %s",tmp_info);
                for (int i = 0; i < all_type_infos_count; ++i) {
                    if(strstr(tmp_info,all_type_infos[i].assemblyName)){
                        if(hook_fun_num==MAX_HOOK_NUM){
                            LOGE("reach MAX_HOOK_NUM:%ld",MAX_HOOK_NUM);
                            break;
                        }
                        trace_type_info(all_type_infos[i],all_type_infos[i].name);
                    }
                }
            } else{
                for (int i = 0; i < all_type_infos_count; ++i) {
                    if(strcmp(all_type_infos[i].name,tmp_info)==0){
                        if(hook_fun_num==MAX_HOOK_NUM){
                            break;
                        }
                        LOGD("trace %s",all_type_infos[i].name);
                        trace_type_info(all_type_infos[i],all_type_infos[i].name);
                        break;
                    }
                }
            }


//            check_fun_instruction();
            il2cpp_stop_gc_world();
            hook_all_fun();
            il2cpp_start_gc_world();
        }
//        il2cpp_free_captured_memory_snapshot(memorySnapshot);
    } else {
        LOGE("unknow error");
    }


}



void trace_entry(){
    strcpy(data_dir_path,get_data_dir_path());
    if (data_dir_path == NULL || data_dir_path[0] == '\0') {
        LOGE("Failed to open cmdline");
        return;
    }

    LOGI("game dir:%s", data_dir_path);
    std::thread il2cpp_trace_thread(start_trace, data_dir_path);
    il2cpp_trace_thread.detach();

}
__attribute__((section(".init_array"))) void (*start_fun)() = trace_entry;