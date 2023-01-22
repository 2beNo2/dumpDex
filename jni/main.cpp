
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string>
#include <sys/uio.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <android/log.h>

#define TAG "DUMP_DEX"
#define INJECT_DEBUG 1
#ifdef INJECT_DEBUG
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  TAG, __VA_ARGS__)
#else
#define LOGD(...)
#define LOGI(...)
#define LOGE(...)
#define LOGW(...)
#endif // INJECT_DEBUG


typedef uint8_t   u1;
typedef uint16_t  u2;
typedef uint32_t  u4;
typedef uint64_t  u8;

#define MAX_LENGTH 260
#define DEX_MAGIC  "dex\n035\0"
#define ODEX_MAGIC  "dex\n037\0"
#define kSHA1DigestLen  20

struct DexHeader {
    u1  magic[8];           /* includes version number */
    u4  checksum;           /* adler32 checksum */
    u1  signature[kSHA1DigestLen]; /* SHA-1 hash */
    u4  fileSize;           /* length of entire file */
    u4  headerSize;         /* offset to start of next section */
    u4  endianTag;
    u4  linkSize;
    u4  linkOff;
    u4  mapOff;
    u4  stringIdsSize;
    u4  stringIdsOff;
    u4  typeIdsSize;
    u4  typeIdsOff;
    u4  protoIdsSize;
    u4  protoIdsOff;
    u4  fieldIdsSize;
    u4  fieldIdsOff;
    u4  methodIdsSize;
    u4  methodIdsOff;
    u4  classDefsSize;
    u4  classDefsOff;
    u4  dataSize;
    u4  dataOff;
};


static int SDK_INT = -1;

static int get_sdk_level()
{
    char sdk[MAX_LENGTH] = {0};
    if (SDK_INT > 0) {
        return SDK_INT;
    }
    __system_property_get("ro.build.version.sdk", sdk);
    SDK_INT = atoi(sdk);
    return SDK_INT;
}


void show_help()
{
    puts("usage: dumpDex -d pid");
    fflush(stdout);
}


int check_is_dex(pid_t pid, size_t offset, const char* buf)
{
    int fd = -1;
    int ret = -1;
    int dex_size = 0;
    char path[MAX_LENGTH] = {0};
    struct DexHeader header = {0};
    struct iovec remote[1];
    struct iovec local[1];
    char* dex_mem = nullptr;

    snprintf(path, sizeof(path), "/proc/%d/mem", pid);
    get_sdk_level();
    if(SDK_INT >= 23){
        local[0].iov_base = &header;
        local[0].iov_len = sizeof(DexHeader);
        remote[0].iov_base = (void *)offset;
        remote[0].iov_len = sizeof(DexHeader);
        ret = process_vm_readv(pid, local, 1, remote, 1, 0);
        if(ret < 0) {
            //printf("[-] process_vm_readv errno:[%s], offset:[%p]\n", strerror(errno), (void*)offset);
            return -1;
        }
    }else{
        printf("sdk < 23 \n");
        return -1;
    }

    if(header.headerSize == 0x70 && header.endianTag == 0x12345678){
        if(strcmp((char*)header.magic, ODEX_MAGIC) == 0){
            return -1;
        }
        //puts(buf);
        //start dump
        dex_size = header.fileSize;
        dex_mem = (char*)malloc(dex_size);
        if(dex_mem == nullptr){
            return -1;
        }
        local[0].iov_base = dex_mem;
        local[0].iov_len = dex_size;
        remote[0].iov_base = (void *)offset;
        remote[0].iov_len = dex_size;
        ret = process_vm_readv(pid, local, 1, remote, 1, 0);
        if(ret < 0) {
            printf("[-] dump_dex->process_vm_readv errno:[%s], offset:[%p]\n", strerror(errno), (void*)offset);
            if(dex_mem != nullptr){
                free(dex_mem);
            }
            return -1;
        }

        //mkdir
        memset(path, 0 , sizeof(path));
        snprintf(path, sizeof(path), "/data/local/tmp/%d", pid);
        if (mkdir(path, 0777) < 0 && errno != EEXIST) {
            printf("[-] mkdir errno:[%s]\n", strerror(errno));
            if(dex_mem != nullptr){
                free(dex_mem);
            }
            return -1;
        }

        //write
        memset(path, 0 , sizeof(path));
        snprintf(path, sizeof(path), "/data/local/tmp/%d/%d_%d.dex", pid, pid, dex_size);
        fd = open(path, O_WRONLY | O_CREAT, 0777);
        if(fd < 0){
            printf("[-] open errno:[%s]\n", strerror(errno));
            if(dex_mem != nullptr){
                free(dex_mem);
            }
            return -1;   
        }
        write(fd, dex_mem, dex_size);
        close(fd);
        free(dex_mem);

        printf("[+] write %s ok\n", path);
    }
    
    return 0;
}


int dump_dex(pid_t pid)
{
    FILE* fp = NULL;
    char path[MAX_LENGTH] = {0};
    char buff[MAX_LENGTH] = {0};
    char perm[5];
    void* base_addr = NULL;

    snprintf(path, sizeof(path), "/proc/%d/maps", pid);

    fp = fopen(path, "r");
    if(fp == NULL){
        printf("[-] fopen:[%s], errno:[%s]\n", path, strerror(errno));
        return -1;
    }

    while(fgets(buff, sizeof(buff), fp)){
        if(sscanf(buff, "%p-%*p %4s", &base_addr, perm) != 2) 
            continue;
        check_is_dex(pid, (size_t)base_addr, buff);
    }

    if(fp != NULL) 
        fclose(fp);
    return 0;
}


int main(int argc, char* argv[])
{
    int c = 0;
    int ret = -1;

    if(argc < 2){
        show_help();
        return 0;
    }

    while((c = getopt(argc, argv, "d:")) != -1) 
    {
      switch(c) {
        case 'd': {
            printf("[+] start dumpDex pid:[%s]\n", optarg);
            ret = dump_dex(atoi(optarg));
            if(ret < 0){
                printf("[-] dumpDex pid:[%s] failed!\n", optarg);
                return 0;
            }
            printf("[+] dumpDex pid:[%s] complete!\n", optarg);
            break;
        }
        case '?': {
            show_help();
            return 0;
        }
      }
    }

    return 0;
}
