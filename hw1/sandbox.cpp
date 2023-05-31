#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <iostream>
#include <string>
#include <map>
#include <vector>
#include <sstream>
#include <errno.h>
#include <filesystem>
#include <elf.h>
using namespace std;
using libc_start_main_type = int (*)(int *(*)(int, char **, char **), int, char**, void (*)(), void (*)(), void (*)(), void*);

#ifdef __cplusplus
extern "C" {
    int __libc_start_main(  int *(main) (int, char **, char **),
                            int argc, 
                            char ** ubp_av, 
                            void (*init) (void), 
                            void (*fini) (void),
                            void (*rtld_fini) (void), 
                            void (* stack_end));
}
#endif

/* global variables */
int loggerFd;
map<string, vector<string> > blacklist;
map<string, string> readFilter;  // {log-file name, current filter string}

/* parse the blacklist, and store it in a map */
void handleBlacklist(string configPath) {
    FILE *fp;
    char * line = NULL;
    size_t len = 0;
    ssize_t readBuf;
    fp = fopen(configPath.c_str(), "r");
    if (fp == NULL) exit(EXIT_FAILURE);

    string currCmd;
    vector<string> tmp;  // empty vector
    while(readBuf = getline(&line, &len, fp) != -1) {
        string lineStr = line;
        if(lineStr.length() == 1 && lineStr[0] == '\n') continue;
        char* parseStr = strtok(line, " ");
        if((string)parseStr == "BEGIN") {  // get the name of the command -> ex. open-blacklist
            currCmd = strtok(NULL, " ");
            currCmd.pop_back();
            blacklist.insert(pair<string, vector<string> >(currCmd, tmp));
        } else if((string)parseStr == "END") {
            continue;
        } else if(parseStr != NULL) {  // blacklist info
            lineStr.pop_back();
            if(currCmd == "open-blacklist") {  // handle symbolic link in blacklist
                struct stat buf;
                const char* originalPath = lineStr.c_str();
                lstat(originalPath, &buf);
                // if(lstat(originalPath, &buf) == -1) perror("lstat");
                if (S_ISLNK(buf.st_mode)) {  // is symbolic link
                    char targetPath[1024];
                    ssize_t len = readlink(originalPath, targetPath, sizeof(targetPath));
                    if(len == -1) perror("readlink in blacklist");
                    targetPath[len] = '\0';
                    lineStr = (string)targetPath;   
                }
            }
            blacklist[currCmd].push_back(lineStr);
        }
    }
}

/* open /proc/self/maps, return pair(base address, current command) */
pair<string, string> getCommandInfo() {
    FILE *fp;
    char * line = NULL;
    size_t len = 0;
    ssize_t readBuf;
    fp = fopen("/proc/self/maps", "r");
    if (fp == NULL) exit(EXIT_FAILURE);
    string baseAddr, cmd;

    if(readBuf = getline(&line, &len, fp) != -1) {  // read the first line
        char* parseStr = strtok(line, " ");
        char* baseAddrTmp = parseStr;
        while(parseStr != NULL) {
            parseStr = strtok(NULL, " ");
            if(parseStr != NULL) cmd = parseStr;
        }
        baseAddr = strtok(baseAddrTmp, "-");
        cmd.pop_back();
        // printf("** base address: %s, command: %s\n", baseAddr.c_str(), cmd.c_str());
    }
    fclose(fp);
    return pair<string, string>(baseAddr, cmd);
}

bool inBlackList(string APIName, string target) {
    if(APIName == "read-blacklist") {  // read: check the filter content
        for(int i = 0; i < blacklist[APIName].size(); i++) {
            if(target.find(blacklist[APIName][i]) != string::npos) return true;
        }
        return false;
    }

    if(APIName == "connect-blacklist") {  // connect: host->IP, then check the IP address
        for(int i = 0; i < blacklist[APIName].size(); i++) {
            // printf("**** current keyword: %s\n", blacklist[APIName][i].c_str());
            // first, get the ip address of the blacklist address keywords
            string hostName = blacklist[APIName][i].substr(0, blacklist[APIName][i].find(":"));
            string port = blacklist[APIName][i].substr(blacklist[APIName][i].find(":"));

            struct addrinfo hints, *res, *p;
            char ipAddress[INET_ADDRSTRLEN];
            memset(&hints, 0, sizeof(hints));
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = 0;  // socket addresses of any type can be returned

            int status = getaddrinfo(hostName.c_str(), NULL, &hints, &res);
            if (status != 0) perror("getaddrinfo in blacklist");

            for (p = res; p != NULL; p = p->ai_next) {
                void *addr;
                struct sockaddr_in *ipv4 = (struct sockaddr_in*) p->ai_addr;
                addr = &(ipv4->sin_addr);
                inet_ntop(p->ai_family, addr, ipAddress, sizeof(ipAddress));

                // check whether the target is in the list
                string currKeyword = (string)ipAddress + port;
                // printf("**** target: %s, keyword: %s\n", target.c_str(), currKeyword.c_str());
                if(target == currKeyword) return true;
            }
            freeaddrinfo(res);
        }
        return false;
    }

    for(int i = 0; i < blacklist[APIName].size(); i++) {  // open & getaddrinfo
        if(target == blacklist[APIName][i]) return true;
    }
    return false;
}

/* fake functions */
int fakeOpen(const char *pathname, int flags, mode_t mode = 0) {
    string pathnameStr = pathname;
    bool inList;

    // handle pathname symbolic link & handle blacklist
    struct stat buf;
    lstat(pathname, &buf);
    // if (lstat(pathname, &buf) == -1) perror("lstat");
    if (S_ISLNK(buf.st_mode)) {
        char targetPathName[1024];
        ssize_t len = readlink(pathname, targetPathName, sizeof(targetPathName));
        if(len == -1) perror("readlink");
        targetPathName[len] = '\0';
        pathnameStr = (string)targetPathName;
        inList = inBlackList("open-blacklist", pathnameStr);
    } else {
        inList = inBlackList("open-blacklist", (string)pathname);
    }

    // handle mode: if neither O_CREAT nor O_TMPFILE is specified in flags, then mode is ignored
    bool needMode = (flags & O_CREAT) | (flags & O_TMPFILE);  // error here, but it can be compiled in x86
    if(needMode == false) mode = 0;
   
   // call real open
    int returnVal = -1;
    if(!inList) {  // not in blacklist -> call real open
        // returnVal = open(pathnameStr.c_str(), flags, mode);
        returnVal = open(pathname, flags, mode);
    } else {  // in the black list -> return -1 and set errno to EACCES
        errno =  EACCES;
    }
    
    // logger
    const char* format = "[logger] open(\"%s\", %d, %d) = %d\n";
    char logInfo[256];
    int logInfoLen = sprintf(logInfo, format, pathnameStr.c_str(), flags, mode, returnVal);
    write(loggerFd, logInfo, logInfoLen);
    return returnVal;
}

ssize_t fakeRead(int fd, void *buf, size_t count) {
    // create read-log file
    int readLogFd;
    pid_t pid = getpid();
    const char* fileNameFormat = "logFiles/%d-%d-read.log";  // {pid}-{fd}-read.log
    char fileName[256];
    int fileNameLen = sprintf(fileName, fileNameFormat, pid, fd);
    string fileNameStr = fileName;
    if((readLogFd = open(fileName, O_CREAT | O_WRONLY | O_APPEND, S_IRUSR | S_IWUSR)) == -1) perror("open in fakeRead");

    // call real read to read the file
    int returnVal = read(fd, buf, count);
    // printf("\n%s\n\n", (char*)buf);
    char* bufRead = static_cast<char*>(buf);
    string bufReadStr(bufRead);

    // handle blacklist, but first need to check whether this log file is in the map
    if(readFilter.count(fileNameStr) == 0) readFilter.insert(pair<string, string>(fileNameStr, ""));
    readFilter[fileNameStr] = readFilter[fileNameStr] + bufReadStr;
    bool inList = inBlackList("read-blacklist", readFilter[fileNameStr]);

    // log the content into the file
    if(inList) {  // don't write into read-log file, clear the filter
        // readFilter[fileNameStr] = "";
        readFilter.erase(fileNameStr);
        returnVal = -1;
        errno = EIO;
        close(fd);
    } else {
        if(write(readLogFd, buf, count) == -1) perror("write in fakeRead");
        // fprintf(fptr, "%s", bufRead);
    }
    close(readLogFd);
    // fclose(fptr);

    // logger
    const char* format = "[logger] read(%d, %p, %d) = %d\n";
    char logInfo[256];
    int logInfoLen = sprintf(logInfo, format, fd, buf, count, returnVal);
    write(loggerFd, logInfo, logInfoLen);
    return returnVal;
}

ssize_t fakeWrite(int fd, const void *buf, size_t count) {
    // call real write to write the file
    // int writeLogFd;
    ssize_t returnVal = write(fd, buf, count);
    char* bufWrite = (char*)buf;

    // create write-log file
    pid_t pid = getpid();
    const char* fileNameFormat = "logFiles/%d-%d-write.log";  // {pid}-{fd}-write.log
    char fileName[256];
    int fileNameLen = sprintf(fileName, fileNameFormat, pid, fd);
    // if(writeLogFd = open(fileName, O_CREAT | O_RDWR | O_APPEND, S_IRUSR | S_IWUSR) == -1) perror("open in fakeWrite");
    // printf("** write fd=%d\n", writeLogFd);
    FILE* fptr = fopen(fileName, "a");
    if(fptr == NULL) perror("fopen in fakeWrite");
    fprintf(fptr, "%s", bufWrite);
    // if(write(writeLogFd, bufWrite, count) == -1) perror("write in fakeRead");
    fclose(fptr);
    // close(writeLogFd);

    // logger
    const char* format = "[logger] write(%d, %p, %d) = %d\n";
    char logInfo[256];
    int logInfoLen = sprintf(logInfo, format, fd, buf, count, returnVal);
    write(loggerFd, logInfo, logInfoLen);
    return returnVal;
}

int fakeConnect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    int returnVal = -1;

    // get the IP address and the port
    char ipAddress[INET_ADDRSTRLEN];
    uint16_t port;
    struct sockaddr_in *ipv4 = (struct sockaddr_in*) addr;
    inet_ntop(AF_INET, &(ipv4->sin_addr), ipAddress, INET_ADDRSTRLEN);
    port = htons(ipv4->sin_port);
    // printf("** IP address: %s, port: %d\n", ipAddress, port);

    // handle blacklist
    string target = (string)ipAddress + ":" + to_string(port);
    bool inList = inBlackList("connect-blacklist", target);

    // call real connect
    if(inList) errno = ECONNREFUSED;
    else returnVal = connect(sockfd, addr, addrlen);

    // logger
    const char* format = "[logger] connect(%d, \"%s\", %d) = %d\n";
    char logInfo[256];
    int logInfoLen = sprintf(logInfo, format, sockfd, ipAddress, addrlen, returnVal);
    write(loggerFd, logInfo, logInfoLen);

    return returnVal;
}

int fakeGetAddrInfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res) {
    // handle blacklist
    bool inList = inBlackList("getaddrinfo-blacklist", (string)node);
    
    // call real getaddrinfo
    int returnVal;
    if(inList) {
        errno = EAI_NONAME;
        returnVal = EAI_NONAME;
    } else {
        returnVal = getaddrinfo(node, service, hints, res);
    }

    // logger
    const char* format = "[logger] getaddrinfo(\"%s\",\"%s\",%p,%p) = %d\n";
    char logInfo[256];
    int logInfoLen = sprintf(logInfo, format, node, service, hints, res, returnVal);
    write(loggerFd, logInfo, logInfoLen);
    return returnVal;
}

int fakeSystem(const char *command) {
    // logger
    const char* format = "[logger] system(\"%s\")\n";
    char logInfo[256];
    int logInfoLen = sprintf(logInfo, format, command);
    write(loggerFd, logInfo, logInfoLen);

    // call real system
    int returnVal = system(command);
    return returnVal;
}

int fakeClose(int fd) {
    // if the fd is read, the filter should be close
    pid_t pid = getpid();
    const char* fileNameFormat = "logFiles/%d-%d-read.log";  // {pid}-{fd}-read.log
    char fileName[256];
    int fileNameLen = sprintf(fileName, fileNameFormat, pid, fd);
    string fileNameStr = fileName;
    if(readFilter.count(fileNameStr) != 0) readFilter.erase(fileNameStr);

    return close(fd);
}

/* without external program, perform GOT hacking */
void parseELFInfo(string baseAddress, string elfFile) {
    // printf("* baseAddress: %p\n", baseAddress.c_str());

    /* 1. get the ELF header of the ELF file */
    int fd = open(elfFile.c_str(), O_RDONLY);
    if (fd < 0) perror("Failed to open file");
    off_t size = lseek(fd, 0, SEEK_END);
    if (size < 0) perror("Failed to get file size");
    void *map_start = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map_start == MAP_FAILED) perror("Failed to mmap file");

    lseek(fd, 0, SEEK_SET);
    Elf64_Ehdr elfHeader;
    read(fd, &elfHeader, sizeof(elfHeader));    

    /* 2. find the position of section header table, and read the section headers */
    int sectionNum = elfHeader.e_shnum;  // e_shnum: the number of entries in the section header table
    Elf64_Shdr sectionHeaders[sectionNum];
    lseek(fd, elfHeader.e_shoff, SEEK_SET);  // e_shoff: byte offset from the beginning of the file to the section header table
    read(fd, sectionHeaders, sizeof(Elf64_Shdr) * sectionNum);

    /* 3. iterate section header table, and find the position of .got & .rela.plt & .dynsym & .dynstr */
    // get the string table header
    uint16_t stringTableIndex = elfHeader.e_shstrndx;  // e_shstrndx: section header table index of the entry associated with the section name string table
    if(stringTableIndex == SHN_XINDEX) stringTableIndex = sectionHeaders[0].sh_link;
    Elf64_Shdr stringTableHeader = sectionHeaders[stringTableIndex];
    char *strtab = (char *)malloc(stringTableHeader.sh_size);
    lseek(fd, stringTableHeader.sh_offset, SEEK_SET);
    read(fd, strtab, stringTableHeader.sh_size);  // locate at the start of the string table

    // iterate sectionHeaders
    Elf64_Addr gotAddr = 0, relaAddr = 0, dynsymAddr = 0, dynstrAddr = 0;
    uint64_t relaSize = 0, relaEntrySize = 0;
    for(int i = 0; i < sectionNum; i++) {
        char *sectionName = strtab + sectionHeaders[i].sh_name;
        if(sectionHeaders[i].sh_type == SHT_PROGBITS && strcmp(".got", sectionName) == 0) {
            gotAddr = sectionHeaders[i].sh_addr;
        }
        if(sectionHeaders[i].sh_type == SHT_RELA && strcmp(".rela.plt", sectionName) == 0) {
            relaAddr = sectionHeaders[i].sh_addr;
            relaSize = sectionHeaders[i].sh_size;
            relaEntrySize = sectionHeaders[i].sh_entsize;
        }
        if(sectionHeaders[i].sh_type == SHT_DYNSYM && strcmp(".dynsym", sectionName) == 0) {
            dynsymAddr = sectionHeaders[i].sh_addr;
        }
        if(sectionHeaders[i].sh_type == SHT_STRTAB && strcmp(".dynstr", sectionName) == 0) {
            dynstrAddr = sectionHeaders[i].sh_addr;
        }
    }
    // get the got table, relocation table, symbol table, dynstr table
    if(gotAddr == 0) perror("Fail to find GOT table address and size");
    char* gotTable = (char*)((uintptr_t)map_start + gotAddr);

    if(relaAddr == 0 || relaSize == 0) perror("Fail to find relocation table address and size");
    Elf64_Rela* relaTable = (Elf64_Rela *)((uintptr_t)map_start + relaAddr);

    if(dynsymAddr == 0) perror("Fail to find symbol table address and size");
    Elf64_Sym* symbolTable = (Elf64_Sym*)((uintptr_t)map_start + dynsymAddr);

    if(dynstrAddr == 0) perror("Fail to find dynamic string address and size");
    char* dynstrTable = (char*)((uintptr_t)map_start + dynstrAddr);

    /* 4. find the symbol which will be hijacked in the .rela.plt section, and get their position in the got table */
    Elf64_Addr offset = -1;
    for(int i = 0; i < relaSize / relaEntrySize; i++) {
        /* 5. get symbol index from rela table, and get the symbol from .dysym (symbol table) */
        int symbolIndex = ELF64_R_SYM(relaTable[i].r_info);
        Elf64_Sym* sym = &symbolTable[symbolIndex];

        /* 6. get the symbol name (st_name is the offset of the symbol in .dynstr) */
        char* symbolName = dynstrTable + sym->st_name;
        string symbolNameStr = symbolName;

        /* 7. get the address of fake functions, and also get the got offset */
        void (*fakeAddr)();
        if(symbolNameStr == "open") {
            fakeAddr = reinterpret_cast<void(*)()>(fakeOpen);
            offset = relaTable[i].r_offset;
        } else if(symbolNameStr == "read") {
            fakeAddr = reinterpret_cast<void(*)()>(fakeRead);
            offset = relaTable[i].r_offset;
        } else if(symbolNameStr == "write") {
            fakeAddr = reinterpret_cast<void(*)()>(fakeWrite);
            offset = relaTable[i].r_offset;
        } else if(symbolNameStr == "connect") {
            fakeAddr = reinterpret_cast<void(*)()>(fakeConnect);
            offset = relaTable[i].r_offset;
        } else if(symbolNameStr == "getaddrinfo") {
            fakeAddr = reinterpret_cast<void(*)()>(fakeGetAddrInfo);
            offset = relaTable[i].r_offset;
        } else if(symbolNameStr == "system") {
            fakeAddr = reinterpret_cast<void(*)()>(fakeSystem);
            offset = relaTable[i].r_offset;
        } else if(symbolNameStr == "close") {
            fakeAddr = reinterpret_cast<void(*)()>(fakeClose);
            offset = relaTable[i].r_offset;
        } else continue;
        
        /* 8. get the GOT entry */
        void **GOTEntry = (void **)((uintptr_t)((uintptr_t)strtol(baseAddress.c_str(), NULL, 16)) + (uintptr_t)offset);

        /* 9. modify GOT table with the address of the fake function */
        uintptr_t GOTStartAddr = reinterpret_cast<uintptr_t>(GOTEntry);
        uintptr_t alignAddr = GOTStartAddr & ~(0xFFF);
        if(mprotect((void **)alignAddr, getpagesize(), (PROT_READ | PROT_WRITE | PROT_EXEC)) == -1) {
            perror("mprotect");
        }
        memcpy(GOTEntry, &fakeAddr, sizeof(&fakeAddr));
    }
    close(fd);
}

int __libc_start_main(int *(main) (int, char **, char **), int argc, char ** ubp_av, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void (* stack_end)) {
    string configPath = getenv("SANDBOX_CONFIG");
    loggerFd = atoi(getenv("LOGGER_FD"));

    // 1. handle blacklist
    handleBlacklist(configPath);

    // 2. get the command name and the base address of the command
    pair<string, string> cmdInfo = getCommandInfo();  // (baseAddr, cmd)

    // 3. parse ELF info with elf.h
    parseELFInfo(cmdInfo.first, cmdInfo.second);

    // 4. call real __libc_start_main by dlsym
    void *libHandle;
    char *error;
    // libHandle = dlopen("/usr/lib64/libc-2.28.so", RTLD_LAZY);
    libHandle = dlopen("libc.so.6", RTLD_LAZY);
    if (!libHandle) {
        fprintf(stderr, "%s\n", dlerror());
    }
    auto libc_start_main_real = reinterpret_cast<libc_start_main_type>(dlsym(libHandle, "__libc_start_main"));
    if ((error = dlerror()) != NULL) {
        fprintf(stderr, "%s\n", error);
    }
    libc_start_main_real(main, argc, ubp_av, init, fini, rtld_fini, stack_end);
    dlclose(libHandle);

    return 0;
}