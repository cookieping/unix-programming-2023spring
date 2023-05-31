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
#include <linux/elf.h>
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

/* store the elf info to the file elfResult.txt */
void storeELFInfo(string cmdPath) {
    string readELFCmd = "readelf -r " + cmdPath + " > elfResult.txt";
    if(system(readELFCmd.c_str()) == -1) exit(EXIT_FAILURE);
}

/* parse the ELF info (offset & API name) of the specific line from ELF file */
pair<string, string> getELFInfo(string lineStr) {
    stringstream ss(lineStr);
    string tmp;
    vector<string> splitStr;
    while(getline(ss, tmp, ' ')) {
        if(tmp.length() == 0 || tmp == " ") continue;
        splitStr.push_back(tmp);
    }
    string offset = splitStr[0];
    string API = splitStr[4];
    string delimeter = "@";
    API = API.substr(0, API.find(delimeter));
    return pair<string, string>(offset, API);
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
    // return write(fd, buf, count);
    // printf("** in fake write\n");
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
    // printf("** in fake connect\n");
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
    if(readFilter.count(fileNameStr) != 0) readFilter[fileNameStr] = "";

    return close(fd);
}


int __libc_start_main(int *(main) (int, char **, char **), int argc, char ** ubp_av, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void (* stack_end)) {
    // printf("** Hello, World!\n********************\n");
    string configPath = getenv("SANDBOX_CONFIG");
    loggerFd = atoi(getenv("LOGGER_FD"));
    unsetenv("LD_PRELOAD");   // to avoid recursion when calling system(readelf -r "usr/bin/cat")  // ****

    // 1. handle blacklist
    handleBlacklist(configPath);

    // 2. get the command name and the base address of the command
    pair<string, string> cmdInfo = getCommandInfo();  // (baseAddr, cmd)

    // // 3. use readelf to get the rela.plt table, parse it to see which API is used, and get its offset
    storeELFInfo(cmdInfo.second);
    setenv("LD_PRELOAD", "./sandbox.so", 1);

    FILE* fpELF;
    char* line = NULL;
    size_t len = 0;
    ssize_t readBuf;
    if((fpELF = fopen("elfResult.txt", "r")) == NULL) exit(EXIT_FAILURE);

    bool startPLTSection = false;
    int pagesize = getpagesize();
    while(readBuf = getline(&line, &len, fpELF) != -1) {
        string lineStr = line;
        if(lineStr.find(".rela.plt") != string::npos) {
            startPLTSection = true;
            getline(&line, &len, fpELF);
            continue;
        }
        if(!startPLTSection) continue;

        // 4. start parsing the plt part of ELF file
        string GOTOffset, API;
        tie(GOTOffset, API) = getELFInfo(lineStr);
        
        // 5. get the address of fake functions
        void (*fakeAddr)();
        if(API == "open") fakeAddr = reinterpret_cast<void(*)()>(fakeOpen);
        else if(API == "read") fakeAddr = reinterpret_cast<void(*)()>(fakeRead);
        else if(API == "write") fakeAddr = reinterpret_cast<void(*)()>(fakeWrite);
        else if(API == "connect") fakeAddr = reinterpret_cast<void(*)()>(fakeConnect);
        else if(API == "getaddrinfo") fakeAddr = reinterpret_cast<void(*)()>(fakeGetAddrInfo);
        else if(API == "system") fakeAddr = reinterpret_cast<void(*)()>(fakeSystem);
        else if(API == "close") fakeAddr = reinterpret_cast<void(*)()>(fakeClose);
        else continue;

        // 6. calculate the GOT address which will be modified
        uintptr_t baseAddrNew = (uintptr_t)strtol(cmdInfo.first.c_str(), NULL, 16);
        uintptr_t GOTOffsetNew = (uintptr_t)strtol(GOTOffset.c_str(), NULL, 16);
        void** GOTEntry = (void **)(baseAddrNew + GOTOffsetNew);

        // 7. modify GOT table with the address of fake open
        uintptr_t GOTStartAddr = baseAddrNew + GOTOffsetNew;
        uintptr_t alignAddr = GOTStartAddr & ~(0xFFF);
        if(mprotect((void **)alignAddr, pagesize * 1, (PROT_READ | PROT_WRITE | PROT_EXEC)) == -1) {
            perror("mprotect");
        }
        memcpy(GOTEntry, &fakeAddr, sizeof(&fakeAddr));
    }
    fclose(fpELF);

    // 8. call real __libc_start_main by dlsym
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