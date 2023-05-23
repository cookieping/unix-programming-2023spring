#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <cstring>
#include <unistd.h>
#include <sys/stat.h>
#include <filesystem>
#include <fstream>
using namespace std;
using recursive_directory_iterator = std::filesystem::recursive_directory_iterator;
using directory_iterator = std::filesystem::directory_iterator;

string findAnswer(string pathToDir, string magic) {
    struct stat s;
    if( stat(pathToDir.c_str(), &s) == 0 ) {
        if( s.st_mode & S_IFDIR ) {  // directory
            for (const auto& dirEntry : directory_iterator(pathToDir)) {
                if(is_symlink(dirEntry.path())) continue;  // skip the symbolic link

                string ans = findAnswer(dirEntry.path(), magic);
                if(ans == "") continue;
                return ans;
            }

        } else if( s.st_mode & S_IFREG ) {  // file
            string path = pathToDir, currNum;
            ifstream file;
            file.open(path);

            getline(file, currNum);
            if(magic == currNum) return path;
            return "";
        }
    } else {
        perror("stat");
    }
    return "";
}

int main(int argc, char *argv[]) {
    string pathToRoot = argv[1];
    string magic = argv[2];

    cerr << "path to root: " << pathToRoot << endl;
    cerr << "magic number: " << magic << endl;

    cout << findAnswer(pathToRoot, magic);
    cerr << "end!\n";
    
    return 0;
}