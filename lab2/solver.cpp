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

bool checkDirectoryOrFile(string path) {  // return true if it is a file
    struct stat s;
    if( stat(path.c_str(), &s) == 0 ) {
        if( s.st_mode & S_IFDIR ) return false;
        else if( s.st_mode & S_IFREG ) return true;
        else return false;
    } else {
        perror("stat");
    }
    return false;
}

bool checkMagicNum(string path, string magic) {
    ifstream file;
    file.open(path);

    string currNum;
    getline(file, currNum);

    cerr << "* curr num: " << currNum << endl;

    if(magic == currNum) return true;
    return false;
}

int main(int argc, char *argv[]) {
    string pathToDir = argv[1];
    string magic = argv[2];

    cerr << "path to directory: " << pathToDir << endl;
    cerr << "magic number: " << magic << endl;

    // cerr, print all directories and files
    for (const auto& dirEntry : recursive_directory_iterator(pathToDir)) {
        if(checkDirectoryOrFile(dirEntry.path())) {
            cerr << string(dirEntry.path()) << endl;
            if(checkMagicNum(dirEntry.path(), magic)) {
                // cerr << "**** find answer!! ****\n";
                cout << string(dirEntry.path());
                break;
            }
        } else {
            // cerr << "not a file!\n";
        }
        // cerr << relative(dirEntry.path(), pathToDir) << endl;
    }

    return 0;
}