#include <sys/stat.h>
#include <stdio.h>

int main() {
    char* folder_name = "example_folder";

    if (mkdir(folder_name, 0777) == 0) {
        printf("Folder created successfully.\n");
    } 
    else{
        printf("Failed to create folder.\n");
    }

    return 0;
}

