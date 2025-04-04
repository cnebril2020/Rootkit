#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

int main() {
    printf("Current UID: %d\n", getuid());

    // set UID to root (0)
    setuid(0);

    printf("UID after setuid: %d\n", getuid());
    return 0;
}