/*
 * main
 * Initialization code for the Spectre Lab
 */

#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/mman.h>

#include "labspectre.h"
#include "labspectreipc.h"

/*
 * main
 * Setup shared memory and launch student code.
 */
int main(int argc, char *argv[]) {
    char *shared_memory;

    // Create some shared memory that will be shared by both userspace and kernel
    shared_memory = mmap(NULL, SHD_SPECTRE_LAB_SHARED_MEMORY_SIZE, PROT_READ | PROT_WRITE, MAP_ANON | MAP_SHARED, -1, 0);

    if (NULL == shared_memory) {
        perror("mmap() error");
        exit(EXIT_FAILURE);
    }

    // Setup memory
    init_shared_memory(shared_memory, SHD_SPECTRE_LAB_SHARED_MEMORY_SIZE);

    
    int kernel_fd;

    // Open the file descriptor used to communicate with the kernel module
    kernel_fd = open("/proc/" SHD_PROCFS_NAME, O_RDWR);
    if (kernel_fd < 0) {
        perror("Problem connecting to the kernel module- did you install it?\n");
        exit(EXIT_FAILURE);
    }

    // Run the attacker code :)
    return run_attacker(kernel_fd, shared_memory);
}
