/*
 * labspectrekm.c
 * Kernel module for the Spectre lab in the Secure Hardware Design course at MIT
 * Created by Joseph Ravichandran for Spring 2022
 * Updated for Spring 2024
 * Get the latest course materials here: https://shd.mit.edu
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/mm.h>
#include <linux/highmem.h>

#include "labspectrekm.h"
#include "labspectreipc.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Joseph Ravichandran <jravi@mit.edu>");
MODULE_DESCRIPTION("Spectre lab target module for Secure Hardware Design at MIT");

// The secrets you're trying to leak!
static volatile char __attribute__((aligned(32768))) kernel_secret3[SHD_SPECTRE_LAB_SECRET_MAX_LEN] = "UNC{j4m35_B0nD}";
static volatile char __attribute__((aligned(32768))) kernel_secret2[SHD_SPECTRE_LAB_SECRET_MAX_LEN] = "UNC{g0_h33ls}";
static volatile char __attribute__((aligned(32768))) kernel_secret1[SHD_SPECTRE_LAB_SECRET_MAX_LEN] = "UNC{sp3ctr3_i5_c00l}";

// The bounds checks that you need to use speculative execution to bypass
static volatile size_t __attribute__((aligned(32768))) secret_leak_limit_part2 = 4;
static volatile size_t __attribute__((aligned(32768))) secret_leak_limit_part3 = 4;

static struct proc_dir_entry *spectre_lab_procfs_victim = NULL;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
#define HAS_PIN_USER_PAGES 1
#else
#define HAS_PIN_USER_PAGES 0
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
static const struct proc_ops spectre_lab_victim_ops = {
    .proc_write = spectre_lab_victim_write,
    .proc_read = spectre_lab_victim_read,
};
#else
static const struct file_operations spectre_lab_victim_ops = {
    .write = spectre_lab_victim_write,
    .read = spectre_lab_victim_read,
};
#endif

/*
 * print_cmd
 * Prints a nicely formatted command to stdout
 *
 * Arguments:
 *  - cmd: A pointer to a spectre_lab_command object to the kernel log
 *
 * Returns: None
 * Side Effects: Prints to kernel log
 */
void print_cmd(spectre_lab_command *cmd) {
    if (NULL == cmd) return;

    printk(SHD_PRINT_INFO "Command at %p\n\tKind: %d\n\tArg 1: 0x%llX\n",
            cmd,
            cmd->kind,
            cmd->arg1);
}

/*
 * spectre_lab_init
 * Installs the procfs handlers for communicating with this module.
 */
int spectre_lab_init(void) {
    printk(SHD_PRINT_INFO "SHD Spectre KM Loaded\n");
    spectre_lab_procfs_victim = proc_create(SHD_PROCFS_NAME, 0777, NULL, &spectre_lab_victim_ops);
    return 0;
}

/*
 * spectre_lab_fini
 * Cleans up the procfs handlers and cleanly removes the module from the kernel.
 */
void spectre_lab_fini(void) {
    printk(SHD_PRINT_INFO "SHD Spectre KM Unloaded\n");
    proc_remove(spectre_lab_procfs_victim);
}

/*
 * spectre_lab_victim_read
 * procfs read handler that does nothing so that reading from /proc/SHD_PROCFS_NAME
 * can actually return.
 */
ssize_t spectre_lab_victim_read(struct file *file_in, char __user *userbuf, size_t num_bytes, loff_t *offset) {
    // Reading does nothing
    return 0;
}

/*
 * spectre_lab_victim_write
 * procfs write handler for interacting with the module
 * Writes expect the user to write a spectre_lab_command struct to the module.
 *
 * Input: A spectre_lab_command struct for us to parse.
 * Output: Number of bytes accepted by the module.
 * Side Effects: Will trigger a spectre bug based on the user_cmd.kind
 */
ssize_t spectre_lab_victim_write(struct file *file_in, const char __user *userbuf, size_t num_bytes, loff_t *offset) {
    spectre_lab_command user_cmd;
    struct page *pages[SHD_SPECTRE_LAB_SHARED_MEMORY_NUM_PAGES];
    char *kernel_mapped_region[SHD_SPECTRE_LAB_SHARED_MEMORY_NUM_PAGES];
    int retval;
    int i, j, z;
    char secret_data;
    volatile char tmp;
    size_t long_latency;
    char *addr_to_leak;

    for (i = 0; i < SHD_SPECTRE_LAB_SHARED_MEMORY_NUM_PAGES; i++) {
        pages[i] = NULL;
    }

    if (copy_from_user(&user_cmd, userbuf, sizeof(user_cmd)) == 0) {
        // arg1 is always a pointer to the shared memory region
        if (!access_ok(user_cmd.arg1, SHD_SPECTRE_LAB_SHARED_MEMORY_SIZE)) {
            printk(SHD_PRINT_INFO "Invalid user request- shared memory is 0x%llX\n", user_cmd.arg1);
            return num_bytes;
        }

        // arg2 is always the secret index to use
        if (!(user_cmd.arg2 < SHD_SPECTRE_LAB_SECRET_MAX_LEN)) {
            printk(SHD_PRINT_INFO "Tried to access a secret that is too large! Requested offset %llu\n", user_cmd.arg2);
            return num_bytes;
        }

        // Pin the pages to RAM so they aren't swapped to disk
#if HAS_PIN_USER_PAGES
        retval = pin_user_pages_fast(user_cmd.arg1, SHD_SPECTRE_LAB_SHARED_MEMORY_NUM_PAGES, FOLL_WRITE, pages);
#else
        retval = get_user_pages_fast(user_cmd.arg1, SHD_SPECTRE_LAB_SHARED_MEMORY_NUM_PAGES, FOLL_WRITE, pages);
#endif // HAS_PIN_USER_PAGES

        if (SHD_SPECTRE_LAB_SHARED_MEMORY_NUM_PAGES != retval) {
            printk(SHD_PRINT_INFO "Unable to pin the user pages! Requested %d pages, got %d\n", SHD_SPECTRE_LAB_SHARED_MEMORY_NUM_PAGES, retval);

            // If the return value is negative, its an error, so don't try to unpin!
            if (retval > 0) {
                // Unpin the pages that got pinned before exiting
#if HAS_PIN_USER_PAGES
                unpin_user_pages(pages, retval);
#else
                put_user_pages(pages, retval);
#endif // HAS_PIN_USER_PAGES
            }

            return num_bytes;
        }

        // Map the new pages (aliases to the userspace pages) into the kernel address space
        // Accessing these pages will incur a TLB miss as they were just remapped
        for (i = 0; i < SHD_SPECTRE_LAB_SHARED_MEMORY_NUM_PAGES; i++) {
            kernel_mapped_region[i] = (char *)kmap(pages[i]);

            if (NULL == kernel_mapped_region[i]) {
                printk(SHD_PRINT_INFO "Unable to map page %d\n", i);

                // Unmap everything in reverse order and return early
                for (j = i - 1; j >= 0; j--) {
                    kunmap(pages[j]);
                }

                return num_bytes;
            }
        }

        // Process this command packet
        switch (user_cmd.kind) {
            // Part 1 is Flush+Reload, so access a secret without a bounds check
            case COMMAND_PART1:
                secret_data = kernel_secret1[user_cmd.arg2];
                if (secret_data < SHD_SPECTRE_LAB_SHARED_MEMORY_NUM_PAGES) {
                    tmp = *kernel_mapped_region[secret_data];
                }
            break;

            // Part 2 is Spectre, so access a secret bounded by a bounds check
            case COMMAND_PART2:
                // Load the secret:
                secret_data = kernel_secret2[user_cmd.arg2];

                // Trigger a page walk:
                addr_to_leak = kernel_mapped_region[secret_data];

                // Flush the limit variable to make this if statement take a long time to resolve
                clflush(&secret_leak_limit_part2);
                if (user_cmd.arg2 < secret_leak_limit_part2) {
                    // Perform the speculative leak
                    tmp = *addr_to_leak;
                }
            break;

            // Part 3 is a more difficult version of Spectre
            case COMMAND_PART3:
                // No cache flush this time around!
                for (z = 0; z < 1000; z++);
                if (user_cmd.arg2 < secret_leak_limit_part3) {
                    long_latency = user_cmd.arg2 * 1ULL * 1ULL * 1ULL * 1ULL * 0ULL;
                    tmp = *kernel_mapped_region[kernel_secret3[user_cmd.arg2] + long_latency];
                }
            break;
        }

        // Unmap in reverse order- needs to be reverse order!
        for (i = SHD_SPECTRE_LAB_SHARED_MEMORY_NUM_PAGES - 1; i >= 0; i--) {
            kunmap(pages[i]);
        }

        // Unpin to ensure refcounts are valid
#if HAS_PIN_USER_PAGES
        unpin_user_pages(pages, SHD_SPECTRE_LAB_SHARED_MEMORY_NUM_PAGES);
#else
        put_user_pages(pages, SHD_SPECTRE_LAB_SHARED_MEMORY_NUM_PAGES);
#endif // HAS_PIN_USER_PAGES

        // Success!
        return num_bytes;
    }
    else {
        // Error
        return 0;
    }
}

module_init(spectre_lab_init);
module_exit(spectre_lab_fini);
