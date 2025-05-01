#ifndef SHD_SPECTRE_LAB_IPC_H
#define SHD_SPECTRE_LAB_IPC_H

/******************************
 * SHD Spectre Lab Parameters *
 ******************************/

// Name of the victim file in /proc/
#define SHD_PROCFS_NAME "labspectre-victim"

#define SHD_SPECTRE_LAB_PAGE_SIZE ((0x1000))

// How many pages should be shared between the userspace and kernel?
#define SHD_SPECTRE_LAB_SHARED_MEMORY_NUM_PAGES ((256))

// Size of the shared memory region in bytes
#define SHD_SPECTRE_LAB_SHARED_MEMORY_SIZE ((SHD_SPECTRE_LAB_PAGE_SIZE * SHD_SPECTRE_LAB_SHARED_MEMORY_NUM_PAGES))

// Maximum secret length (in bytes)
#define SHD_SPECTRE_LAB_SECRET_MAX_LEN ((64))

/*********************************************************
 * SHD Spectre Lab Shared Structures (Kernel/ Userspace) *
 *********************************************************/

// "IPC" is a bit of a misnomer, as we now target the kernel instead of another process

/*
 * spectre_lab_command_kind
 * One of the commands we can issue to the kernel
 */
typedef enum {
	// Non-speculatively leak part of the secret (Part 1)
	COMMAND_PART1,

	// Run the vulnerable method (vulnerable to spectre) (Part 2)
	COMMAND_PART2,

	// Run the second vulnerable method (vulnerable to spectre) but harder! (Part 3)
	COMMAND_PART3
} spectre_lab_command_kind;

/*
 * spectre_lab_command
 * A command packet for a single action we can request from the kernel
 */
typedef struct spectre_lab_command_t {
	// What kind of command is this?
	spectre_lab_command_kind kind;

	// Usually this is the user virtual address of the shared memory region
	uint64_t arg1;

	// Usually this is the offset into the secret to access
	uint64_t arg2;
} spectre_lab_command;

#endif // SHD_SPECTRE_LAB_IPC_H
