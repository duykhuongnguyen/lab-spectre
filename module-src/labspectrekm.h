#ifndef SHD_SPECTRE_LAB_KM_H
#define SHD_SPECTRE_LAB_KM_H

#define SHD_LABNAME "labspectre"
#define SHD_PRINT_INFO KERN_INFO "[" SHD_LABNAME "] "

ssize_t spectre_lab_victim_read(struct file *file_in, char __user *userbuf, size_t num_bytes, loff_t *offset);
ssize_t spectre_lab_victim_write(struct file *file_in, const char __user *userbuf, size_t num_bytes, loff_t *offset);

#endif // SHD_SPECTRE_LAB_KM_H
