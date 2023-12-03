#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/syscalls.h>
static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name",
};
/*Create Function Pointer
 Kallsyms_lookup_name Is Undocument Function
 In higher Kernel Version Can not Use*/
typedef unsigned long(*kallsyms_lookup_name_t)(const char *name);

/*define mkdir syscall */
//typedef asmlinkage long (*sys_mkdir_ptr)(const char __user *pathname, umode_t mode);
typedef asmlinkage long (*sys_mkdir_ptr)(const struct pt_regs *);
sys_mkdir_ptr orig_mkdir;


asmlinkage int hook_mkdir(const struct pt_regs *regs)
{
    char __user *pathname = (char *)regs->di;
    char dir_name[NAME_MAX] = {0};

    /* Copy the directory name from userspace (pathname, from
     * the pt_regs struct, to kernelspace (dir_name) so that we
     * can print it out to the kernel buffer */
    long error = strncpy_from_user(dir_name, pathname, NAME_MAX);

    if (error > 0)
        printk(KERN_INFO "rootkit: Trying to create directory with name: %s\n", dir_name);

    /* Pass the pt_regs struct along to the original sys_mkdir syscall */
    orig_mkdir(regs);
    return 0;
}


/*Create Hook Function To link old_function */
// asmlinkage long hok_mkdir(const char __user *pathname , umode_t mode){
//     char dir_name[NAME_MAX] = {0}; 
//     long error = copy_from_user(dir_name, pathname, NAME_MAX);
//     if (error > 0)
//     {
//         pr_info("mkdir dir %px",dir_name);
//         pr_info("mkdir dir %s",dir_name);
//         pr_info("mkdir dir %px",*dir_name);
//         pr_info("mkdir dir %px",pathname);
//         pr_info("mkdir dir %px",&pathname);
//         pr_info("mkdir dir %px",*pathname);
//     }
//     else{
//         pr_info("error code %ld",error);
//     }
    
    
//     printk("syscall mkdir by hook");
//     orig_mkdir(pathname,mode);
//     return 0;
// }

/*Open / Close Write Protect 
opcode = 0 Close 
opcode = 1 Open */
inline void wirte_reg(unsigned long cr0){
    asm volatile("mov %0,%%cr0" : "+r"(cr0) : : "memory");
}

void Cr0_write(int opcode){
    if (opcode == 0)
    {
        pr_info("Close Cr0");
        unsigned long cr0 = read_cr0();
        clear_bit(16,&cr0);
        wirte_reg(cr0);
        return;
    }
    pr_info("Open Cr0");
    unsigned long cr0 = read_cr0();
    set_bit(16,&cr0);
    wirte_reg(cr0);
    return;
}
unsigned long mkdir_address ;
unsigned long * syscall_table_address;
static int __init kernelload(void){
    int ret = register_kprobe(&kp);
    if (ret == -1 )
    {
        pr_err("kprobe Register error");
    }
    //Use kprobe Get kallsyms_lookup_name Function Address 
    kallsyms_lookup_name_t kallsyms_lookup_name_ = (kallsyms_lookup_name_t)kp.addr;
    
    syscall_table_address = (kallsyms_lookup_name_)("sys_call_table");
    if (syscall_table_address == NULL)
    {
        pr_info(KERN_SOH "kernel Get sys_call table Error ");
    }
    mkdir_address =(unsigned long)(syscall_table_address[__NR_mkdir]);
    orig_mkdir = (sys_mkdir_ptr)(syscall_table_address[__NR_mkdir]);
    pr_info("orig_mkdir_t is %px",(unsigned long*)orig_mkdir);
    pr_info("hook_mkdir is %px",(unsigned long*)hook_mkdir);

    unregister_kprobe(&kp);
    
    // Close Write Protect
    Cr0_write(0);
    // Replace HookAddress 
    syscall_table_address[__NR_mkdir] = (unsigned long)hook_mkdir;

    // Open Write Protect 
    Cr0_write(1);
    pr_info("Hook Compelet");
    return 0;
}

static void __exit kernelunload(void){
    Cr0_write(0);
    syscall_table_address[__NR_mkdir] = (unsigned long)mkdir_address;
    Cr0_write(1);
    printk("Kernel Unload ");
}

MODULE_LICENSE("GPL");
module_init(kernelload);
module_exit(kernelunload);