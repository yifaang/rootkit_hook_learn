#include <linux/init.h>
#include <linux/ftrace.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
//kallsyms_lookup_name_ Function Pointer 
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
kallsyms_lookup_name_t kallsyms_lookup_name_;


//Init ftrace Struct 
struct ftrace_Function
{
    const char *name;
    unsigned long  address;
    unsigned long function;
    struct ftrace_ops ops;
};
struct ftrace_Function *trace_func;


static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name",
};


/* Create Sys_kill_Hook Function Pointer*/
typedef asmlinkage long (*sys_kill_t)(const struct pt_regs *regs);
sys_kill_t sys_kill_;
static asmlinkage int hook_kill(const struct pt_regs *regs) {
    pid_t __user *user_pid = (pid_t*)(regs->di);
    int __user *user_sig = (int*)(regs->si);
    // // Access user space data using get_user
    pr_info("Get PID %d\tGet sig %d", user_pid,user_sig);
    pr_info("Hook Success");
    return sys_kill_(regs);
}

/* Create Sys_mkdir Hook Function */
typedef asmlinkage long (*sys_mkdir_ptr)(const struct pt_regs *regs);
sys_mkdir_ptr orig_mkdir;
static asmlinkage int hook_mkdir(const struct pt_regs *regs)
{
    char __user *pathname = (char *)regs->di;
    char dir_name[NAME_MAX] = {0};
    long error = strncpy_from_user(dir_name, pathname, NAME_MAX);
    if (error > 0)
        printk(KERN_INFO "User Create dir : %s", dir_name);
    return orig_mkdir(regs);
}

// Callback Function 
void  HookFunction(unsigned long ip, unsigned long parent_ip,struct ftrace_ops *op, struct pt_regs *regs){
    if (!within_module(parent_ip,THIS_MODULE))
    {
        regs->ip = (unsigned long)trace_func->address;
    } 
}

/* Install & Uninstall Hook  */
void install_my_hook(void){
    int err;
    trace_func->ops.func = (ftrace_func_t)HookFunction;
    trace_func->ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION |FTRACE_OPS_FL_IPMODIFY;
    ftrace_set_filter_ip(&trace_func->ops,trace_func->function,0,0);
    err = register_ftrace_function(&trace_func->ops);
    if (err == -1)
    {
        pr_err("Register ftrace function error");
        return;
    }
    else{
        pr_info("Register ftrace function success");
    }
}

void uninstall_my_hook(void){
    unregister_ftrace_function(&trace_func->ops);
}


static int __init KernelLoad(void){
    trace_func = kmalloc(sizeof(struct ftrace_Function), GFP_KERNEL);
    int ret = register_kprobe(&kp);
    if (ret == -1 )
    {
        pr_err("kprobe Can't Found Address");
    }
    kallsyms_lookup_name_ = (kallsyms_lookup_name_t)kp.addr;
    unregister_kprobe(&kp);
    unsigned long *syscall_table = kallsyms_lookup_name_("sys_call_table");
    unsigned long sys_mkdir_address = (unsigned long)(syscall_table[__NR_mkdir]);
    orig_mkdir = (sys_mkdir_ptr)sys_mkdir_address;

    unsigned long sys_kill_address = (unsigned long)(syscall_table[__NR_kill]);
    sys_kill_ = (sys_kill_t)sys_kill_address;

    trace_func->address =(unsigned long)hook_kill;
    trace_func->function = sys_kill_address;

    install_my_hook();
    pr_info("Hook Complete");
    return 0;
} 

static void __exit KernelUnload(void){
    uninstall_my_hook();
    pr_info("Unload Kernel");
}

MODULE_LICENSE("GPL");
module_init(KernelLoad);
module_exit(KernelUnload);
