cmd_/home/yfsec/rootkit/Linux_kernel_modules/Syscall_Hook/lkm.mod := printf '%s\n'   lkm.o | awk '!x[$$0]++ { print("/home/yfsec/rootkit/Linux_kernel_modules/Syscall_Hook/"$$0) }' > /home/yfsec/rootkit/Linux_kernel_modules/Syscall_Hook/lkm.mod
