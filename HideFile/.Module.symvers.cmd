cmd_/home/yfsec/rootkit/Linux_kernel_modules/HideFile/Module.symvers := sed 's/ko$$/o/' /home/yfsec/rootkit/Linux_kernel_modules/HideFile/modules.order | scripts/mod/modpost -m -a  -o /home/yfsec/rootkit/Linux_kernel_modules/HideFile/Module.symvers -e -i Module.symvers   -T -
