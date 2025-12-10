/*
 * Copyright (C) 2026 pdnguyen of HCMC University of Technology VNU-HCM
 */

/* LamiaAtrium release
 * Source Code License Grant: The authors hereby grant to Licensee
 * personal permission to use and modify the Licensed Source Code
 * for the sole purpose of studying while attending the course CO2018.
 */

#include "os-mm.h"
#include "syscall.h"
#include "libmem.h"
#include "queue.h"
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

#ifdef MM64
#include "mm64.h"
#else
#include "mm.h"
#endif

pthread_mutex_t syscall_lock = PTHREAD_MUTEX_INITIALIZER;
/* Hàm trợ giúp: Tìm PCB trong một queue dựa trên PID */
struct pcb_t *find_pcb_by_pid(struct queue_t *q, uint32_t pid)
{
    if (q == NULL)
        return NULL;
    
    /* Duyệt qua tất cả process trong queue */
    for (int i = 0; i < q->size; i++) {
        if (q->proc[i]->pid == pid) {
            return q->proc[i];
        }
    }
    
    return NULL;
}

/* * LƯU Ý QUAN TRỌNG: 
 * - krnl phải là con trỏ (struct krnl_t *)
 * - regs phải là con trỏ (struct sc_regs *)
 */
int __sys_memmap(struct krnl_t *krnl, uint32_t pid, struct sc_regs *regs)
{
   pthread_mutex_lock(&syscall_lock);
   int memop = regs->a1; // Dùng -> vì regs là con trỏ
   BYTE value;
   
   // DEBUG: Kiểm tra xem syscall có được gọi không
   // printf("DEBUG: __sys_memmap called by PID %d, Op: %d\n", pid, memop);

   struct pcb_t *caller = find_pcb_by_pid(krnl->running_list, pid);
   if (caller == NULL) {
       #ifdef MLQ_SCHED
       for (int i = 0; i < MAX_PRIO; i++) {
           caller = find_pcb_by_pid(&krnl->mlq_ready_queue[i], pid);
           if (caller != NULL) break;
       }
       #else
       caller = find_pcb_by_pid(krnl->ready_queue, pid);
       #endif
   }

   if (caller == NULL) {
       printf("[Kernel] Error: sys_memmap cannot find PID %u\n", pid);
        pthread_mutex_unlock(&syscall_lock);
       return -1;
   }

   switch (memop) {
   case SYSMEM_MAP_OP:
            vmap_pgd_memset(caller, regs->a2, regs->a3);
            break;
   case SYSMEM_INC_OP:
            inc_vma_limit(caller, regs->a2, regs->a3);
            break;
   case SYSMEM_SWP_OP:
            __mm_swap_page(caller, regs->a2, regs->a3);
            break;
   case SYSMEM_IO_READ:
             // Dùng krnl->mram vì krnl là con trỏ
             if (MEMPHY_read(krnl->mram, regs->a2, &value) == 0) {
                regs->a3 = value; // Trả giá trị về cho userspace
             } else {
                regs->a3 = 0; // Hoặc mã lỗi
             }
            break;
   case SYSMEM_IO_WRITE:
             MEMPHY_write(krnl->mram, regs->a2, regs->a3);
            break;
   default:
            printf("Memop code: %d\n", memop);
             pthread_mutex_unlock(&syscall_lock);
            break;
   }
   pthread_mutex_unlock(&syscall_lock);
   return 0;
}
