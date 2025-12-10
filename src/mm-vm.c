/*
 * Copyright (C) 2026 pdnguyen of HCMC University of Technology VNU-HCM
 */

/* LamiaAtrium release
 * Source Code License Grant: The authors hereby grant to Licensee
 * personal permission to use and modify the Licensed Source Code
 * for the sole purpose of studying while attending the course CO2018.
 */

/*
 * PAGING based Memory Management
 * Virtual memory module mm/mm-vm.c
 *
 * PHIÊN BẢN SỬA LỖI (Fixed validate_overlap và inc_vma_limit)
 */

#include "string.h"
#include "mm.h"
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

struct vm_area_struct *get_vma_by_num(struct mm_struct *mm, int vmaid)
{
  struct vm_area_struct *pvma = mm->mmap;

  if (mm->mmap == NULL)
    return NULL;

  int vmait = pvma->vm_id;

  while (vmait < vmaid)
  {
    if (pvma == NULL)
      return NULL;

    pvma = pvma->vm_next;
    vmait = pvma->vm_id;
  }

  return pvma;
}

int __mm_swap_page(struct pcb_t *caller, addr_t vicfpn , addr_t swpfpn)
{
    __swap_cp_page(caller->krnl->mram, vicfpn, caller->krnl->active_mswp, swpfpn);
    return 0;
}

struct vm_rg_struct *get_vm_area_node_at_brk(struct pcb_t *caller, int vmaid, addr_t size, addr_t alignedsz)
{
  struct vm_rg_struct * newrg;
  struct vm_area_struct *cur_vma = get_vma_by_num(caller->mm, vmaid);

  if (cur_vma == NULL)
    return NULL;

  newrg = malloc(sizeof(struct vm_rg_struct));

  newrg->rg_start = cur_vma->sbrk;
  newrg->rg_end = newrg->rg_start + size;

  return newrg;
}

/*
 * validate_overlap_vm_area
 * SỬA LỖI: Thêm cur_vma để bỏ qua việc tự kiểm tra
 */
int validate_overlap_vm_area(struct pcb_t *caller, int vmaid, addr_t vmastart, addr_t vmaend)
{
  if (vmastart >= vmaend) {
    return -1;
  }

  struct vm_area_struct *vma = caller->mm->mmap;
  struct vm_area_struct *cur_vma = get_vma_by_num(caller->mm, vmaid);

  while (vma != NULL)
  {
    if (vma != cur_vma) // Bỏ qua việc so sánh VMA với chính nó
    {
        // Kiểm tra chồng lấn: (StartA < EndB) and (EndA > StartB)
        if (vmastart < vma->vm_end && vmaend > vma->vm_start) {
            // Có chồng lấn
            return -1; 
        }
    }
    vma = vma->vm_next;
  }

  return 0; // Không chồng lấn
}

/*
 * inc_vma_limit
 * SỬA LỖI: Cập nhật cả vm_end và sbrk
 */
int inc_vma_limit(struct pcb_t *caller, int vmaid, addr_t inc_sz)
{
    if (caller == NULL || caller->mm == NULL) {
        printf("Error: inc_vma_limit - caller or mm is NULL\n");
        return -1;
    }
    
    struct vm_area_struct *cur_vma = get_vma_by_num(caller->mm, vmaid);
    if (cur_vma == NULL) {
        printf("Error: inc_vma_limit - Cannot find VMA %d\n", vmaid);
        return -1;
    }
    
    // Tính số page cần allocate (làm tròn LÊN)
    int incnumpage = (inc_sz + PAGING_PAGESZ - 1) / PAGING_PAGESZ;
    
    addr_t old_sbrk = cur_vma->sbrk;
    addr_t new_sbrk = old_sbrk + inc_sz;
    
    // Kiểm tra overlap với các VMA khác
    if (validate_overlap_vm_area(caller, vmaid, old_sbrk, new_sbrk) < 0) {
        printf("Error: inc_vma_limit - Memory overlap detected\n");
        return -1;
    }
    
    /* 
     * ========== BƯỚC QUAN TRỌNG NHẤT ==========
     * Gọi vmap_pgd_memset để tạo page table structure
     * Hàm này sẽ trigger __get_pte → allocate P4D, PUD, PMD, PT
     * Nếu không có bước này, print_pgtbl sẽ in P4D/PUD/PMD = 0
     */
    #ifdef MM64
    if (vmap_pgd_memset(caller, old_sbrk, incnumpage) != 0) {
        printf("Error: inc_vma_limit - vmap_pgd_memset failed\n");
        return -1;
    }
    #endif
    
    /* Cấp phát physical frames và map vào page table */
    struct vm_rg_struct newrg;  // Dùng stack variable, không cần malloc
    if (vm_map_ram(caller, old_sbrk, new_sbrk, 
                   old_sbrk, incnumpage, &newrg) < 0) {
        printf("Error: inc_vma_limit - vm_map_ram failed\n");
        return -1;
    }
    
    /* Chỉ cập nhật state SAU KHI thành công */
    cur_vma->sbrk = new_sbrk;
    cur_vma->vm_end = new_sbrk;
    
    return 0;
}


