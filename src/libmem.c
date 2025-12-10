/*
 * Copyright (C) 2026 pdnguyen of HCMC University of Technology VNU-HCM
 */
/* System Library - Memory Module - FIXED VERSION */

#include "string.h"
#include "mm.h"
#include "mm64.h"
#include "syscall.h"
#include "libmem.h"
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

static pthread_mutex_t mmvm_lock = PTHREAD_MUTEX_INITIALIZER;

int enlist_vm_freerg_list(struct mm_struct *mm, struct vm_rg_struct *rg_elmt)
{
  struct vm_rg_struct *rg_node = mm->mmap->vm_freerg_list;
  if (rg_elmt->rg_start >= rg_elmt->rg_end) return -1;
  if (rg_node != NULL) rg_elmt->rg_next = rg_node;
  mm->mmap->vm_freerg_list = rg_elmt;
  return 0;
}

struct vm_rg_struct *get_symrg_byid(struct mm_struct *mm, int rgid)
{
  if (rgid < 0 || rgid > PAGING_MAX_SYMTBL_SZ) return NULL;
  return &mm->symrgtbl[rgid];
}

int __alloc(struct pcb_t *caller, int vmaid, int rgid, addr_t size, addr_t *alloc_addr)
{
  pthread_mutex_lock(&mmvm_lock);
  
  
  
  // ===== THÊM ĐOẠN DEBUG NÀY =====
  if (caller->mm == NULL) { printf("DEBUG: __alloc - mm is NULL\n"); pthread_mutex_unlock(&mmvm_lock); return -1; }
  if (caller->mm->mmap == NULL) { printf("DEBUG: __alloc - mmap is NULL\n"); pthread_mutex_unlock(&mmvm_lock); return -1; }
  //printf("DEBUG: __alloc call - PID: %d, Size: %d, Old Sbrk: %lu\n", caller->pid, size, caller->mm->mmap->sbrk);
  // =================================
  
  
  
  struct vm_rg_struct rgnode;
  
  // SỬA: Dùng caller->mm thay vì caller->krnl->mm
  if (caller->mm == NULL) {
      printf("Error: __alloc - caller->mm is NULL\n");
      pthread_mutex_unlock(&mmvm_lock);
      return -1;
  }

  if (get_free_vmrg_area(caller, vmaid, size, &rgnode) == 0)
  {
    caller->mm->symrgtbl[rgid].rg_start = rgnode.rg_start;
    caller->mm->symrgtbl[rgid].rg_end = rgnode.rg_end;
    *alloc_addr = rgnode.rg_start;
    pthread_mutex_unlock(&mmvm_lock);
    return 0;
  }

  int inc_sz = PAGING_PAGE_ALIGNSZ(size);
  int old_sbrk = caller->mm->mmap->sbrk; // Lấy sbrk hiện tại

  struct sc_regs regs;
  regs.a1 = SYSMEM_INC_OP;
  regs.a2 = vmaid;
  regs.a3 = inc_sz;
  
  // Gọi syscall để tăng bộ nhớ
  if (syscall(caller->krnl, caller->pid, 17, &regs) != 0) {
      printf("Error: __alloc - Syscall failed\n");
      pthread_mutex_unlock(&mmvm_lock);
      return -1;
  }

  // Cập nhật bảng symbol
  caller->mm->symrgtbl[rgid].rg_start = old_sbrk;
  caller->mm->symrgtbl[rgid].rg_end = old_sbrk + size;

  *alloc_addr = old_sbrk;
  
  // LƯU Ý: KHÔNG tự tăng sbrk ở đây nữa, syscall đã làm rồi.

  pthread_mutex_unlock(&mmvm_lock);
  return 0;
}

int __free(struct pcb_t *caller, int vmaid, int rgid)
{
  pthread_mutex_lock(&mmvm_lock);
  if (rgid < 0 || rgid > PAGING_MAX_SYMTBL_SZ) {
    pthread_mutex_unlock(&mmvm_lock);
    return -1;
  }
  struct vm_rg_struct *rgnode = get_symrg_byid(caller->mm, rgid);
  if (rgnode->rg_start == 0 && rgnode->rg_end == 0) {
    pthread_mutex_unlock(&mmvm_lock);
    return -1;
  }
  struct vm_rg_struct *freerg_node = malloc(sizeof(struct vm_rg_struct));
  freerg_node->rg_start = rgnode->rg_start;
  freerg_node->rg_end = rgnode->rg_end;
  freerg_node->rg_next = NULL;
  rgnode->rg_start = rgnode->rg_end = 0;
  rgnode->rg_next = NULL;
  enlist_vm_freerg_list(caller->mm, freerg_node);
  pthread_mutex_unlock(&mmvm_lock);
  return 0;
}

int liballoc(struct pcb_t *proc, addr_t size, uint32_t reg_index)
{
  addr_t addr;
  if (__alloc(proc, 0, reg_index, size, &addr) == -1) return -1;
  proc->regs[reg_index] = addr;
  printf("liballoc:178\n");
  print_pgtbl(proc,0,-1);
  return 0;
}

int libfree(struct pcb_t *proc, uint32_t reg_index)
{
  if (__free(proc, 0, reg_index) == -1) return -1;
  proc->regs[reg_index] = 0;
  printf("libfree:218\n");
  print_pgtbl(proc,0,-1);
  return 0;
}

int pg_getpage(struct mm_struct *mm, int pgn, int *fpn, struct pcb_t *caller)
{
  uint32_t pte = pte_get_entry(caller, pgn);
  if (!PAGING_PAGE_PRESENT(pte)) {
      return -1;
  }

  if (PAGING_PTE_SWAPPED_MASK & pte) {
      
      addr_t vicpgn, swpfpn_victim, tgtfpn;
      
      if (find_victim_page(caller->mm, &vicpgn) < 0) {
          if (MEMPHY_get_freefp(caller->mram, &tgtfpn) == 0) {
             pte_set_fpn(caller, pgn, tgtfpn);
             enlist_pgn_node(&caller->mm->fifo_pgn, pgn);
             *fpn = tgtfpn;
             return 0;
          }
          return -1;
      }

      uint32_t vicpte = pte_get_entry(caller, vicpgn);
      addr_t vicfpn = PAGING_FPN(vicpte);
      tgtfpn = vicfpn;

      if (MEMPHY_get_freefp(caller->active_mswp, &swpfpn_victim) < 0) return -1;

      __swap_cp_page(caller->mram, vicfpn, caller->active_mswp, swpfpn_victim);
      pte_set_swap(caller, vicpgn, 0, swpfpn_victim);

      addr_t swpfpn_target = PAGING_PTE_SWP(pte);
      
      __swap_cp_page(caller->active_mswp, swpfpn_target, caller->mram, tgtfpn);
      printf("SWAP IN: SWAP_FPN %d -> PGN %d (FPN %d\n", (int)swpfpn_target, pgn, (int)tgtfpn);
      pte_set_fpn(caller, pgn, tgtfpn);
      MEMPHY_put_freefp(caller->active_mswp, swpfpn_target);
      enlist_pgn_node(&caller->mm->fifo_pgn, pgn);
  }

  *fpn = PAGING_FPN(pte_get_entry(caller, pgn));
  return 0;
}

int pg_getval(struct mm_struct *mm, int addr, BYTE *data, struct pcb_t *caller)
{
  int pgn = PAGING_PGN(addr);
  int off = PAGING_OFFST(addr);
  int fpn;
  if (pg_getpage(mm, pgn, &fpn, caller) != 0) return -1;
  int phyaddr = (fpn << PAGING_ADDR_FPN_LOBIT) + off;
  if (MEMPHY_read(caller->mram, phyaddr, data) != 0) return -1;
  return 0;
}

int pg_setval(struct mm_struct *mm, int addr, BYTE value, struct pcb_t *caller)
{
  int pgn = PAGING_PGN(addr);
  int off = PAGING_OFFST(addr);
  int fpn;
  if (pg_getpage(mm, pgn, &fpn, caller) != 0) return -1;
  int phyaddr = (fpn << PAGING_ADDR_FPN_LOBIT) + off;
  if (MEMPHY_write(caller->mram, phyaddr, value) != 0) return -1;
  
  // Mark dirty
  uint32_t pte = pte_get_entry(caller, pgn);
  SETBIT(pte, PAGING_PTE_DIRTY_MASK);
  pte_set_entry(caller, pgn, pte);
  return 0;
}

int __read(struct pcb_t *caller, int vmaid, int rgid, addr_t offset, BYTE *data)
{
  struct vm_rg_struct *currg = get_symrg_byid(caller->mm, rgid);
  if (currg == NULL || (currg->rg_start + offset >= currg->rg_end)) return -1;
  pg_getval(caller->mm, currg->rg_start + offset, data, caller);
  return 0;
}

int __write(struct pcb_t *caller, int vmaid, int rgid, addr_t offset, BYTE value)
{
  struct vm_rg_struct *currg = get_symrg_byid(caller->mm, rgid);
  if (currg == NULL || (currg->rg_start + offset >= currg->rg_end)) return -1;
  pg_setval(caller->mm, currg->rg_start + offset, value, caller);
  return 0;
}

int libread(struct pcb_t *proc, uint32_t source, addr_t offset, uint32_t* destination)
{
  BYTE data;
  if (__read(proc, 0, source, offset, &data) == 0) {
      *destination = data;
      printf("libread:426\n");
      return 0;
  }
  return -1;
}

int libwrite(struct pcb_t *proc, BYTE data, uint32_t destination, addr_t offset)
{
  int res = __write(proc, 0, destination, offset, data);
  if (res != -1) {
      /* Code in ra giống mẫu */
      printf("libwrite:502\n");
      print_pgtbl(proc, 0, -1);
  }
  return res;
}

int find_victim_page(struct mm_struct *mm, addr_t *retpgn)
{
  if (mm==NULL) return -1;
  struct pgn_t *pg = mm->fifo_pgn;
  if (!pg) return -1;
  struct pgn_t *prev = NULL;
  while (pg->pg_next) {
    prev = pg;
    pg = pg->pg_next;
  }
  *retpgn = pg->pgn;
  if (prev == NULL) mm->fifo_pgn = NULL;
  else prev->pg_next = NULL;
  free(pg);
  return 0;
}

int get_free_vmrg_area(struct pcb_t *caller, int vmaid, int size, struct vm_rg_struct *newrg)
{
  struct vm_area_struct *cur_vma = get_vma_by_num(caller->mm, vmaid);
  struct vm_rg_struct *rgit = cur_vma->vm_freerg_list;
  struct vm_rg_struct *prev = NULL;
  if (rgit == NULL) return -1;
  
  while (rgit != NULL) {
    if (rgit->rg_start + size <= rgit->rg_end) {
      newrg->rg_start = rgit->rg_start;
      newrg->rg_end = rgit->rg_start + size;
      if (rgit->rg_start + size < rgit->rg_end) {
        rgit->rg_start += size;
      } else {
        if(prev == NULL) cur_vma->vm_freerg_list = rgit->rg_next;
        else prev->rg_next = rgit->rg_next;
        free(rgit);
      }
      return 0;
    }
    prev = rgit;
    rgit = rgit->rg_next;
  }
  return -1;
}
