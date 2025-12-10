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
 * Memory management unit mm/mm.c
 */

#include "mm64.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#if defined(MM64)

/*
 * init_pte - Initialize PTE entry
 */
int init_pte(addr_t *pte,
             int pre,    // present
             addr_t fpn,    // FPN
             int drt,    // dirty
             int swp,    // swap
             int swptyp, // swap type
             addr_t swpoff) // swap offset
{
  if (pre != 0) {
    if (swp == 0) { // Non swap ~ page online
      if (fpn == 0)
        return -1;  // Invalid setting

      /* Valid setting with FPN */
      SETBIT(*pte, PAGING_PTE_PRESENT_MASK);
      CLRBIT(*pte, PAGING_PTE_SWAPPED_MASK);
      CLRBIT(*pte, PAGING_PTE_DIRTY_MASK);

      SETVAL(*pte, fpn, PAGING_PTE_FPN_MASK, PAGING_PTE_FPN_LOBIT);
    }
    else
    { // page swapped
      SETBIT(*pte, PAGING_PTE_PRESENT_MASK);
      SETBIT(*pte, PAGING_PTE_SWAPPED_MASK);
      CLRBIT(*pte, PAGING_PTE_DIRTY_MASK);

      SETVAL(*pte, swptyp, PAGING_PTE_SWPTYP_MASK, PAGING_PTE_SWPTYP_LOBIT);
      SETVAL(*pte, swpoff, PAGING_PTE_SWPOFF_MASK, PAGING_PTE_SWPOFF_LOBIT);
    }
  }

  return 0;
}


/*
 * get_pd_from_pagenum - Parse address to 5 page directory level
 * @pgn   : pagenumer
 * @pgd   : page global directory
 * @p4d   : page level directory
 * @pud   : page upper directory
 * @pmd   : page middle directory
 * @pt    : page table 
 */
int get_pd_from_address(addr_t addr, addr_t* pgd, addr_t* p4d, addr_t* pud, addr_t* pmd, addr_t* pt)
{
	/* Extract page direactories */
	*pgd = PAGING64_ADDR_PGD(addr);
	*p4d = PAGING64_ADDR_P4D(addr);
	*pud = PAGING64_ADDR_PUD(addr);
	*pmd = PAGING64_ADDR_PMD(addr);
	*pt  = PAGING64_ADDR_PT(addr);

	return 0;
}

/*
 * get_pd_from_pagenum - Parse page number to 5 page directory level
 * @pgn   : pagenumer
 * @pgd   : page global directory
 * @p4d   : page level directory
 * @pud   : page upper directory
 * @pmd   : page middle directory
 * @pt    : page table 
 */
int get_pd_from_pagenum(addr_t pgn, addr_t* pgd, addr_t* p4d, addr_t* pud, addr_t* pmd, addr_t* pt)
{
	/* Shift the address to get page num and perform the mapping*/
	return get_pd_from_address(pgn << PAGING64_ADDR_PT_SHIFT,
                         pgd,p4d,pud,pmd,pt);
}

static addr_t* __get_pte(struct pcb_t *caller, addr_t pgn)
{
    addr_t pgd_idx, p4d_idx, pud_idx, pmd_idx, pt_idx;
    get_pd_from_pagenum(pgn, &pgd_idx, &p4d_idx, &pud_idx, &pmd_idx, &pt_idx);

    addr_t *pgd = caller->mm->pgd;

    addr_t *p4d_table = (addr_t*)pgd[pgd_idx];
    if (p4d_table == NULL) {
        p4d_table = (addr_t*)malloc(PAGING64_PAGESZ);
        if (!p4d_table) return NULL;
        memset(p4d_table, 0, PAGING64_PAGESZ);
        pgd[pgd_idx] = (addr_t)p4d_table;
    }

    addr_t *pud_table = (addr_t*)p4d_table[p4d_idx];
    if (pud_table == NULL) {
        pud_table = (addr_t*)malloc(PAGING64_PAGESZ);
        if (!pud_table) return NULL;
        memset(pud_table, 0, PAGING64_PAGESZ);
        p4d_table[p4d_idx] = (addr_t)pud_table;
    }

    addr_t *pmd_table = (addr_t*)pud_table[pud_idx];
    if (pmd_table == NULL) {
        pmd_table = (addr_t*)malloc(PAGING64_PAGESZ);
        if (!pmd_table) return NULL;
        memset(pmd_table, 0, PAGING64_PAGESZ);
        pud_table[pud_idx] = (addr_t)pmd_table;
    }

    addr_t *pt_table = (addr_t*)pmd_table[pmd_idx];
    if (pt_table == NULL) {
        pt_table = (addr_t*)malloc(PAGING64_PAGESZ);
        if (!pt_table) return NULL;
        memset(pt_table, 0, PAGING64_PAGESZ);
        pmd_table[pmd_idx] = (addr_t)pt_table;
    }

    return &pt_table[pt_idx];
}

/*
 * pte_set_swap - Set PTE entry for swapped page
 * @pte    : target page table entry (PTE)
 * @swptyp : swap type
 * @swpoff : swap offset
 */
int pte_set_swap(struct pcb_t *caller, addr_t pgn, int swptyp, addr_t swpoff)
{
  addr_t *pte = __get_pte(caller, pgn);
  if (pte == NULL) return -1;
	
  SETBIT(*pte, PAGING_PTE_PRESENT_MASK);
  SETBIT(*pte, PAGING_PTE_SWAPPED_MASK);

  SETVAL(*pte, swptyp, PAGING_PTE_SWPTYP_MASK, PAGING_PTE_SWPTYP_LOBIT);
  SETVAL(*pte, swpoff, PAGING_PTE_SWPOFF_MASK, PAGING_PTE_SWPOFF_LOBIT);

  return 0;
}

/*
 * pte_set_fpn - Set PTE entry for on-line page
 * @pte   : target page table entry (PTE)
 * @fpn   : frame page number (FPN)
 */
int pte_set_fpn(struct pcb_t *caller, addr_t pgn, addr_t fpn)
{
  addr_t *pte = __get_pte(caller, pgn);
  if (pte == NULL) return -1;

  SETBIT(*pte, PAGING_PTE_PRESENT_MASK);
  CLRBIT(*pte, PAGING_PTE_SWAPPED_MASK);

  SETVAL(*pte, fpn, PAGING_PTE_FPN_MASK, PAGING_PTE_FPN_LOBIT);

  return 0;
}


/* Get PTE page table entry
 * @caller : caller
 * @pgn    : page number
 * @ret    : page table entry
 **/
uint32_t pte_get_entry(struct pcb_t *caller, addr_t pgn)
{
  addr_t pgd_idx, p4d_idx, pud_idx, pmd_idx, pt_idx;
  get_pd_from_pagenum(pgn, &pgd_idx, &p4d_idx, &pud_idx, &pmd_idx, &pt_idx);

  addr_t *pgd = caller->mm->pgd;
  if (pgd == NULL) return 0;

  addr_t *p4d_table = (addr_t*)pgd[pgd_idx];
  if (p4d_table == NULL) return 0;

  addr_t *pud_table = (addr_t*)p4d_table[p4d_idx];
  if (pud_table == NULL) return 0;

  addr_t *pmd_table = (addr_t*)pud_table[pud_idx];
  if (pmd_table == NULL) return 0;

  addr_t *pt_table = (addr_t*)pmd_table[pmd_idx];
  if (pt_table == NULL) return 0;
  
  return pt_table[pt_idx];
}

/* Set PTE page table entry
 * @caller : caller
 * @pgn    : page number
 * @ret    : page table entry
 **/
int pte_set_entry(struct pcb_t *caller, addr_t pgn, uint32_t pte_val)
{
	addr_t *pte = __get_pte(caller, pgn);
	if (pte == NULL) return -1;

	*pte = pte_val;
	
	return 0;
}

/*
 * vmap_pgd_memset - map a range of page at aligned address
 */
int vmap_pgd_memset(struct pcb_t *caller,           // process call
                    addr_t addr,                       // start address which is aligned to pagesz
                    int pgnum)                      // num of mapping page
{
  addr_t pgn_start = addr >> PAGING64_ADDR_PT_SHIFT;
  int pgit;

  for (pgit = 0; pgit < pgnum; pgit++)
  {
    addr_t current_pgn = pgn_start + pgit;
    addr_t *pte = __get_pte(caller, current_pgn);

    if (pte == NULL)
    {
       return -1;
    }
    
    *pte = 0xdeadbeefdeadbeef;
  }

  return 0;
}

/*
 * vmap_page_range - map a range of page at aligned address
 */
addr_t vmap_page_range(struct pcb_t *caller,           // process call
                    addr_t addr,                       // start address which is aligned to pagesz
                    int pgnum,                      // num of mapping page
                    struct framephy_struct *frames, // list of the mapped frames
                    struct vm_rg_struct *ret_rg)    // return mapped region, the real mapped fp
{                                                   // no guarantee all given pages are mapped
  struct framephy_struct *fpit = frames;
  int pgit = 0;
  addr_t pgn_start = addr >> PAGING64_ADDR_PT_SHIFT;

  /* update the rg_end and rg_start of ret_rg */
  ret_rg->rg_start = addr;
  ret_rg->rg_end = addr + pgnum * PAGING64_PAGESZ;

  /* map range of frame to address space */
  for (pgit = 0; pgit < pgnum && fpit != NULL; pgit++)
  {
    addr_t current_pgn = pgn_start + pgit;
    addr_t fpn = fpit->fpn;

    pte_set_fpn(caller, current_pgn, fpn);

    /* Tracking for later page replacement activities (if needed) */
    /* Enqueue new usage page */
    enlist_pgn_node(&caller->mm->fifo_pgn, current_pgn);

    fpit = fpit->fp_next;
  }

  return addr;
}

/*
 * alloc_pages_range - allocate req_pgnum of frame in ram
 * @caller    : caller
 * @req_pgnum : request page num
 * @frm_lst   : frame list
 */
addr_t alloc_pages_range(struct pcb_t *caller, int req_pgnum, struct framephy_struct **frm_lst)
{
  int pgit;
  addr_t fpn;
  struct framephy_struct *newfp_str;

  *frm_lst = NULL;

  for (pgit = 0; pgit < req_pgnum; pgit++)
  {
    /* Thử lấy frame từ RAM */
    if (MEMPHY_get_freefp(caller->mram, &fpn) == 0) 
    {
       newfp_str = malloc(sizeof(struct framephy_struct));
       newfp_str->fpn = fpn;
       newfp_str->fp_next = *frm_lst;
       *frm_lst = newfp_str;
    }
    else
    { 
       /*RAM ĐẦY -> KÍCH HOẠT SWAP*/
       addr_t vicpgn, swpfpn;
       
       if (find_victim_page(caller->mm, &vicpgn) < 0) return -1;

       if (MEMPHY_get_freefp(caller->active_mswp, &swpfpn) < 0) return -1;

       // 3. In thông báo (để bạn thấy)
       printf("SWAP OUT: PGN %ld (FPN %ld) -> SWAP_FPN %ld\n", (long)vicpgn, (long)PAGING_FPN(pte_get_entry(caller, vicpgn)), (long)swpfpn);
       
       // 4. Thực hiện Swap
       __swap_cp_page(caller->mram, PAGING_FPN(pte_get_entry(caller, vicpgn)), caller->active_mswp, swpfpn);
       pte_set_swap(caller, vicpgn, 0, swpfpn);

       // 5. Lấy lại frame
       fpn = PAGING_FPN(pte_get_entry(caller, vicpgn)); // Lấy FPN vừa giải phóng
       newfp_str = malloc(sizeof(struct framephy_struct));
       newfp_str->fpn = fpn;
       newfp_str->fp_next = *frm_lst;
       *frm_lst = newfp_str;
    }
  }
  return 0;
}

/*
 * vm_map_ram - do the mapping all vm are to ram storage device
 * @caller    : caller
 * @astart    : vm area start
 * @aend      : vm area end
 * @mapstart  : start mapping point
 * @incpgnum  : number of mapped page
 * @ret_rg    : returned region
 */
addr_t vm_map_ram(struct pcb_t *caller, addr_t astart, addr_t aend, addr_t mapstart, int incpgnum, struct vm_rg_struct *ret_rg)
{
  struct framephy_struct *frm_lst = NULL;
  addr_t ret_alloc = 0;
  int pgnum = incpgnum;

  /*@bksysnet: author provides a feasible solution of getting frames
   *FATAL logic in here, wrong behaviour if we have not enough page
   *i.e. we request 1000 frames meanwhile our RAM has size of 3 frames
   *Don't try to perform that case in this simple work, it will result
   *in endless procedure of swap-off to get frame and we have not provide
   *duplicate control mechanism, keep it simple
   */
  ret_alloc = alloc_pages_range(caller, pgnum, &frm_lst);

  if (ret_alloc < 0 && ret_alloc != -3000)
    return -1;

  /* Out of memory */
  if (ret_alloc == -3000)
  {
    return -1;
  }

  /* it leaves the case of memory is enough but half in ram, half in swap
   * do the swaping all to swapper to get the all in ram */
   vmap_page_range(caller, mapstart, incpgnum, frm_lst, ret_rg);

  return 0;
}

/* Swap copy content page from source frame to destination frame
 * @mpsrc  : source memphy
 * @srcfpn : source physical page number (FPN)
 * @mpdst  : destination memphy
 * @dstfpn : destination physical page number (FPN)
 **/
int __swap_cp_page(struct memphy_struct *mpsrc, addr_t srcfpn,
                   struct memphy_struct *mpdst, addr_t dstfpn)
{
  int cellidx;
  addr_t addrsrc, addrdst;
  for (cellidx = 0; cellidx < PAGING_PAGESZ; cellidx++)
  {
    addrsrc = srcfpn * PAGING_PAGESZ + cellidx;
    addrdst = dstfpn * PAGING_PAGESZ + cellidx;

    BYTE data;
    MEMPHY_read(mpsrc, addrsrc, &data);
    MEMPHY_write(mpdst, addrdst, data);
  }

  return 0;
}

/*
 *Initialize a empty Memory Management instance
 * @mm:     self mm
 * @caller: mm owner
 */
int init_mm(struct mm_struct *mm, struct pcb_t *caller)
{
  struct vm_area_struct *vma0 = malloc(sizeof(struct vm_area_struct));
  //addr_t pgd_fpn;
  int i;

  mm->pgd = (addr_t*) malloc(PAGING64_PAGESZ);
  if (mm->pgd == NULL) {
     free(vma0);
     return -1;
  }
  memset(mm->pgd, 0, PAGING64_PAGESZ);

  vma0->vm_id = 0;
  vma0->vm_start = 0;
  vma0->vm_end = vma0->vm_start;
  vma0->sbrk = vma0->vm_start;
  struct vm_rg_struct *first_rg = init_vm_rg(vma0->vm_start, vma0->vm_end);
  vma0->vm_freerg_list = NULL;
  enlist_vm_rg_node(&vma0->vm_freerg_list, first_rg);

  vma0->vm_next = NULL;

  vma0->vm_mm = mm; 

  mm->mmap = vma0;
  
  for (i = 0; i < PAGING_MAX_SYMTBL_SZ; i++)
  {
    mm->symrgtbl[i].rg_start = mm->symrgtbl[i].rg_end = 0;
  }
  
  mm->fifo_pgn = NULL;

  return 0;
}

struct vm_rg_struct *init_vm_rg(addr_t rg_start, addr_t rg_end)
{
  struct vm_rg_struct *rgnode = malloc(sizeof(struct vm_rg_struct));

  rgnode->rg_start = rg_start;
  rgnode->rg_end = rg_end;
  rgnode->rg_next = NULL;

  return rgnode;
}

int enlist_vm_rg_node(struct vm_rg_struct **rglist, struct vm_rg_struct *rgnode)
{
  rgnode->rg_next = *rglist;
  *rglist = rgnode;

  return 0;
}

int enlist_pgn_node(struct pgn_t **plist, addr_t pgn)
{
  struct pgn_t *pnode = malloc(sizeof(struct pgn_t));

  pnode->pgn = pgn;
  pnode->pg_next = *plist;
  *plist = pnode;

  return 0;
}

int print_list_fp(struct framephy_struct *ifp)
{
  struct framephy_struct *fp = ifp;

  printf("print_list_fp: ");
  if (fp == NULL) { printf("NULL list\n"); return -1;}
  printf("\n");
  while (fp != NULL)
  {
    printf("fp[" FORMAT_ADDR "]\n", (unsigned long long)fp->fpn);
    fp = fp->fp_next;
  }
  printf("\n");
  return 0;
}

int print_list_rg(struct vm_rg_struct *irg)
{
  struct vm_rg_struct *rg = irg;

  printf("print_list_rg: ");
  if (rg == NULL) { printf("NULL list\n"); return -1; }
  printf("\n");
  while (rg != NULL)
  {
    printf("rg[" FORMAT_ADDR "->"  FORMAT_ADDR "]\n",(unsigned long long) rg->rg_start,(unsigned long long) rg->rg_end);
    rg = rg->rg_next;
  }
  printf("\n");
  return 0;
}

int print_list_vma(struct vm_area_struct *ivma)
{
  struct vm_area_struct *vma = ivma;

  printf("print_list_vma: ");
  if (vma == NULL) { printf("NULL list\n"); return -1; }
  printf("\n");
  while (vma != NULL)
  {
    printf("va[" FORMAT_ADDR "->" FORMAT_ADDR "]\n", (unsigned long long)vma->vm_start, (unsigned long long)vma->vm_end);
    vma = vma->vm_next;
  }
  printf("\n");
  return 0;
}

int print_list_pgn(struct pgn_t *ip)
{
  printf("print_list_pgn: ");
  if (ip == NULL) { printf("NULL list\n"); return -1; }
  printf("\n");
  while (ip != NULL)
  {
    printf("va[" FORMAT_ADDR "]-\n",(unsigned long long) ip->pgn);
    ip = ip->pg_next;
  }
  printf("n");
  return 0;
}

int print_pgtbl(struct pcb_t *caller, addr_t start, addr_t end)
{
  printf("print_pgtbl:\n");

  addr_t pgd_idx, p4d_idx, pud_idx, pmd_idx, pt_idx;
  get_pd_from_address(start, &pgd_idx, &p4d_idx, &pud_idx, &pmd_idx, &pt_idx);

  addr_t *pgd = caller->mm->pgd;
  printf(" PGD=" FORMATX_ADDR,(unsigned long long) (addr_t)pgd);

  addr_t *p4d_table = (addr_t*)pgd[pgd_idx];
  if (p4d_table == NULL) {
    printf("P4g=00000000 PUD=00000000 PMD=00000000\n");
    return 0;
  }
  printf(" P4g=" FORMATX_ADDR, (unsigned long long)(addr_t)p4d_table);

  addr_t *pud_table = (addr_t*)p4d_table[p4d_idx];
  if (pud_table == NULL) {
    printf("PUD=00000000 PMD=00000000\n");
    return 0;
  }
  printf(" PUD=" FORMATX_ADDR, (unsigned long long)(addr_t)pud_table);

  addr_t *pmd_table = (addr_t*)pud_table[pud_idx];
  if (pmd_table == NULL) {
    printf("PMD=00000000\n");
    return 0;
  }
  printf(" PMD=" FORMATX_ADDR, (unsigned long long)(addr_t)pmd_table);
  
  printf("\n");

  return 0;
}

/*
 * dump_memory_complete - Dump memory with page table and physical memory
 * @caller: Process to dump
 * @mram: Physical RAM structure
 * @mswp: Swap space structure (can be NULL)
 * @start: Start virtual address (-1 to use vm_start)
 * @end: End virtual address (-1 to use sbrk)
 */
int dump_memory_complete(struct pcb_t *caller, struct memphy_struct *mram, 
                         struct memphy_struct *mswp, addr_t start, addr_t end)
{
  if (caller == NULL || caller->mm == NULL || mram == NULL) {
    printf("Error: dump_memory_complete - Invalid parameters\n");
    return -1;
  }

  struct vm_area_struct *cur_vma = get_vma_by_num(caller->mm, 0);
  if (cur_vma == NULL) {
    printf("Error: dump_memory_complete - Cannot find VMA\n");
    return -1;
  }

  // Determine address range
  if (end == -1) {
    start = cur_vma->vm_start;
    end = cur_vma->sbrk;
  }
  if (start == -1) {
    start = cur_vma->vm_start;
  }

  addr_t pgn_start = start >> PAGING64_ADDR_PT_SHIFT;
  addr_t pgn_end = (end + PAGING64_PAGESZ - 1) >> PAGING64_ADDR_PT_SHIFT;
  
  printf("\n=== Memory Dump with Page Tables ===\n");
  printf("Process PID: %d\n", caller->pid);
  printf("Virtual Address Range: " FORMATX_ADDR " - " FORMATX_ADDR "\n", 
         (unsigned long long)start, (unsigned long long)end);
  printf("Page Range: " FORMAT_ADDR " - " FORMAT_ADDR "\n\n", 
         (unsigned long long)pgn_start, (unsigned long long)pgn_end);

  // Print page table structure
  addr_t pgd_idx, p4d_idx, pud_idx, pmd_idx, pt_idx;
  get_pd_from_address(start, &pgd_idx, &p4d_idx, &pud_idx, &pmd_idx, &pt_idx);
  
  addr_t *pgd = caller->mm->pgd;
  printf("Page Table Structure:\n");
  printf("  PGD=" FORMATX_ADDR "\n", (unsigned long long)(addr_t)pgd);
  
  if (pgd != NULL) {
    addr_t *p4d_table = (addr_t*)pgd[pgd_idx];
    if (p4d_table != NULL) {
      printf("  P4D=" FORMATX_ADDR "\n", (unsigned long long)(addr_t)p4d_table);
      
      addr_t *pud_table = (addr_t*)p4d_table[p4d_idx];
      if (pud_table != NULL) {
        printf("  PUD=" FORMATX_ADDR "\n", (unsigned long long)(addr_t)pud_table);
        
        addr_t *pmd_table = (addr_t*)pud_table[pud_idx];
        if (pmd_table != NULL) {
          printf("  PMD=" FORMATX_ADDR "\n", (unsigned long long)(addr_t)pmd_table);
        }
      }
    }
  }
  printf("\n");

  addr_t pgit;
  int mapped_count = 0;
  int swapped_count = 0;

  for (pgit = pgn_start; pgit < pgn_end; pgit++) {
    uint32_t pte = pte_get_entry(caller, pgit);

    if (pte == 0) continue; // Skip unmapped pages

    addr_t vaddr = (pgit << PAGING64_ADDR_PT_SHIFT);
    printf("Virtual Page " FORMATX_ADDR " (PGN " FORMAT_ADDR "):\n", 
           (unsigned long long)vaddr, (unsigned long long)pgit);
    printf("  PTE: 0x%08x", pte);

    if (PAGING_PAGE_PRESENT(pte)) {
      if (pte & PAGING_PTE_SWAPPED_MASK) {
        // Swapped page
        addr_t swpfpn = PAGING_PTE_SWP(pte);
        printf(" (Present, Swapped, Swap FPN=" FORMAT_ADDR ")", (unsigned long long)swpfpn);
        if (pte & PAGING_PTE_DIRTY_MASK) printf(" [Dirty]");
        printf("\n  Status: SWAPPED to Swap Frame " FORMAT_ADDR "\n", (unsigned long long)swpfpn);
        
        // Optionally dump from swap space
        if (mswp != NULL) {
          printf("  Swap Frame Content:\n");
          addr_t swap_base = swpfpn * PAGING_PAGESZ;
          int i;
          for (i = 0; i < PAGING_PAGESZ && i < 64; i++) { // Limit output
            BYTE data;
            if (MEMPHY_read(mswp, swap_base + i, &data) == 0) {
              if (i % 16 == 0) printf("    %04x:", i);
              printf(" %02x", (unsigned char)data);
              if (i % 16 == 15) printf("\n");
            }
          }
          if (i < PAGING_PAGESZ) printf("    ... (truncated)\n");
        }
        swapped_count++;
      } else {
        // Present page in RAM
        addr_t fpn = PAGING_FPN(pte);
        printf(" (Present, FPN=" FORMAT_ADDR ")", (unsigned long long)fpn);
        if (pte & PAGING_PTE_DIRTY_MASK) printf(" [Dirty]");
        printf("\n  Physical Frame " FORMAT_ADDR ":\n", (unsigned long long)fpn);
        
        // Dump physical frame content
        addr_t phy_base = fpn * PAGING_PAGESZ;
        int i;
        for (i = 0; i < PAGING_PAGESZ && i < 64; i++) { // Limit output
          BYTE data;
          if (MEMPHY_read(mram, phy_base + i, &data) == 0) {
            if (i % 16 == 0) printf("    %04x:", i);
            printf(" %02x", (unsigned char)data);
            if (i % 16 == 15) printf("\n");
          }
        }
        if (i < PAGING_PAGESZ) printf("    ... (truncated)\n");
        mapped_count++;
      }
    } else {
      printf(" (Not Present)\n");
    }
    printf("\n");
  }

  printf("=== Summary ===\n");
  printf("Total Pages Scanned: " FORMAT_ADDR "\n", (unsigned long long)(pgn_end - pgn_start));
  printf("Mapped Pages (in RAM): %d\n", mapped_count);
  printf("Swapped Pages: %d\n", swapped_count);
  printf("Unmapped Pages: " FORMAT_ADDR "\n", 
         (unsigned long long)((pgn_end - pgn_start) - mapped_count - swapped_count));
  printf("========================\n\n");

  return 0;
}

#endif  //def MM64


