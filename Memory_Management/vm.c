#include "param.h"
#include "types.h"
#include "defs.h"
#include "x86.h"
#include "memlayout.h"
#include "mmu.h"
#include "proc.h"
#include "elf.h"

extern char data[]; // defined by kernel.ld
pde_t *kpgdir;      // for use in scheduler()

// Set up CPU's kernel segment descriptors.
// Run once on entry on each CPU.
void seginit(void)
{
  struct cpu *c;

  // Map "logical" addresses to virtual addresses using identity map.
  // Cannot share a CODE descriptor for both kernel and user
  // because it would have to have DPL_USR, but the CPU forbids
  // an interrupt from CPL=0 to DPL=3.
  c = &cpus[cpuid()];
  c->gdt[SEG_KCODE] = SEG(STA_X | STA_R, 0, 0xffffffff, 0);
  c->gdt[SEG_KDATA] = SEG(STA_W, 0, 0xffffffff, 0);
  c->gdt[SEG_UCODE] = SEG(STA_X | STA_R, 0, 0xffffffff, DPL_USER);
  c->gdt[SEG_UDATA] = SEG(STA_W, 0, 0xffffffff, DPL_USER);
  lgdt(c->gdt, sizeof(c->gdt));
}

// Return the address of the PTE in page table pgdir
// that corresponds to virtual address va.  If alloc!=0,
// create any required page table pages.
static pte_t *
walkpgdir(pde_t *pgdir, const void *va, int alloc)
{
  pde_t *pde;
  pte_t *pgtab;

  pde = &pgdir[PDX(va)];
  if (*pde & PTE_P)
  {
    pgtab = (pte_t *)P2V(PTE_ADDR(*pde));
  }
  else
  {
    if (!alloc || (pgtab = (pte_t *)kalloc()) == 0)
      return 0;
    // Make sure all those PTE_P bits are zero.
    memset(pgtab, 0, PGSIZE);
    // The permissions here are overly generous, but they can
    // be further restricted by the permissions in the page table
    // entries, if necessary.
    *pde = V2P(pgtab) | PTE_P | PTE_W | PTE_U;
  }
  return &pgtab[PTX(va)];
}

// Create PTEs for virtual addresses starting at va that refer to
// physical addresses starting at pa. va and size might not
// be page-aligned.
static int
mappages(pde_t *pgdir, void *va, uint size, uint pa, int perm)
{
  char *a, *last;
  pte_t *pte;

  a = (char *)PGROUNDDOWN((uint)va);
  last = (char *)PGROUNDDOWN(((uint)va) + size - 1);
  for (;;)
  {
    if ((pte = walkpgdir(pgdir, a, 1)) == 0)
      return -1;
    if (*pte & PTE_P)
      panic("remap");
    *pte = pa | perm | PTE_P;
    if (a == last)
      break;
    a += PGSIZE;
    pa += PGSIZE;
  }
  return 0;
}

// There is one page table per process, plus one that's used when
// a CPU is not running any process (kpgdir). The kernel uses the
// current process's page table during system calls and interrupts;
// page protection bits prevent user code from using the kernel's
// mappings.
//
// setupkvm() and exec() set up every page table like this:
//
//   0..KERNBASE: user memory (text+data+stack+heap), mapped to
//                phys memory allocated by the kernel
//   KERNBASE..KERNBASE+EXTMEM: mapped to 0..EXTMEM (for I/O space)
//   KERNBASE+EXTMEM..data: mapped to EXTMEM..V2P(data)
//                for the kernel's instructions and r/o data
//   data..KERNBASE+PHYSTOP: mapped to V2P(data)..PHYSTOP,
//                                  rw data + free physical memory
//   0xfe000000..0: mapped direct (devices such as ioapic)
//
// The kernel allocates physical memory for its heap and for user memory
// between V2P(end) and the end of physical memory (PHYSTOP)
// (directly addressable from end..P2V(PHYSTOP)).

// This table defines the kernel's mappings, which are present in
// every process's page table.
static struct kmap
{
  void *virt;
  uint phys_start;
  uint phys_end;
  int perm;
} kmap[] = {
    {(void *)KERNBASE, 0, EXTMEM, PTE_W},            // I/O space
    {(void *)KERNLINK, V2P(KERNLINK), V2P(data), 0}, // kern text+rodata
    {(void *)data, V2P(data), PHYSTOP, PTE_W},       // kern data+memory
    {(void *)DEVSPACE, DEVSPACE, 0, PTE_W},          // more devices
};

// Set up kernel part of a page table.
pde_t *
setupkvm(void)
{
  pde_t *pgdir;
  struct kmap *k;

  if ((pgdir = (pde_t *)kalloc()) == 0)
    return 0;
  memset(pgdir, 0, PGSIZE);
  if (P2V(PHYSTOP) > (void *)DEVSPACE)
    panic("PHYSTOP too high");
  for (k = kmap; k < &kmap[NELEM(kmap)]; k++)
    if (mappages(pgdir, k->virt, k->phys_end - k->phys_start,
                 (uint)k->phys_start, k->perm) < 0)
    {
      freevm(pgdir);
      return 0;
    }
  return pgdir;
}

// Allocate one page table for the machine for the kernel address
// space for scheduler processes.
void kvmalloc(void)
{
  kpgdir = setupkvm();
  switchkvm();
}

// Switch h/w page table register to the kernel-only page table,
// for when no process is running.
void switchkvm(void)
{
  lcr3(V2P(kpgdir)); // switch to the kernel page table
}

// Switch TSS and h/w page table to correspond to process p.
void switchuvm(struct proc *p)
{
  if (p == 0)
    panic("switchuvm: no process");
  if (p->kstack == 0)
    panic("switchuvm: no kstack");
  if (p->pgdir == 0)
    panic("switchuvm: no pgdir");

  pushcli();
  mycpu()->gdt[SEG_TSS] = SEG16(STS_T32A, &mycpu()->ts,
                                sizeof(mycpu()->ts) - 1, 0);
  mycpu()->gdt[SEG_TSS].s = 0;
  mycpu()->ts.ss0 = SEG_KDATA << 3;
  mycpu()->ts.esp0 = (uint)p->kstack + KSTACKSIZE;
  // setting IOPL=0 in eflags *and* iomb beyond the tss segment limit
  // forbids I/O instructions (e.g., inb and outb) from user space
  mycpu()->ts.iomb = (ushort)0xFFFF;
  ltr(SEG_TSS << 3);
  lcr3(V2P(p->pgdir)); // switch to process's address space
  popcli();
}

// Load the initcode into address 0 of pgdir.
// sz must be less than a page.
void inituvm(pde_t *pgdir, char *init, uint sz)
{
  char *mem;

  if (sz >= PGSIZE)
    panic("inituvm: more than a page");
  mem = kalloc();
  memset(mem, 0, PGSIZE);
  mappages(pgdir, 0, PGSIZE, V2P(mem), PTE_W | PTE_U);
  memmove(mem, init, sz);
}

// Load a program segment into pgdir.  addr must be page-aligned
// and the pages from addr to addr+sz must already be mapped.
int loaduvm(pde_t *pgdir, char *addr, struct inode *ip, uint offset, uint sz)
{
  uint i, pa, n;
  pte_t *pte;

  if ((uint)addr % PGSIZE != 0)
    panic("loaduvm: addr must be page aligned");
  for (i = 0; i < sz; i += PGSIZE)
  {
    if ((pte = walkpgdir(pgdir, addr + i, 0)) == 0)
      panic("loaduvm: address should exist");
    pa = PTE_ADDR(*pte);
    if (sz - i < PGSIZE)
      n = sz - i;
    else
      n = PGSIZE;
    if (readi(ip, P2V(pa), offset + i, n) != n)
      return -1;
  }
  return 0;
}

///////////////////////////////////////////// vodro \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\//

int _update_ram_counters(struct proc *p)
{
  if (!_not_sh_init(p))
    return 0;
  for (int i = 0; i < p->_queue_size; i++)
  {
    pte_t *pte = walkpgdir(p->pgdir, (char *)p->_ram_pages_va[i], 0);
    // cprintf("pte is %x used = %x\n", *pte, (*pte & PTE_A));
    // cprintf("va = %x age : %x\n", p->_ram_pages_va[i], p->_ram_pages_couter[i]);
    p->_ram_pages_couter[i] = p->_ram_pages_couter[i] >> 1;
    if (*pte & PTE_A)
    {
      p->_ram_pages_couter[i] |= (1 << (4 * 8 - 1));
      if (AGING_DETAILS)

        cprintf("pid = %x | va = %x      accessed. so  counter : %x\n", p->pid, p->_ram_pages_va[i], p->_ram_pages_couter[i]);
    }
    else
    {
      if (AGING_DETAILS)
        cprintf("pid = %x | va = %x not  accessed. so  counter : %x\n", p->pid, p->_ram_pages_va[i], p->_ram_pages_couter[i]);
    }
    // cprintf("va = %x pore : %x\n", p->_ram_pages_va[i], p->_ram_pages_couter[i]);

    *pte &= ~PTE_A;
  }
  return 0;
}

// return 0 when successful
int _swap_out(struct proc *p, pde_t *pgdir)
{
  if(SWAP_IN_OUT_PRINT){
    cprintf("before swap out : \n"); 
    _print_container(p); 
  }
  // cprintf("_monitor_page_ram_allocate : our queue is full now !\n");
  // cprintf("DEQUEU IS MERA VAI \n");

  uint va = _dequeue(p);
  // p->_num_pages_ram--;
  // cprintf("DEQUEU IS MERA VAI \n");

  // cprintf("-------- %x %x", A2PN(pgdata->p_va), pgdata->offset);
  pte_t *pte = walkpgdir(pgdir, (char *)va, 0);
  uint pa = PTE_ADDR(*pte);
  // cprintf(" virtual address = %p physical address of %p offset %x\n", A2PN(pgdata->p_va), A2PN(pa), pgdata->offset);
  if (pa == 0)
    panic("alloc_swap_kfree");
  // uint kpa = P2V(pa);
  // char *buff = uva2ka(pgdir, pgdata->p_va);

  if ((*pte & PTE_P) != 0)
  {

    char *v = P2V(pa);
    // cprintf("testing va = %x, pa = %x P2V = %x V2P = %x \n", va, pa, P2V(pa), V2P(pa));
    uint offset = _get_a_free_offset(p, va) * PGSIZE;
    if (writeToSwapFile(p, (char *)v, offset, PGSIZE) < 0)
    {
      panic("swap in : writeToSwapFile failed!\n");
    }

    // Do something with the flags-----------------------
    // *pte &= ~PTE_
    *pte &= ~PTE_P;
    *pte |= PTE_PG;

    // experimental
    // *pte &= ~PTE_
    kfree(v);
    // eita age comment out chilo
    // lcr3(V2P(pgdir)); // ei jinish toh lage nah ! boycott this
    // if (p->pid == 3)
    if (SWAP_DETAILS)
      cprintf("pid = %x | SWAP out : va = %x pte = %x pgdir = %x queue = %x offset = %x\n", p->pid, A2PN(va), PTE_ADDR(*pte), *pgdir, p->_queue_size, offset);

    // *pte = 0; // page entry should persist
  }
  else
  {
    cprintf("_swap out :  how on earth not present page to be swapped out.\n");
    return -1;
  }
  if(SWAP_IN_OUT_PRINT){
    cprintf("after swap out : \n"); 
    _print_container(p); 
  }
  
  return 0;
}

// return 0 when successful
int _swap_in(struct proc *p, pde_t *pgdir, uint va)
{
  if(SWAP_IN_OUT_PRINT){
    cprintf("before swap IN : \n"); 
    _print_container(p); 
  }
  va = PGROUNDDOWN(va);
  pte_t *pte = walkpgdir(pgdir, (char *)va, 0);
  if ((*pte & PTE_PG) == 0)
  {
    cprintf("pid = %x the page doesn't exist %x\n", p->pid, A2PN(va));
    panic("the page doesn't exist\n");
    return -1;
  }
  else
  {
    // cprintf("swap_in page : %x\n", A2PN(va));
  }
  // new ram page created
  char *mem = kalloc();
  // cprintf("pid = %x | va = %x\n", va);
  uint offset = _find_and_remove_page_offset(p, va) * PGSIZE;
  // mem has been read
  if (readFromSwapFile(p, mem, offset, PGSIZE) < 0)
  {
    panic("swap in : readFromSwapFile failed !\n");
  }
  _enqueue(p, va, offset);
  
  uint flags = PTE_FLAGS(*pte);
  flags &= ~PTE_PG;
  // now mappages may need to be rewritten
  if (mappages(pgdir, (char *)va, PGSIZE, V2P(mem), flags) < 0)
  {
    panic("swap in failed ");
    return -1;
  }
  // if (p->pid == 3)
  if (SWAP_DETAILS)
    cprintf("pid = %x | SWAP in  : va = %x pte = %x pgdir = %x queue = %x offset = %x\n", p->pid, A2PN(va), PTE_ADDR(*pte), *pgdir, p->_queue_size, offset);

  lcr3(V2P(pgdir)); // should we comment it out ?

  // cprintf("_swap in : %x done \n ", (*pte & PTE_P));
  if(SWAP_IN_OUT_PRINT){
    cprintf("AFTER swap IN : \n"); 
    _print_container(p);  
  }
  


  return 0;
}

// returns -1 when page count exists MAX_TOTAL_PAGES
// return 0 normally
char _monitor_page_ram_allocate(struct proc *_child_proc, pde_t *pgdir)
{
  struct proc *p = _child_proc;
  // cprintf("_monitor_page_ram_allocate : (%s %d )  pages = (%d, %d)   size = %d\n", p->name, p->pid, myproc()->_num_pages_ram, _total_page_count(), myproc()->sz);

  if (!_not_sh_init(p))
    return 0;

  // cprintf("_monitor_page_ram_allocate : (%s %d )  pages = (%d, %d)   size = %d\n", p->name, p->pid, myproc()->_num_pages_ram, _total_page_count(), myproc()->sz);
  // taken 29 as we need a buffer page for swap in and out
  if (p->_num_pages_total == MAX_TOTAL_PAGES)
  {
    cprintf("_monitor_page_ram_allocate : something is not wrong. page count exceeds : %d\n", MAX_TOTAL_PAGES);
    // panic("_monitor_page_ram_allocate");
    return -1;
  }

  // we should now swap out
  while (p->_queue_size >= MAX_PSYC_PAGES - 1)
  {
    _swap_out(p, pgdir);
  }
  if (p->_queue_size > MAX_PSYC_PAGES)
  {
    panic("queue has more page than limit\n");
  }
  // cprintf("")

  // now we have to through a page out
  return 0;
}

// returns -1 when page count exists MAX_TOTAL_PAGES
// return 0 normally
char _monitor_page_ram_deallocate(struct proc *p, uint va)
{
  if (!_not_sh_init(p))
    return 0;

  _remove_page_from_container(p, va);

  if (p->_num_pages_total == 0)
  {
    cprintf("_monitor_page_ram_allocate : something is not wrong. page count goes below : %d\n", 0);
    // panic("_monitor_page_ram_deallocate");
    return -1;
  }
  // cprintf("_monitor_page_ram_deallocate : (%s %d %d)\n", p->name, p->pid, p->_num_pages_ram);
  if (p->_queue_size < 0)
  {
    cprintf("_monitor_page_ram_deallocate : something is not wrong. page count shrinks bellow  : %d\n", 0);
    // return -1;
  }
  return 0;
}

// return 0 if successful
int _alloc_page_to_queue_swap(struct proc *p, pde_t *pgdir, uint va)
{
  // cprintf("p ----- %x va = %x\n", p->pid, va);
  uint offset = A2PN(va) * PGSIZE;
  // char *buff = uva2ka(pgdir, (char *)va);
  pte_t *pte = walkpgdir(pgdir, (char *)va, 0);
  if (pte == 0)
  {
    panic("alloc_page_to_queueu_swap\n");
  }
  // now we don't need to have the page in swap file
  // uint pa = PTE_ADDR(*pte);
  // char *buff = P2V(PTE_ADDR(*pte));
  // char *buff2 = (char *)V2P(PTE_ADDR(*pte));
  // cprintf("pid = %d buff1 = %p   offset = %x %x %x\n", p->pid, buff, offset, PGSIZE, p->_queue_size);
  // writeToSwapFile(p, buff, offset, PGSIZE);
  // if (writeToSwapFile(p, buff, offset, PGSIZE) < 0)
  // {
  //   panic("init : writeToSwapFile failed\n");
  // }
  // cprintf("p ----- %x va = %x\n", p->pid, va);

  _enqueue(p, va, offset);
  // p->_num_pages_ram++;
  // cprintf("p ----- %x va = %x\n", p->pid, va);

  // cprintf("alloc : virtual address of %p offset %x queue size %x\n", A2PN(pgdata.p_va), pgdata.offset, p->_queue_size);
  return 0;
}

///////////////////////////////////////////// vodro \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\//

// Allocate page tables and physical memory to grow process from oldsz to
// newsz, which need not be page aligned.  Returns new size or 0 on error.
int allocuvm(pde_t *pgdir, uint oldsz, uint newsz)
{
  // cprintf("pid %x | allocuvm enters \n", myproc()->pid);

  // cprintf("alloc : old size = %x new size = %x\n", oldsz, newsz);
  char *mem;
  uint a;

  if (newsz >= KERNBASE)
    return 0;
  if (newsz < oldsz)
    return oldsz;

  a = PGROUNDUP(oldsz);
  for (; a < newsz; a += PGSIZE)
  {
    mem = kalloc();
    if (mem == 0)
    {
      cprintf("allocuvm out of memory\n");
      deallocuvm(pgdir, newsz, oldsz);
      return 0;
    }
    memset(mem, 0, PGSIZE);
    ///////////////////////////////////////////// vodro \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\//
    // cprintf("page number = %x %x\n", A2PN(a), PTE_ADDR(mem));
    _monitor_page_ram_allocate(myproc(), pgdir);

    ///////////////////////////////////////////// vodro \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\//

    if (mappages(pgdir, (char *)a, PGSIZE, V2P(mem), PTE_W | PTE_U) < 0)
    {
      cprintf("allocuvm out of memory (2)\n");
      deallocuvm(pgdir, newsz, oldsz);
      kfree(mem);
      return 0;
    }
    ///////////////////////////////////////////// vodro \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\//
    if (_not_sh_init(myproc()))
    {
      // cprintf("page number = %x\n", A2PN(a));
      // lcr3(V2P(my))
      _alloc_page_to_queue_swap(myproc(), pgdir, a);
      myproc()->_num_pages_total++;
    }

    ///////////////////////////////////////////// vodro \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\//
  }
  // cprintf("pid %x | allocuvm returns \n", myproc()->pid);

  return newsz;
}

// Deallocate user pages to bring the process size from oldsz to
// newsz.  oldsz and newsz need not be page-aligned, nor does newsz
// need to be less than oldsz.  oldsz can be larger than the actual
// process size.  Returns the new process size.
int deallocuvm(pde_t *pgdir, uint oldsz, uint newsz)
{
  // cprintf("pid %x | deallocuvm enters \n", myproc()->pid);
  pte_t *pte;
  uint a, pa;

  if (newsz >= oldsz)
    return oldsz;

  a = PGROUNDUP(newsz);
  for (; a < oldsz; a += PGSIZE)
  {
    // cprintf("size now : %x\n", a);
    pte = walkpgdir(pgdir, (char *)a, 0);
    ///////////////////////////////////////////// vodro \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\//
    struct proc *p = myproc();
    if (p->_dealloc_update && pte && (*pte & PTE_P) && _not_sh_init(p))
    {
      _monitor_page_ram_deallocate(p, a);
      p->_num_pages_total--;
    }
    ///////////////////////////////////////////// vodro \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\//
    if (!pte)
      a = PGADDR(PDX(a) + 1, 0, 0) - PGSIZE;
    else if ((*pte & PTE_P) != 0)
    {
      pa = PTE_ADDR(*pte);
      if (pa == 0)
        panic("kfree");
      char *v = P2V(pa);
      kfree(v);
      *pte = 0;
    }
  }
  // cprintf("pid %x | deallocuvm returns \n", myproc()->pid);

  return newsz;
}

// Free a page table and all the physical memory pages
// in the user part.
void freevm(pde_t *pgdir)
{
  uint i;

  if (pgdir == 0)
    panic("freevm: no pgdir");
  deallocuvm(pgdir, KERNBASE, 0);
  for (i = 0; i < NPDENTRIES; i++)
  {
    if (pgdir[i] & PTE_P)
    {
      char *v = P2V(PTE_ADDR(pgdir[i]));
      kfree(v);
    }
  }
  kfree((char *)pgdir);
}

// Clear PTE_U on a page. Used to create an inaccessible
// page beneath the user stack.
void clearpteu(pde_t *pgdir, char *uva)
{
  pte_t *pte;

  pte = walkpgdir(pgdir, uva, 0);
  if (pte == 0)
    panic("clearpteu");
  *pte &= ~PTE_U;
}

// Given a parent process's page table, create a copy
// of it for a child.
pde_t *
copyuvm(pde_t *pgdir, uint sz, struct proc *_child_proc)
{
  // cprintf("copyuvm enters\n");
  pde_t *d;
  pte_t *pte;
  uint pa, i, flags;
  char *mem;

  if ((d = setupkvm()) == 0)
    return 0;

  for (i = 0; i < sz; i += PGSIZE)
  {

    if ((pte = walkpgdir(pgdir, (void *)i, 0)) == 0)
      panic("copyuvm: pte should exist");
    if (!((*pte & PTE_P) || (*pte & PTE_PG)))
      panic("copyuvm: page not present");
    pa = PTE_ADDR(*pte);
    flags = PTE_FLAGS(*pte);
    ///////////////////////////////////////////// vodro \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\//
    // cprintf("copyuvm called with \n");
    _monitor_page_ram_allocate(_child_proc, d);
    ///////////////////////////////////////////// vodro \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\//
    if ((mem = kalloc()) == 0)
      goto bad;
    memmove(mem, (char *)P2V(pa), PGSIZE);
    if (mappages(d, (void *)i, PGSIZE, V2P(mem), flags) < 0)
    {
      kfree(mem);
      goto bad;
    }
    else if (_not_sh_init(_child_proc))
    {
      ///////////////////////////////////////////// vodro \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\//
      _alloc_page_to_queue_swap(_child_proc, d, i);
      // _child_proc->_num_pages_ram++;
      // memmove(mem, (char *)P2V(pa), PGSIZE);
      _child_proc->_num_pages_total++;
      ///////////////////////////////////////////// vodro \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\//
    }
  }
  // cprintf("copyuvm returns\n");

  return d;

bad:
  freevm(d);
  return 0;
}

// PAGEBREAK!
//  Map user virtual address to kernel address.
char *
uva2ka(pde_t *pgdir, char *uva)
{
  pte_t *pte;

  pte = walkpgdir(pgdir, uva, 0);
  // cprintf("uva2ka PTE %x uva2k %x\n", *pte, *pte & PTE_P);
  if ((*pte & PTE_P) == 0)
    return 0;
  if ((*pte & PTE_U) == 0)
    return 0;
  return (char *)P2V(PTE_ADDR(*pte));
}

// Copy len bytes from p to user address va in page table pgdir.
// Most useful when pgdir is not the current page table.
// uva2ka ensures this only works for PTE_U pages.
int copyout(pde_t *pgdir, uint va, void *p, uint len)
{
  char *buf, *pa0;
  uint n, va0;

  buf = (char *)p;
  while (len > 0)
  {
    va0 = (uint)PGROUNDDOWN(va);
    pa0 = uva2ka(pgdir, (char *)va0);
    if (pa0 == 0)
      return -1;
    n = PGSIZE - (va - va0);
    if (n > len)
      n = len;
    memmove(pa0 + (va - va0), buf, n);
    len -= n;
    buf += n;
    va = va0 + PGSIZE;
  }
  return 0;
}

// PAGEBREAK!
//  Blank page.
// PAGEBREAK!
//  Blank page.
// PAGEBREAK!
//  Blank page.
