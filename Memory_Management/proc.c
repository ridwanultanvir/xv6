#include "types.h"
#include "defs.h"
#include "param.h"
#include "memlayout.h"
#include "mmu.h"
#include "x86.h"
#include "proc.h"
#include "spinlock.h"
#include "stat.h"

struct
{
  struct spinlock lock;
  struct proc proc[NPROC];
} ptable;

static struct proc *initproc;

int nextpid = 1;
extern void forkret(void);
extern void trapret(void);

static void wakeup1(void *chan);

void pinit(void)
{
  initlock(&ptable.lock, "ptable");
}

// Must be called with interrupts disabled
int cpuid()
{
  return mycpu() - cpus;
}

// Must be called with interrupts disabled to avoid the caller being
// rescheduled between reading lapicid and running through the loop.
struct cpu *
mycpu(void)
{
  int apicid, i;

  if (readeflags() & FL_IF)
    panic("mycpu called with interrupts enabled\n");

  apicid = lapicid();
  // APIC IDs are not guaranteed to be contiguous. Maybe we should have
  // a reverse map, or reserve a register to store &cpus[i].
  for (i = 0; i < ncpu; ++i)
  {
    if (cpus[i].apicid == apicid)
      return &cpus[i];
  }
  panic("unknown apicid\n");
}

// Disable interrupts so that we are not rescheduled
// while reading proc from the cpu structure
struct proc *
myproc(void)
{
  struct cpu *c;
  struct proc *p;
  pushcli();
  c = mycpu();
  p = c->proc;
  popcli();
  return p;
}

// PAGEBREAK: 32
//  Look in the process table for an UNUSED proc.
//  If found, change state to EMBRYO and initialize
//  state required to run in the kernel.
//  Otherwise return 0.
static struct proc *
allocproc(void)
{
  struct proc *p;
  char *sp;

  acquire(&ptable.lock);

  for (p = ptable.proc; p < &ptable.proc[NPROC]; p++)
    if (p->state == UNUSED)
      goto found;

  release(&ptable.lock);
  return 0;

found:
  p->state = EMBRYO;
  p->pid = nextpid++;

  release(&ptable.lock);

  // Allocate kernel stack.
  if ((p->kstack = kalloc()) == 0)
  {
    p->state = UNUSED;
    return 0;
  }
  sp = p->kstack + KSTACKSIZE;

  // Leave room for trap frame.
  sp -= sizeof *p->tf;
  p->tf = (struct trapframe *)sp;

  // Set up new context to start executing at forkret,
  // which returns to trapret.
  sp -= 4;
  *(uint *)sp = (uint)trapret;

  sp -= sizeof *p->context;
  p->context = (struct context *)sp;
  memset(p->context, 0, sizeof *p->context);
  p->context->eip = (uint)forkret;

  ///////////////////////////////////////////// vodro \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\//

  if (_not_sh_init(p))
  {
    // cprintf("alloc proc : file created\n");
    createSwapFile(p);
    p->_queue_size = 0;
    // p->_num_pages_ram = 0;
    p->_dealloc_update = 1;
    p->_num_pages_total = 0;
    for (int i = 0; i < MAX_SWAP_PAGES; i++)
    {
      p->_offset_list[i] = -1;
      // cprintf(" %x \n", p->_offset_list[i]);
    }

    // cprintf("file creation done!\n");
    // _not_sh_init(p);
    // cprintf("%s\n", _not_sh_init(p));
  }
  ///////////////////////////////////////////// vodro \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\//
  return p;
}

// PAGEBREAK: 32
//  Set up first user process.
void userinit(void)
{
  struct proc *p;
  extern char _binary_initcode_start[], _binary_initcode_size[];

  p = allocproc();

  initproc = p;
  if ((p->pgdir = setupkvm()) == 0)
    panic("userinit: out of memory?");
  inituvm(p->pgdir, _binary_initcode_start, (int)_binary_initcode_size);
  p->sz = PGSIZE;
  memset(p->tf, 0, sizeof(*p->tf));
  p->tf->cs = (SEG_UCODE << 3) | DPL_USER;
  p->tf->ds = (SEG_UDATA << 3) | DPL_USER;
  p->tf->es = p->tf->ds;
  p->tf->ss = p->tf->ds;
  p->tf->eflags = FL_IF;
  p->tf->esp = PGSIZE;
  p->tf->eip = 0; // beginning of initcode.S

  safestrcpy(p->name, "initcode", sizeof(p->name));
  p->cwd = namei("/");

  // this assignment to p->state lets other cores
  // run this process. the acquire forces the above
  // writes to be visible, and the lock is also needed
  // because the assignment might not be atomic.
  acquire(&ptable.lock);

  p->state = RUNNABLE;

  release(&ptable.lock);
}

// Grow current process's memory by n bytes.
// Return 0 on success, -1 on failure.
int growproc(int n)
{
  // cprintf("GROWPROC CALLED : %x %x\n", PGROUNDUP(n) / PGSIZE, PGSIZE);
  uint sz;
  struct proc *curproc = myproc();

  sz = curproc->sz;
  if (n > 0)
  {
    if ((sz = allocuvm(curproc->pgdir, sz, sz + n)) == 0)
      return -1;
  }
  else if (n < 0)
  {
    if ((sz = deallocuvm(curproc->pgdir, sz, sz + n)) == 0)
      return -1;
  }
  curproc->sz = sz;
  switchuvm(curproc);
  return 0;
}

// Create a new process copying p as the parent.
// Sets up stack to return as if from system call.
// Caller must set state of returned proc to RUNNABLE.
int fork(void)
{
  int i, pid;
  struct proc *np;
  struct proc *curproc = myproc();

  // Allocate process.
  if ((np = allocproc()) == 0)
  {
    return -1;
  }
  // cprintf("fork : %s \n", np->name);
  // Copy process state from proc.
  if ((np->pgdir = copyuvm(curproc->pgdir, curproc->sz, np)) == 0)
  {
    kfree(np->kstack);
    np->kstack = 0;
    np->state = UNUSED;
    return -1;
  }
  // cprintf("childprocess pgdir copy done.\n");
  np->sz = curproc->sz;
  np->parent = curproc;
  *np->tf = *curproc->tf;

  // Clear %eax so that fork returns 0 in the child.
  np->tf->eax = 0;

  for (i = 0; i < NOFILE; i++)
    if (curproc->ofile[i])
      np->ofile[i] = filedup(curproc->ofile[i]);
  np->cwd = idup(curproc->cwd);

  safestrcpy(np->name, curproc->name, sizeof(curproc->name));

  pid = np->pid;
  // cprintf("childprocess pgdir copy done.\n");

  acquire(&ptable.lock);

  np->state = RUNNABLE;

  release(&ptable.lock);
  // cprintf("fork done borovai!\n");
  return pid;
}

// Exit the current process.  Does not return.
// An exited process remains in the zombie state
// until its parent calls wait() to find out it exited.
void exit(void)
{
  struct proc *curproc = myproc();
  struct proc *p;
  int fd;

  if (curproc == initproc)
    panic("init exiting");

  // Close all open files.
  for (fd = 0; fd < NOFILE; fd++)
  {
    if (curproc->ofile[fd])
    {
      fileclose(curproc->ofile[fd]);
      curproc->ofile[fd] = 0;
    }
  }

  begin_op();
  iput(curproc->cwd);
  end_op();
  curproc->cwd = 0;
  ///////////////////////////////////////////// vodro \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\//
  if (_not_sh_init(curproc))
  {
    // cprintf("exit process ( %s, %d ) : removing swap file \n", curproc->name, curproc->pid);
    removeSwapFile(curproc);
  }
  ///////////////////////////////////////////// vodro \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\//

  acquire(&ptable.lock);

  // Parent might be sleeping in wait().
  wakeup1(curproc->parent);

  // Pass abandoned children to init.
  for (p = ptable.proc; p < &ptable.proc[NPROC]; p++)
  {
    if (p->parent == curproc)
    {
      p->parent = initproc;
      if (p->state == ZOMBIE)
        wakeup1(initproc);
    }
  }

  // Jump into the scheduler, never to return.
  curproc->state = ZOMBIE;

  sched();
  panic("zombie exit");
}

// Wait for a child process to exit and return its pid.
// Return -1 if this process has no children.
int wait(void)
{
  struct proc *p;
  int havekids, pid;
  struct proc *curproc = myproc();

  acquire(&ptable.lock);
  for (;;)
  {
    // Scan through table looking for exited children.
    havekids = 0;
    for (p = ptable.proc; p < &ptable.proc[NPROC]; p++)
    {
      if (p->parent != curproc)
        continue;
      havekids = 1;
      if (p->state == ZOMBIE)
      {
        // Found one.
        pid = p->pid;
        kfree(p->kstack);
        p->kstack = 0;
        freevm(p->pgdir);
        p->pid = 0;
        p->parent = 0;
        p->name[0] = 0;
        p->killed = 0;
        p->state = UNUSED;
        release(&ptable.lock);
        return pid;
      }
    }

    // No point waiting if we don't have any children.
    if (!havekids || curproc->killed)
    {
      release(&ptable.lock);
      return -1;
    }

    // Wait for children to exit.  (See wakeup1 call in proc_exit.)
    sleep(curproc, &ptable.lock); // DOC: wait-sleep
  }
}

// PAGEBREAK: 42
//  Per-CPU process scheduler.
//  Each CPU calls scheduler() after setting itself up.
//  Scheduler never returns.  It loops, doing:
//   - choose a process to run
//   - swtch to start running that process
//   - eventually that process transfers control
//       via swtch back to the scheduler.
void scheduler(void)
{
  struct proc *p;
  struct cpu *c = mycpu();
  c->proc = 0;

  for (;;)
  {
    // Enable interrupts on this processor.
    sti();

    // Loop over process table looking for process to run.
    acquire(&ptable.lock);
    for (p = ptable.proc; p < &ptable.proc[NPROC]; p++)
    {
      if (p->state != RUNNABLE)
        continue;

      // Switch to chosen process.  It is the process's job
      // to release ptable.lock and then reacquire it
      // before jumping back to us.
      c->proc = p;
      switchuvm(p);
      p->state = RUNNING;

      swtch(&(c->scheduler), p->context);
      switchkvm();

      // Process is done running for now.
      // It should have changed its p->state before coming back.
      c->proc = 0;
    }
    release(&ptable.lock);
  }
}

// Enter scheduler.  Must hold only ptable.lock
// and have changed proc->state. Saves and restores
// intena because intena is a property of this
// kernel thread, not this CPU. It should
// be proc->intena and proc->ncli, but that would
// break in the few places where a lock is held but
// there's no process.
void sched(void)
{
  int intena;
  struct proc *p = myproc();

  if (!holding(&ptable.lock))
    panic("sched ptable.lock");
  if (mycpu()->ncli != 1)
    panic("sched locks");
  if (p->state == RUNNING)
    panic("sched running");
  if (readeflags() & FL_IF)
    panic("sched interruptible");
  intena = mycpu()->intena;
  swtch(&p->context, mycpu()->scheduler);
  mycpu()->intena = intena;
}

// Give up the CPU for one scheduling round.
void yield(void)
{
  acquire(&ptable.lock); // DOC: yieldlock
  myproc()->state = RUNNABLE;
  sched();
  release(&ptable.lock);
}

// A fork child's very first scheduling by scheduler()
// will swtch here.  "Return" to user space.
void forkret(void)
{
  static int first = 1;
  // Still holding ptable.lock from scheduler.
  release(&ptable.lock);

  if (first)
  {
    // Some initialization functions must be run in the context
    // of a regular process (e.g., they call sleep), and thus cannot
    // be run from main().
    first = 0;
    iinit(ROOTDEV);
    initlog(ROOTDEV);
  }

  // Return to "caller", actually trapret (see allocproc).
}

// Atomically release lock and sleep on chan.
// Reacquires lock when awakened.
void sleep(void *chan, struct spinlock *lk)
{
  struct proc *p = myproc();

  if (p == 0)
    panic("sleep");

  if (lk == 0)
    panic("sleep without lk");

  // Must acquire ptable.lock in order to
  // change p->state and then call sched.
  // Once we hold ptable.lock, we can be
  // guaranteed that we won't miss any wakeup
  // (wakeup runs with ptable.lock locked),
  // so it's okay to release lk.
  if (lk != &ptable.lock)
  {                        // DOC: sleeplock0
    acquire(&ptable.lock); // DOC: sleeplock1
    release(lk);
  }
  // Go to sleep.
  p->chan = chan;
  p->state = SLEEPING;

  sched();

  // Tidy up.
  p->chan = 0;

  // Reacquire original lock.
  if (lk != &ptable.lock)
  { // DOC: sleeplock2
    release(&ptable.lock);
    acquire(lk);
  }
}

// PAGEBREAK!
//  Wake up all processes sleeping on chan.
//  The ptable lock must be held.
static void
wakeup1(void *chan)
{
  struct proc *p;

  for (p = ptable.proc; p < &ptable.proc[NPROC]; p++)
    if (p->state == SLEEPING && p->chan == chan)
      p->state = RUNNABLE;
}

// Wake up all processes sleeping on chan.
void wakeup(void *chan)
{
  acquire(&ptable.lock);
  wakeup1(chan);
  release(&ptable.lock);
}

// Kill the process with the given pid.
// Process won't exit until it returns
// to user space (see trap in trap.c).
int kill(int pid)
{
  struct proc *p;

  acquire(&ptable.lock);
  for (p = ptable.proc; p < &ptable.proc[NPROC]; p++)
  {
    if (p->pid == pid)
    {

      p->killed = 1;
      // Wake process from sleep if necessary.
      if (p->state == SLEEPING)
        p->state = RUNNABLE;

      release(&ptable.lock);

      return 0;
    }
  }
  release(&ptable.lock);
  return -1;
}

int _print_memory_details(struct proc *p);

// PAGEBREAK: 36
//  Print a process listing to console.  For debugging.
//  Runs when user types ^P on console.
//  No lock to avoid wedging a stuck machine further.
void procdump(void)
{
  static char *states[] = {
      [UNUSED] "unused",
      [EMBRYO] "embryo",
      [SLEEPING] "sleep ",
      [RUNNABLE] "runble",
      [RUNNING] "run   ",
      [ZOMBIE] "zombie"};
  int i;
  struct proc *p;
  char *state;
  uint pc[10];

  for (p = ptable.proc; p < &ptable.proc[NPROC]; p++)
  {
    if (p->state == UNUSED)
      continue;
    if (p->state >= 0 && p->state < NELEM(states) && states[p->state])
      state = states[p->state];
    else
      state = "???";
    cprintf("%d %s %s", p->pid, state, p->name);
    if (p->state == SLEEPING)
    {
      getcallerpcs((uint *)p->context->ebp + 2, pc);
      for (i = 0; i < 10 && pc[i] != 0; i++)
        cprintf(" %p", pc[i]);
    }
    cprintf("\n");
    _print_memory_details(p);
  }

  // for (p = ptable.proc; p < &ptable.proc[NPROC]; p++)
  // {
  //   if (p->state == UNUSED)
  //     continue;
  // }
}

///////////////////////////////////////////// vodro \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\//

// #define PDIR_SIZE (1 << 10)
// #define PGTAB_SIZE (1 << 10)
int _print_memory_details(struct proc *p)
{
  cprintf("Page tables:\n");
  cprintf("    memory location of page directory = %p\n", V2P(p->pgdir));

  // cprintf("my sizeof = %d unit = %d\n", sizeof(&p->pgdir), sizeof(p->pgdir[0]));

  pde_t *pde = p->pgdir;
  pte_t *pgtab;
  for (int i_pdir = 0; pde < &p->pgdir[NPDENTRIES]; pde++, i_pdir++)
  {

    if (*pde & PTE_P)
    {
      pgtab = (pte_t *)P2V(PTE_ADDR(*pde));
      char is_first_time = 1;
      for (int i_pgtab = 0; i_pgtab < NPTENTRIES; i_pgtab++)
      {
        if (*pgtab & PTE_P && *pgtab & PTE_U)
        {
          if (is_first_time)
          {
            cprintf("    pdir PTE %x, %p\n", i_pdir, A2PN(PTE_ADDR(*pde)));
            cprintf("        memory location of page table = %p\n", PTE_ADDR(*pde));
            is_first_time = 0;
          }
          cprintf("            ptbl PTE %x, %x, %p\n", i_pgtab, PTE_ADDR(*pgtab) >> PTXSHIFT, PTE_ADDR(*pgtab));
          // cprintf("IT HAPPEND i_pdir = %d i_pgtab = %d.\n", i_pdir, i_pgtab);
          // cnt++;
          // cprintf("        memory location of page table = %p", *pgtab);
        }
        pgtab++;
      }
    }
  }

  // now print them all

  cprintf("Page mappings:\n");
  pde = p->pgdir;
  for (int i_pdir = 0; pde < &p->pgdir[NPDENTRIES]; pde++, i_pdir++)
  {

    if (*pde & PTE_P)
    {
      pgtab = (pte_t *)P2V(PTE_ADDR(*pde));
      for (int i_pgtab = 0; i_pgtab < NPTENTRIES; i_pgtab++)
      {
        if (*pgtab & PTE_P && *pgtab & PTE_U)
        {
          cprintf("    %p -> %p\n", A2PN(PGADDR(i_pdir, i_pgtab, 0)), A2PN(PTE_ADDR(*pgtab)));
        }
        pgtab++;
      }
    }
  }

  return 0;
}

int _not_sh_init(struct proc *p)
{
  return p->pid > 2; // init 1, sh 2
}

void _print_container(struct proc *p)
{
  cprintf("THIS IS WHOLE QUEUE\n");
  for (int i = 0; i < p->_queue_size; i++)
  {
    cprintf("%d : %x \n", i, p->_ram_pages_va[i]);
  }
}

int _enqueue(struct proc *p, uint va, uint offset)
{

  // _print_container(p);
  // cprintf("enqueue pid = %x va = %x\n", p->pid, va);
  p->_ram_pages_va[p->_queue_size] = va;
  p->_ram_pages_couter[p->_queue_size] = 0;
  // p->_swap_offset[p->_queue_size] = offset;
  p->_queue_size++;
  // cprintf("ENQUEUE : \n");
  // cprintf("va : %x size = %d\n", va, p->_queue_size);
  // _print_container(p);
  return 0;
}

void _swap_ram_pages(struct proc *p, int from, int to)
{
  p->_ram_pages_va[to] = p->_ram_pages_va[from];
  p->_ram_pages_couter[to] = p->_ram_pages_couter[from];
}

int _reorder_ram_queue(struct proc *p)
{
  cprintf("_reorder_ram_queue: ---------------------\n"); 
  if (!_not_sh_init(p))
    return 0;
  // int idx = 0;
  for (int i = 0; i < p->_queue_size - 1; i++)
  {
    if (p->_ram_pages_couter[i] < p->_ram_pages_couter[0])
    {
      cprintf("\n\n queue REORDERING --------------------------------------------------------\n"); 
      // if (AGING_DETAILS)
      cprintf("pid = %x | %x (%x) reordered to  %x\n", p->pid, i, p->_ram_pages_va[i], 0);
      // swapping counters
      uint t = p->_ram_pages_couter[i];
      p->_ram_pages_couter[i] = p->_ram_pages_couter[0];
      p->_ram_pages_couter[0] = t;
      // swapping addresses
      t = p->_ram_pages_va[i];
      p->_ram_pages_va[i] = p->_ram_pages_va[0];
      p->_ram_pages_va[0] = t;
    }
  }
  return 0;
}

// returns the virtual address
uint _dequeue(struct proc *p)
{
  if (AGING_ALGO)
  {
    _reorder_ram_queue(p);
  }
  uint va = p->_ram_pages_va[0];

  if (p->_queue_size == 0)
  {
    panic("_dequeue. no page table but dequeueing");
  }
  for (int i = 0; i < p->_queue_size - 1; i++)
  {
    p->_ram_pages_va[i] = p->_ram_pages_va[i + 1];
    p->_ram_pages_couter[i] = p->_ram_pages_couter[i + 1];
    // p->_pdatas.offset[i] = p->_pdatas.offset[i + 1];
  }
  p->_queue_size--;
  // cprintf("DEQUEUE : \n");
  // _print_container(p);
  return va;
}

// remove an matching entry from our page contatainer
int _remove_page_from_container(struct proc *p, uint va)
{
  // cprintf("_RMOVE_page from container. pid = %x  va = %x\n", p->pid, va);
  int idx = -1;
  for (int i = 0; i < p->_queue_size; i++)
  {
    if (p->_ram_pages_va[i] == va)
    {
      idx = i;
      break;
    }
  }
  if (idx == -1)
    return idx;
  for (int i = idx; i < p->_queue_size - 1; i++)
  {
    p->_ram_pages_va[i] = p->_ram_pages_va[i + 1];
    p->_ram_pages_couter[i] = p->_ram_pages_couter[i + 1];

    // p->_pdatas.offset[i] = p->_pdatas.offset[i + 1];
  }
  p->_queue_size--;
  return idx;
}

uint _get_a_free_offset(struct proc *p, uint va)
{
  va = PTE_ADDR(va);
  for (int i = 0; i < MAX_SWAP_PAGES; i++)
  {
    if (p->_offset_list[i] == -1)
    {
      p->_offset_list[i] = va;
      return i;
    }
  }
  panic("_get_a_free_offset : full");
}
uint _find_and_remove_page_offset(struct proc *p, uint va)
{
  va = PTE_ADDR(va);
  for (int i = 0; i < MAX_SWAP_PAGES; i++)
  {
    if (p->_offset_list[i] == va)
    {
      p->_offset_list[i] = -1;
      return i;
    }
  }
  panic("_find_and_remove_page_offset : you forget to put the page");
}

void _time_incremented()
{
  if (AGING_ALGO)
  {
    acquire(&ptable.lock);
    // cprintf("yahooo ! time barche borovai \n");
    struct proc *p;
    for (p = ptable.proc; p < &ptable.proc[NPROC]; p++)
    {
      if (p->state != UNUSED)
        _update_ram_counters(p);
    }
    release(&ptable.lock);
  }
}

int _total_page_count()
{
  struct proc *p = myproc();
  return PGROUNDUP(p->sz) / PGSIZE;
}

///////////////////////////////////////////// vodro \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\//
