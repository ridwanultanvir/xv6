#include "types.h"
// #include "ulib.c"
#include "user.h"

#define PGSIZE 4096


int main(int argc, char *argv[])
{
    for (int i = 0; i < argc; i++)
    {
        // printf(1, "%s\n", argv[i]);
    }
    char *c;

    /*
    code sysproc.c
    how this works?
    sys_sbrk(void) ==> 
    growproc ==> 
    if(n > 0){
        allocuvm(curproc->pgdir, sz, sz + n))
    }
    else if(n < 0){
        sz = deallocuvm(curproc->pgdir, sz, sz + n
    }
    */ 
    if (argc == 2)
    {
        int size = atoi(argv[1]) * 4 * 1024;
        printf(1, "now it  is time for malloc %s size %d\n", argv[1], size);
        printf(1,"\n\n\n\n==================================================================\n");
        c = sbrk(size);
        // fork();
        uint *temp = (uint *)c;
        for (uint i = 0; i < size; i += 4)
        {
            // printf(1)
            *temp = i;
            // printf(1, "%x : %x\n", i, (*temp));
            temp += 1;
        }
        
        
        c = sbrk(-size);
        c++;
    }
    else
    {
        printf(1, "you missed the size.\n");
    }

    printf(1, "test was successful!\n");
    wait();
    exit();
}
 