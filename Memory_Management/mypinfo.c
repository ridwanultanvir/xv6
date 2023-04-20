#include "types.h"
// #include "ulib.c"
#include "user.h"

#define PGSIZE 4096

/*
int
test1(uint max_page)
{
	uint currsize=(uint)sbrk(0);
 
	for(uint i=currsize;i<max_page * PGSIZE;i+=PGSIZE)
	{
		if(sbrk(PGSIZE) == (void*)-1)
		{
			printf(1,"sbrk error\n");
			return -1;
		}
 
	}
	if((uint)sbrk(0) != (uint)max_page * PGSIZE)
	{
		printf(1,"sbrk error sz != mx_page * pgsz \n");
		return -1;
	}
 
	for(uint i=currsize;i<max_page * PGSIZE;i+=PGSIZE)
	{
		sbrk(-PGSIZE);
	}
 
	return 0;
}
 
int
main(int argc, char * argv[]){
	if(test1(12)==0)
		printf(1,"test 1 passed\n");
	else
		printf(1,"test failed\n");
	
	exit();
}
*/ 

int main(int argc, char *argv[])
{
    for (int i = 0; i < argc; i++)
    {
        // printf(1, "%s\n", argv[i]);
    }
    char *c;

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

        /*
        temp = (uint *)c;
        uint x = 0;
        for (uint i = 0; i < size; i += 4)
        {
            // *temp++ = (char)i;
            // if (i != *temp)
            x = *temp;
            // printf(1, "%x\n", temp);
            if ((uint)temp % PGSIZE == 0 || i % PGSIZE == 0)
                printf(1, "%x : %x va = %x\n", i, x, temp);
            temp += 1;
        }
        printf(1, "x is %x\n", x);
        */ 
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
 