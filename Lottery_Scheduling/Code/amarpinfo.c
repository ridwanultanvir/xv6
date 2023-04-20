#include "types.h"
#include "user.h"
#include "param.h"
#include "pstat.h"

//amarpinfo : getpinfo() ke call korbe 
int
main(int argc, char **argv)
{
    struct pstat curpstat;
    getpinfo(&curpstat);
    printf(1,"pid\ttickets\tticks\t\n");
    for(int i = 0; i<NPROC;i++)
    {
        if(curpstat.inuse[i]!=0)
        {
            printf(1,"%d \t %d \t %d\n", curpstat.pid[i],curpstat.tickets[i], curpstat.ticks[i]);
        }
        else{
            continue; 
            //curpstat.inuse[i] = 0 ; mane hole eta inuse NA; so eta show kora lagbe NA 
        }
    }
    exit();
}