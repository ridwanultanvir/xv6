#include "types.h"
#include "user.h"
#include "param.h"
#include "pstat.h"

#define MAX_CHILD 5


int currentNoChild = 5; 

int pids[MAX_CHILD];
int tickets[MAX_CHILD];

void run_to_infinity()
{
    while (1)
    {
        // printf(1, "SOMETHING IS WRONG\n");
    };
}

int init_child(int tickets)
{
    int pid = fork();
    if (pid < 0)
    {
        printf(1, "THIS IS ERROR \n");
        return -1;
    }
    if (pid == 0)
    {
        // child

        // printf(1, "tickets : %d\n", tickets);
        settickets(tickets);

        run_to_infinity();
        return -1;
    }
    else
    {
        // parent
        return pid;
    }
}

void showinfo()
{
    struct pstat ps;
    getpinfo(&ps);
    printf(1, "PID    TICKETS    TICKS\n");

    for (int i = 0; i < NPROC; i++)
    {
        // printf(1, "cnt = %d : %d\n", i, ps.inuse[i]);
        if (ps.inuse[i] == 0)
        {
            // printf(1, "i = %d is not used\n", i);
            continue;
        }
        else
        {
            for (int k = 0; k < currentNoChild; k++)
            {
                if (pids[k] == ps.pid[i])
                {
                    printf(1, "%d       %d         %d\n", ps.pid[i],
                           ps.tickets[i], ps.ticks[i]);
                    // break;
                }
            }
        }
    }
}

// 1st : sleep time for parent process (default = 1s)
int main(int argc, char **argv)
{

    settickets(1000000);
    currentNoChild = MAX_CHILD; 
    // printf(1, "uptime : %d\n", uptime());

    // exit();
    
    // showinfo();

    int sleepTime = 1000;
    // printf(1, "argc: %d currentNoChild: %d\n", argc, currentNoChild);

    // printf(1, "\n Parameters:------------------- \n");
    /*
    for(int i = 0;i<argc;i++){
        printf(1,"%d\n" , atoi(argv[i]));

    }
    */

    if (argc >= 2)
    {
        sleepTime = atoi(argv[1]);
    }
    
    if(argc > 2)
    {
        
        currentNoChild = argc-2; 
        printf(1, "argc: %d updated currentNoChild:%d\n", argc, currentNoChild);
        for(int i = 0; i < currentNoChild; i++)
        {
            //tickets[0] = atoi(argv[2]) hobe 
            printf(1,"%d-> %d\n" , i, atoi(argv[i+2]));
            tickets[i] = atoi(argv[i+2]); 
        }
        for (int i = 0; i < currentNoChild; i++)
        {
            pids[i] = init_child(tickets[i]);
            // printf(1, "i = %d pid = %d\n", i, pids[i]);
        }
    }
    else{
        for (int i = 0; i < MAX_CHILD; i++)
        {
            tickets[i] = (i * 3 + 10);
        }
        for (int i = 0; i < MAX_CHILD; i++)
        {
            pids[i] = init_child(tickets[i]);
            // printf(1, "i = %d pid = %d\n", i, pids[i]);
        }
         
    }
    
    for (int i = 0; i < currentNoChild; i++)
    {
        printf(1, "tickets[%d]= %d\n", i, tickets[i]);
    }

    
    

    printf(1, "Sleep time %d\n", sleepTime);
    sleep(sleepTime);
    showinfo();

    for (int i = 0; i < currentNoChild; i++)
    {
        kill(pids[i]);
    }

    for (int i = 0; i < currentNoChild; i++)
    {
        if (wait() == -1)
        {
            printf(1, "Error process kill failed ; wait() == -1 found!\n");
        }
    }


    exit();
}