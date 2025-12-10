#include <stdio.h>
#include <stdlib.h>
#include "queue.h"
#include <pthread.h>


int empty(struct queue_t *q)
{
        if (q == NULL)
                return 1;
        return (q->size == 0);
}

void enqueue(struct queue_t *q, struct pcb_t *proc)
{
        /* TODO: put a new process to queue [q] */
        if(q == NULL || proc == NULL)
        {
                return;
        }
        if(q->size >= MAX_QUEUE_SIZE)
        {
                return;
        }

        q->proc[q->size] = proc;
        q->size++;

}

struct pcb_t *dequeue(struct queue_t *q)
{
        /* TODO: return a pcb whose prioprity is the highest
         * in the queue [q] and remember to remove it from q
         * */
        
	if(q == NULL || q->size == 0)
        {
                
                return NULL;
        }
        struct pcb_t *proc = q ->proc[0];
        for(int i=0; i<q->size - 1; i++)
        {
                q->proc[i] = q->proc[i+1];
        }
        q->size--;
        
        return proc;
}       

struct pcb_t *purgequeue(struct queue_t *q, struct pcb_t *proc)
{
        /* TODO: remove a specific item from queue
         * */
if (q == NULL || q->size == 0 || proc == NULL) return NULL;
    
    int found_idx = -1;
    for (int i = 0; i < q->size; i++) {
        // SỬA: So sánh trực tiếp địa chỉ con trỏ thay vì PID
        if (q->proc[i] == proc) { 
            found_idx = i;
            break;
        }
    }
    
    if (found_idx == -1) return NULL;
    
    struct pcb_t *removed_proc = q->proc[found_idx];
    for (int i = found_idx; i < q->size - 1; i++) {
        q->proc[i] = q->proc[i + 1];
    }
    q->size--;
    return removed_proc;
}
