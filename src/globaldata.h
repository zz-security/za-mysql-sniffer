#ifndef _GLOBALDATA_H_
#define _GLOBALDATA_H_

#include "concurrentqueue.h"

extern moodycamel::ConcurrentQueue<char*> log_queue;


#endif
