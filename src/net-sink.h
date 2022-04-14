#ifndef _NET_SINK_H_
#define _NET_SINK_H_

// #include "concurrentqueue.h"

// extern moodycamel::ConcurrentQueue<char*> log_queue;

#ifdef __cplusplus
extern "C" {
#endif
void tcp_sink_init(const char* addr);

#ifdef __cplusplus
}
#endif

#endif