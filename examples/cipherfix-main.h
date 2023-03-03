/*
Header with all necessary Cipherfix infrastructure.
Used for reducing the example boilerplate.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#define CLOCK CLOCK_MONOTONIC

#include "cipherfix.h"

// Functions that each example must define.
void cf_init_target(void);
void cf_run_target(bool dumpResult);
void cf_prepare_next(void);


void __attribute__((optimize("O0"))) foo()
{
    void *a = malloc(4);
    free(a);
}

int main(int argc, char *argv[])
{
    // Time measurement
    struct timespec timeStart, timeLoop, timeEnd;
    clock_gettime(CLOCK, &timeStart);

    foo();

    // Number of iterations
    int n = 1;
    if(argc >= 2)
    {
        n = atoi(argv[1]);
        printf("Running %d rounds\n", n);
    }

    // Performance evaluation mode?
    bool performanceMode = false;
    if(argc >= 3 && strcmp(argv[2], "perf") == 0)
    {
        printf("Performance mode\n");
        performanceMode = true;
    }
    
    // Initialize target
    cf_init_target();

    clock_gettime(CLOCK, &timeLoop);
    while(n --> 0)
    {
        // Run target
        cf_run_target(!performanceMode || n == 0);

        // Ensure that there is no leftover taint
        drop_taint();

        // Update variables to prepare next run
        cf_prepare_next();
    }
    
    clock_gettime(CLOCK, &timeEnd);
    int64_t durationInit = (timeLoop.tv_sec - timeStart.tv_sec) * 1000000 + (timeLoop.tv_nsec - timeStart.tv_nsec) / 1000;
    int64_t durationLoop = (timeEnd.tv_sec - timeLoop.tv_sec) * 1000000 + (timeEnd.tv_nsec - timeLoop.tv_nsec) / 1000;

    printf("\n");
    printf("Init time: %*ld us -> %*.3f ms\n", 9, durationInit, 9, durationInit / 1000.0);
    printf("Loop time: %*ld us -> %*.3f ms\n", 9, durationLoop, 9, durationLoop / 1000.0);

    return 0;
}
