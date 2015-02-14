/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (C) 2007-2012 RELIC Authors
 *
 * This file is part of RELIC. RELIC is legal property of its developers,
 * whose names are not listed here. Please refer to the COPYRIGHT file
 * for contact information.
 *
 * RELIC is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * RELIC is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with RELIC. If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @file
 *
 * Implementation of useful benchmark routines.
 *
 * @version $Id$
 * @ingroup relic
 */

#include <stdio.h>
#include <string.h>

#include "authenc_bench.h"
#define HREAL 0
#define HPROC 1
#define HTHRD 2
#define ANSI 3
#define POSIX 4
#define CYCLE 5
#define MACH 6

#define TIMER HTHRD

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Timer type.
 */
#if TIMER == HREAL || TIMER == HPROC || TIMER == HTHRD

#include <sys/time.h>
#include <time.h>
typedef struct timespec bench_t;

#elif TIMER == ANSI

#include <time.h>
typedef clock_t bench_t;

#elif TIMER == POSIX

#include <sys/time.h>
typedef struct timeval bench_t;

#elif TIMER == CYCLE

typedef unsigned long long bench_t;

#elif TIMER == MACH

#include <mach/mach.h>
#include <mach/mach_time.h>
typedef uint64_t bench_t;

#else

typedef unsigned long long bench_t;

#endif

/**
 * Shared parameter for these timer.
 */
#if TIMER == HREAL
#define CLOCK			CLOCK_REALTIME
#elif TIMER == HPROC
#define CLOCK			CLOCK_PROCESS_CPUTIME_ID
#elif TIMER == HTHRD
#define CLOCK			CLOCK_THREAD_CPUTIME_ID
#else
#define CLOCK			NULL
#endif

/**
 * Stores the time measured before the execution of the benchmark.
 */
static bench_t before;

/**
 * Stores the time measured after the execution of the benchmark.
 */
static bench_t after;

/**
 * Stores the sum of timings for the current benchmark.
 */
static long long total;

/**
 * Benchmarking overhead to be measured and subtracted from benchmarks.
 */
static long long overhead = 0;

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

#if TIMER == CYCLE
unsigned long long arch_cycles(void) {
	unsigned int hi, lo;
	asm("rdtsc\n\t":"=a" (lo), "=d"(hi));
	return ((unsigned long long) lo) | (((unsigned long long) hi) << 32);
}
#endif

void bench_reset() {
#if TIMER != NONE
	total = 0;
#else
	(void)before;
	(void)after;
	(void)overhead;
	(void)empty;
#endif
}

void bench_before() {
#if TIMER == HREAL || TIMER == HPROC || TIMER == HTHRD
	clock_gettime(CLOCK_MONOTONIC, &before);
#elif TIMER == ANSI
	before = clock();
#elif TIMER == POSIX
	gettimeofday(&before, NULL);
#elif TIMER == CYCLE
	before = arch_cycles();
#elif TIMER == MACH
    before = mach_absolute_time();
#endif
}

void bench_after() {
	long long result;
#if TIMER == HREAL || TIMER == HPROC || TIMER == HTHRD
	clock_gettime(CLOCK_MONOTONIC, &after);
	result = ((long)after.tv_sec - (long)before.tv_sec) * 1000000000;
	result += (after.tv_nsec - before.tv_nsec);
#elif TIMER == ANSI
	after = clock();
	result = (after - before) * 1000000000 / CLOCKS_PER_SEC;
#elif TIMER == POSIX
	gettimeofday(&after, NULL);
	result = ((long)after.tv_sec - (long)before.tv_sec) * 1000000000;
	result += (after.tv_usec - before.tv_usec) * 1000;
#elif TIMER == CYCLE
	after = arch_cycles();
	result = (after - before);
#elif TIMER == MACH
    after = mach_absolute_time();
    result = (after - before);
#endif

#if TIMER != NONE
	total += result;
#else
	(void)result;
#endif
}

void bench_compute(int benches) {
#if TIMER == MACH
    uint64_t elapsedTime = 0;
    uint64_t elapsedTimeNano = 0;
    mach_timebase_info_data_t timeBaseInfo;
    mach_timebase_info(&timeBaseInfo);
    
    elapsedTime = total;
    elapsedTimeNano = elapsedTime * timeBaseInfo.numer / timeBaseInfo.denom;
    total = (unsigned long long) (((double) elapsedTimeNano) * 1.3);
#endif
#if TIMER != NONE
	total = total / benches - overhead;
#else
	(void)benches;
#endif
}

void bench_print() {
#if TIMER == CYCLE
	printf("%16lld cycles", total);
#else
	printf("%16lld nanosec", total);
#endif
	if (total < 0) {
		printf(" (bad overhead estimation)\n");
	} else {
		printf("\n");
	}
}

unsigned long long bench_total() {
	return total;
}
