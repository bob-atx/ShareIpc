/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */
/*
 * tms_include.h
 *
 *  Created on: Oct 24, 2015
 *      Author: bob
 */

#ifndef TMS_INCLUDE_H_
#define TMS_INCLUDE_H_

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

// system includes
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <signal.h>
#include <stddef.h>
#include <sys/syscall.h>
#include <pthread.h>
#include <stdint.h>
#include <inttypes.h>
#include <errno.h>
#include <sys/time.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/queue.h>
#include <limits.h>
#include <assert.h>
#include <stdarg.h>
#include <semaphore.h>
#include <sys/mman.h>
#include <sys/file.h>
#include <execinfo.h>
#include <mqueue.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/eventfd.h>
#include <sys/un.h>
#include <sys/wait.h>

#if defined(__FreeBSD__)
# include <sys/param.h>
#endif

#define TmsStructPacked struct __attribute__ ((__packed__))
#define TmsUnionPacked union __attribute__ ((__packed__))
#define TmsEnumPacked enum  __attribute__ ((__packed__))
#define TmsStruct struct
#define TmsUnion union
#define TmsEnum enum
#define TmsBitT uint32_t

#include "shm_tlsf.h"
#include "shm_log.h"
#include "shm_mem.h"
//#include "tms_api.h"

#endif /* TMS_INCLUDE_H_ */
