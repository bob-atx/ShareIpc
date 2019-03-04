/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */


/*
 * tms_mem.h

 *
 *  Created on: Nov 1, 2015
 *      Author: bob
 */


#ifndef TMS_MEM_H_
#define TMS_MEM_H_

#define TMS_USE_NODE_CHECK
#define TMS_USE_ALIGN_CHECK

#define TMS_COOKIE_SIZE 8
typedef struct TmsCookieT {uint8_t byte[TMS_COOKIE_SIZE];} TmsCookieT;

#define TMS_SHM_DIR "/dev/shm"
#define TMS_LOCK_DIR TMS_SHM_DIR
#define TMS_SHM_PREFIX "/tms-"
#define TMS_LOCK_PREFIX "/tms-lock-"
#define TMS_PATH_MAX 127
#define TMS_HASH_SECTIONS_PERCENT 25
#define TMS_DEFAULT_SHM_PERM (S_IRUSR | S_IWUSR | S_IRGRP  | S_IWGRP)
#define TMS_NONBLOCK 0
#define TMS_BLOCK_INDEF (-1)

#define TMS_LOCK_TIMEOUT_SEC 5
#define TMS_OPEN_POLL_MSEC	100
#define TMS_WAITPID_POOL_USEC 10000
#define GET_RAND(min, max) ((rand() % ((max) - (min) + 1)) + (min))

#define DELAY //usleep(GET_RAND(0, 1000));

//https://stackoverflow.com/questions/11317474/macro-to-count-number-of-arguments
#define TMS_ARG_N( \
          _1,  _2,  _3,  _4,  _5,  _6,  _7,  _8,  _9, _10, \
         _11, _12, _13, _14, _15, _16, _17, _18, _19, _20, \
         _21, _22, _23, _24, _25, _26, _27, _28, _29, _30, \
         _31, _32, _33, _34, _35, _36, _37, _38, _39, _40, \
         _41, _42, _43, _44, _45, _46, _47, _48, _49, _50, \
         _51, _52, _53, _54, _55, _56, _57, _58, _59, _60, \
         _61, _62, _63, N, ...) N

/* Note 63 is removed */
#define TMS_RSEQ_N()                                        \
         62, 61, 60,                                       \
         59, 58, 57, 56, 55, 54, 53, 52, 51, 50,           \
         49, 48, 47, 46, 45, 44, 43, 42, 41, 40,           \
         39, 38, 37, 36, 35, 34, 33, 32, 31, 30,           \
         29, 28, 27, 26, 25, 24, 23, 22, 21, 20,           \
         19, 18, 17, 16, 15, 14, 13, 12, 11, 10,           \
          9,  8,  7,  6,  5,  4,  3,  2,  1,  0

#define TMS_NARG_(...) TMS_ARG_N(__VA_ARGS__)

/* Note dummy first argument _ and ##__VA_ARGS__ instead of __VA_ARGS__ */
#define TMS_NARG(...) TMS_NARG_(_, ##__VA_ARGS__, TMS_RSEQ_N())

//#define my_func(...) func(TMS_NARG(__VA_ARGS__), __VA_ARGS__)

//////////////////////////////////////////////////

#define TMS_ALIGN_MASK (~(TMS_MLOCK | TMS_DYNAMIC))

#define TMS_DEFAULT_SIZE(size) \
		TMS_ALIGN_SIZE(size, TMS_ALIGN_DEFAULT)

#define TMS_MEM_NODE_SIZE \
	TMS_ALIGN_SIZE(sizeof(TmsMemT), TMS_ALIGN_DEFAULT)

#define TMS_SHM_NODE_SIZE \
	TMS_ALIGN_SIZE(sizeof(TmsShmT), TMS_ALIGN_DEFAULT)

#define TMS_POOL_NODE_SIZE \
	TMS_ALIGN_SIZE(sizeof(TmsPoolT), TMS_ALIGN_POOL)

#define TMS_LIST_BASE_SIZE \
	TMS_ALIGN_SIZE(sizeof(TmsListBaseT), TMS_ALIGN_POOL)

#define TMS_LIST_CTL_SIZE \
	TMS_ALIGN_SIZE(sizeof(TmsListCtlT), TMS_ALIGN_POOL)

#define TMS_HASH_BASE_SIZE \
	TMS_ALIGN_SIZE(sizeof(TmsHashBaseT), TMS_ALIGN_DEFAULT)

#define TMS_HASH_NODE_SIZE \
	sizeof(TmsHashTableT)

//////////////////////////////////////////////////////

#define TMS_MEM_SIZE_ALIGN(_size, _align, _flags) \
	((_size) + sizeof(TmsGuardT) + TMS_MEM_NODE_SIZE + (_align = TMS_ALIGN_GET(_flags)))

#define TMS_POOL_MEMBER_SIZE(_size, _flags) \
	((_size) + sizeof(TmsGuardT) + TMS_MEM_NODE_SIZE + TMS_ALIGN_GET((_flags) & TMS_ALIGN_MASK))

#define TMS_HASH_HDR_SIZE(_keysize) \
	TMS_ALIGN_SIZE(sizeof(TmsHashHdrT) + _keysize, TMS_ALIGN_DEFAULT)

#define TMS_HASH_LOCK_SIZE(num) \
	(sizeof(TmsHashLockT) * (_hash_lock_mask(num) + 1))

#define TMS_HASH_MEMBER_SIZE(_size, _keysize) \
	(TMS_HASH_HDR_SIZE(_keysize) + _size)

#define TMS_HASH_TABLE_SIZE(_num) ((_num) * TMS_HASH_NODE_SIZE)

///////////////////////////////////////////////////////

#define TMS_RING_ARRAY_SIZE(num) \
	TMS_ALIGN_SIZE((num) * sizeof(TmsRingT), TMS_ALIGN_DEFAULT)

#define TMS_SHM_CREATE_SIZE(_size, _align, _flags) \
	TMS_ALIGN_SIZE((_size) + sizeof(TmsGuardT) \
	+ TMS_SHM_NODE_SIZE \
	+ 2 * sizeof(TmsObjDataT)\
	+ (_align = TMS_ALIGN_GET(_flags)), TMS_ALIGN_PAGE)

#define TMS_TLSF_POOL_INIT_SIZE(_num, _size, _flags) \
	TMS_ALIGN_SIZE(tlsf_pool_malloc_size(_num, TMS_POOL_MEMBER_SIZE(_size, _flags) \
	+ TMS_ALIGN_POOL), TMS_ALIGN_DEFAULT)

#define TMS_TLSF_POOL_CREATE_SIZE(_num, _size, _flags) \
	TMS_ALIGN_SIZE(TMS_TLSF_POOL_INIT_SIZE(_num, _size, _flags) \
	+ TMS_POOL_NODE_SIZE + 2*TMS_ALIGN_POOL \
	+ (flags & TMS_MLOCK ? TMS_ALIGN_PAGE : 0), TMS_ALIGN_DEFAULT)

#define TMS_FIXED_POOL_CREATE_SIZE(_num, _size, _flags) \
	TMS_ALIGN_SIZE((_num) * TMS_POOL_MEMBER_SIZE(_size, _flags)\
	+ TMS_POOL_NODE_SIZE + TMS_ALIGN_POOL \
	+ (flags & TMS_MLOCK ? TMS_ALIGN_PAGE : 0), TMS_ALIGN_DEFAULT)

#define TMS_HEAP_POOL_CREATE_SIZE(_num, _size, _flags) \
	TMS_ALIGN_SIZE(TMS_POOL_NODE_SIZE + TMS_ALIGN_POOL, TMS_ALIGN_DEFAULT)

#define TMS_LINK_POOL_CREATE_SIZE(_num, _size, _flags) 0

///////////////////////////////////////////////

#define UPTR_(x) ((uintptr_t) (x))
#define TMS_ALIGN_PTR(p, a) ((uint8_t *)((UPTR_(p) + UPTR_((a)-1)) & (~UPTR_((a)-1))))
#define TMS_ALIGN_SIZE(s, a)  (((s) + (a) - 1) & (~((a) - 1)))
//also ((((~(_x)) + 1) & ((_v)-1)) + (_x))

#define TMS_ALIGN_DEFAULT (sizeof(void *))
#define TMS_ALIGN_POOL (2*sizeof(void *))
#define TMS_ALIGN_PAGE sysconf(_SC_PAGESIZE)
#define TMS_ALIGN_CACHE sysconf (_SC_LEVEL1_DCACHE_LINESIZE)
#define TMS_ALIGN_HASH sizeof(int)

#define TMS_ALIGN_GET(_flags) \
	(!((_flags) & (TMS_PAGE_ALIGN | TMS_MLOCK | TMS_CACHE_ALIGN | TMS_DYNAMIC)) ? TMS_ALIGN_DEFAULT : \
	(_flags) & (TMS_PAGE_ALIGN | TMS_MLOCK) ? TMS_ALIGN_PAGE : \
	(_flags) & TMS_CACHE_ALIGN ? TMS_ALIGN_CACHE :\
	TMS_ALIGN_POOL)

#if 0
	if (align && talign){
		align = align <= talign ? talign : talign * ((talign + align - 1) / talign);
	}
	try (ALIGN_IS_VALID(align));
#endif

#define TMS_PTR_OFFSET(x, y) ((uint8_t *) (x) - (uint8_t *) (y))
#define TMS_PTR_ADD(x, y) ((uint8_t *) (x) + (y))
#define TMS_PTR_SUB(x, y) ((uint8_t *) (x) - (y))

//#define ALIGN_IS_VALID(x) (!((x) & ((x)-1)) && (x) >= 0)
#define ALIGN_IS_VALID(p, a) (!(UPTR_(p) & ((a)-1)))

#define NAME_IS_VALID(name) ((name) && (strnlen(name, TMS_NAME_MAX+1) <= TMS_NAME_MAX))
#define NAME_IS_INVALID(name) (!NAME_IS_VALID(name))
#define SLASHNAME_IS_VALID(name) (NAME_IS_VALID(name) && *(name) == '/')
#define SLASHNAME_IS_INVALID(name) (!SLASHNAME_IS_VALID(name))

#define TMS_MEM_GUARD  0x12340000
#define TMS_GUARD_MASK 0xffff0000

#ifdef TMS_USE_NODE_CHECK
#define TMS_GUARD_PASS(ptr) \
	try((ptr) && (((ptr)->guard & TMS_GUARD_MASK) == TMS_MEM_GUARD))

#define TMS_NODE_PASS(node) \
	try((node) \
	&& (((node)->guard & TMS_GUARD_MASK) == TMS_MEM_GUARD)\
	&& (*((TmsGuardT *) ((uint8_t *) (node) + (node)->usrSize + TMS_MEM_NODE_SIZE)) == TMS_MEM_GUARD)\
	)
#else
#define TMS_GUARD_PASS(ptr)
#define TMS_NODE_PASS(node)
#endif

#define TMS_OBJ_IS(ptr, x) \
	((ptr)->guard & x)

#define TMS_OBJ_PASS(ptr, x) \
	((ptr) && (((ptr)->guard & (TMS_GUARD_MASK | x)) == (TMS_MEM_GUARD | x)))

#define TMS_LIST_PASS(ptr) \
	((ptr) && TMS_OBJ_PASS((ptr)->base, TMS_OBJ_LIST))

#define TMS_IS_DUPLEX(flags) ((flags) & TMS_DUPLEX ? 2 : 1)

#define TMS_LIST_PRI_MAX 9
#define TMS_POOL_OVERHEAD 120
#define TMS_POOL_SIZE_MIN 65536

#define TMS_RTPRIORITY_MIN 1
#define TMS_RTPRIORITY_LOW 10
#define TMS_RTPRIORITY_MED 20
#define TMS_RTPRIORITY_HIGH 30
#define TMS_RTPRIORITY_MAX 40

#define TMS_MUTEXTIMEOUT_SEC 1
#define TMS_ADD_FETCH_RELAXED(...) __atomic_add_fetch(__VA_ARGS__, __ATOMIC_RELAXED)
#define TMS_SUB_FETCH_RELAXED(...) __atomic_sub_fetch(__VA_ARGS__, __ATOMIC_RELAXED)

#define gettid() syscall(SYS_gettid)
#define tgkill(pid, tid, sig) syscall(SYS_tgkill, pid, tid, sig)

#if 0
int tms_quiet = 0;
#define TMS_QUIET(x) tms_quiet = x
#define TmsRdLock(x) ({if(!quiet)TMS_DEBUG("%s: READ LOCK! %p\n", #x, x); int _rc = pthread_rwlock_rdlock(x); _rc;})
#define TmsWrLock(x) ({if(!quiet)TMS_DEBUG("%s: WRITE LOCK! %p\n", #x, x); int _rc = pthread_rwlock_wrlock(x); _rc;})
#define TmsRdWrUnlock(x) ({if(!quiet)TMS_DEBUG("%s: UNLOCK! %p\n", #x, x); int _rc = pthread_rwlock_unlock(x); _rc;})
#else
#define TMS_QUIET(x)
#define TmsRdLock(x) pthread_rwlock_rdlock(x)
#define TmsWrLock(x) pthread_rwlock_wrlock(x)
#define TmsRdWrUnlock(x) pthread_rwlock_unlock(x)
#endif

/*TMS_DEBUG("WAITING!!!! %s\n", #cond); */\
#define CV_WAIT(cv, mutex, cond, flag, msec) ({\
	int _rc = 0;\
	if (!(cond) && (errno != EINVAL)){\
		errno = 0;\
		if ((msec) == 0){\
			errno = EAGAIN;\
		}\
		else if ((msec) > 0) {\
			struct timespec _ts;\
			error_if (_msec_to_abstime(msec, &_ts, CLOCK_MONOTONIC));\
			flag++;\
			while (!errno && !(cond)){\
				if (errno == EINVAL){\
					break;\
				}\
				error_if ((errno = pthread_cond_timedwait(cv, mutex, &_ts)));\
			}\
			flag--;\
		}\
		else if ((msec) == -1) {\
			flag++;\
			while (!errno && !(cond)){\
				if (errno == EINVAL){\
					break;\
				}\
				error_if ((errno = pthread_cond_wait(cv, mutex)));\
			}\
			flag--;\
		}\
		else {\
			errno = EINVAL;\
			error("invalid msec option.\n");\
		}\
		_rc = errno;\
	}\
	_rc;\
})

////////////////

#define TMS_MOD(x, y) ((x) < (y) ? x : (x) - (y))

#ifdef UNUSED
#elif defined(__GNUC__)
# define UNUSED(x) UNUSED_ ## x __attribute__((unused))
#elif defined(__LCLINT__)
# define UNUSED(x) /*@unused@*/ x
#else
# define UNUSED(x) x
#endif

typedef TmsEnum {
	// first bits for alignment and lists
	TMS_PAGE_ALIGN  = 0x1,
	TMS_CACHE_ALIGN	= 0x2,
	TMS_MLOCK 		= 0x4,
	TMS_NOCOPY		= 0x8,
	TMS_LINK		= 0x10,
	TMS_COPY_OUT	= 0x20,
	TMS_DUPLEX		= 0x40,
	TMS_FIXED		= 0x80,
	TMS_DYNAMIC		= 0x100,
	TMS_HEAP		= 0x200,
	TMS_RING		= 0x400,
	TMS_OPEN_A 		= 0x800,
	TMS_OPEN_B 		= 0x1000,
	TMS_STACK		= 0x2000,
	TMS_NOPOOL		= 0x4000,
	TMS_HASH		= 0x8000,

	// next bytes for other flags
	TMS_RESV2 		= 0x10000,
	TMS_RDONLY 		= 0x20000,
	TMS_WRONLY 		= 0x40000,
	TMS_RDWR 		= 0x80000,
	TMS_RESV3		= 0x100000,
	TMS_SHARED 		= 0x200000,
	TMS_RESV4	 	= 0x400000,
	TMS_RESV5		= 0x800000,
	TMS_RESV6		= 0x1000000,
	TMS_RESV7		= 0x2000000,
	TMS_EXFAIL		= 0x4000000,
	TMS_EXOPEN		= 0x8000000,

	// used for testing
	TMS_THREAD		= 0x10000000,
	TMS_PROC		= 0x20000000
} TmsMemFlagsT;

#define TMS_POOL_DEFAULT TMS_HEAP
#define TMS_SHM_POOL_DEFAULT TMS_FIXED

#define TMS_POOL_FLAGS (TMS_DYNAMIC | TMS_FIXED | TMS_HEAP)
#define TMS_ALIGN_FLAGS (TMS_PAGE_ALIGN | TMS_CACHE_ALIGN | TMS_MLOCK)

#define TMS_LIST_NOCOPY_FLAGS \
		( TMS_OPEN_A \
		| TMS_OPEN_B \
		| TMS_RDONLY \
		| TMS_WRONLY \
		| TMS_PROC \
		| TMS_THREAD)

#define TMS_LIST_OPEN_FLAGS \
		( TMS_OPEN_A \
		| TMS_OPEN_B \
		| TMS_COPY_OUT \
		| TMS_POOL_FLAGS \
		| TMS_ALIGN_FLAGS \
		| TMS_PROC \
		| TMS_THREAD \
		| TMS_RDONLY \
		| TMS_WRONLY)

#define TMS_LIST_CREATE_FLAGS \
		( TMS_POOL_FLAGS \
		| TMS_NOPOOL \
		| TMS_ALIGN_FLAGS \
		| TMS_RING \
		| TMS_SHARED \
		| TMS_EXOPEN \
		| TMS_EXFAIL \
		| TMS_DUPLEX \
		| TMS_NOCOPY \
		| TMS_PROC \
		| TMS_THREAD \
		| TMS_LINK)

#define TMS_HASH_CREATE_FLAGS \
		( TMS_POOL_FLAGS \
		| TMS_SHARED \
		| TMS_EXOPEN \
		| TMS_EXFAIL \
		| TMS_PROC \
		| TMS_THREAD)

#define TMS_LIST_LINK_FLAGS \
		( TMS_SHARED \
		| TMS_DUPLEX \
		| TMS_PROC \
		| TMS_THREAD)

typedef uint32_t TmsGuardT;

typedef TmsEnum {
	TMS_THREAD_NONE				= 0x0,
	TMS_THREAD_FIFO_PRILOW 		= 0x1,
	TMS_THREAD_FIFO_PRIMED 		= 0x2,
	TMS_THREAD_FIFO_PRIHIGH		= 0x4,
	TMS_THREAD_RR_PRILOW 		= 0x8,
	TMS_THREAD_RR_PRIMED 		= 0x10,
	TMS_THREAD_RR_PRIHIGH		= 0x20,
	TMS_THREAD_JOINABLE			= 0x40,
	TMS_THREAD_DETACHED			= 0x80,
	TMS_THREAD_AUTOSTART		= 0x100
} TmsThreadFlagT;

// bit mask!!
typedef TmsEnum {
	TMS_CB_OK	 	= 0x0,
	TMS_CB_EXIT 	= 0x1,
	TMS_CB_FREE 	= 0x2,
	TMS_CB_PUTBACK 	= 0x4,
	TMS_CB_DISCARD  = 0x8,
	TMS_CB_MASK 	= 0xf
} TmsCbActionT;

typedef TmsEnumPacked {
	TMS_OBJ_SHM			= 0x1,
	TMS_OBJ_LIST		= 0x2,
	TMS_OBJ_HASH		= 0x4,
	TMS_OBJ_POOL		= 0x8,
	TMS_OBJ_MLOCK		= 0x10,
	TMS_OBJ_NOCOPY		= 0x20,
	TMS_OBJ_THREAD		= 0x40,
	TMS_OBJ_POOLNODE 	= 0x80,
	TMS_OBJ_LISTNODE	= 0x100,
	TMS_OBJ_HASHNODE	= 0x200
} TmsObjT;

typedef TmsEnum {
	TMS_MEM_NAME,
	TMS_LOCK_NAME
} TmsShmNameT;

typedef TmsEnum {
	TMS_HASH_RMW = 0x1,
	TMS_HASH_NO_INIT = 0x2,
	TMS_HASH_READ = 0x4
} TmsHashFlagT;

typedef TmsStruct {
	pthread_rwlock_t rwlock;
	pthread_mutex_t mutex;
	pthread_cond_t read_cv;
	pthread_cond_t write_cv;
	uint8_t write_is_pending;
	uint8_t read_is_pending;
} TmsListLockT;

typedef TmsStruct TmsLinkT {
	ptrdiff_t  head;
	ptrdiff_t  tail;
	uint32_t cnt;
} TmsLinkT;

typedef TmsStruct {
	pthread_mutex_t mutex;
	pthread_cond_t cv;
	uint8_t is_pending;
} TmsThreadLockT;

typedef TmsStruct TmsThreadT{
	pthread_t pthread;
	TmsThreadLockT lock;
	void *user;
	void *rc;
	void *(*func) (void *);
	void (*cleanup)(void *);
	TmsGuardT guard;
	int flags;
	uint8_t join;
} TmsThreadT;

typedef TmsStruct {
	struct timespec ts;
	ptrdiff_t offset;
	ptrdiff_t next;
	ptrdiff_t prev;
	ptrdiff_t obj;
	pid_t tid;
} TmsObjDataT;

typedef TmsStruct TmsNameRegT{
	TmsLinkT link;
	pthread_mutex_t mutex;
	int cnt;
} TmsNameLinkT;

typedef TmsStruct {
	char name[TMS_PATH_MAX+1];
	int fd;
} TmsFileLockT;

typedef TmsStruct TmsNameInfoT {
	char name[TMS_PATH_MAX+1];
	void *open_base;
	uint32_t hash;
	int len;
	int flags;
	int cnt;
} TmsNameInfoT;

typedef TmsStructPacked {
	TmsGuardT guard;
	size_t usrSize;
	size_t actSize;
	TmsObjDataT data;
} TmsMemT;

typedef TmsStruct {
	TmsGuardT guard;
	pthread_rwlock_t rwlock;
	char name[TMS_PATH_MAX+1];
	size_t usrSize;
	size_t actSize;
	mode_t perm;
	int flags;
	TmsObjDataT data;
} TmsShmT;

typedef TmsStruct {
	unsigned int seq_num;
	int error;
} TmsHashStatusT;

typedef TmsCbActionT (*TmsListCallbackT)(void *data, size_t size, int pri, void *arg, int *rc);
typedef TmsCbActionT (*TmsWalkCallbackT)(void *data, size_t size, void *arg, int *rc);
typedef int (*TmsHashCallbackT)(void *buf, int size, void *arg, TmsHashStatusT *status);

typedef TmsStruct TmsPoolT {
	TmsGuardT guard;
	TmsLinkT alloc_list;
	TmsLinkT free_list;
	pthread_mutex_t mutex;
	pthread_cond_t cv;
	ptrdiff_t offset;
	struct TmsPoolT *self;
	void *start;
	size_t freeSize;
	size_t userSize;
	size_t elem_size;
	size_t total_size;
	size_t block_size;
	int alloc_is_pending;
	int cnt;
	int num_elem;
	int flags;
	int ready;
	int use_destroy;
} TmsPoolT;

typedef TmsLinkT TmsHashTableT;

typedef TmsStruct {
	pthread_rwlock_t rw_lock;
	pthread_rwlock_t del_lock;
	pthread_rwlock_t rmw_lock;
	pthread_mutex_t cv_mutex;
	pthread_cond_t read_cv;
	uint8_t read_is_pending;
} TmsHashLockT;

typedef TmsStructPacked {
	uint32_t seq_num;
	uint32_t full_hash;
	char key[0];
} TmsHashHdrT;

typedef TmsStruct TmsHashBaseT{
	TmsGuardT guard;
	char name[TMS_PATH_MAX+1];
	ptrdiff_t locks;
	ptrdiff_t pool;
	ptrdiff_t table;
	uint32_t hdr_size;
	uint32_t num_elem;
	uint32_t key_size;
	uint32_t elem_size;
	uint32_t align_lock_size;
	uint32_t section_mask;
	uint32_t modulo_mask;
	uint32_t collisions;
	int flags;
	uint8_t use_destroy;
}TmsHashBaseT;

typedef TmsStruct TmsHashT {
	TmsHashBaseT *base;
	TmsHashLockT *locks;
	TmsHashTableT *table;
	TmsPoolT *pool;
	int open_flags;
} TmsHashT;

typedef TmsStruct{
	pthread_mutex_t mutex;
	TmsHashCallbackT cb;
	TmsHashTableT *table;
	TmsHashLockT *lock;
	TmsHashT *hash;
	uint8_t *key;
	void *arg;
	uint32_t full_hash;
	uint32_t seq_num;
	int ksize;
	int flags;
	int msec;
	uint8_t init;
} TmsHashStateT;

typedef TmsStruct TmsListHeaderT {
	TmsListLockT lock;
	int flags;
} TmsListHeaderT;

typedef TmsStruct TmsListPropT {
	size_t write_size;
	size_t read_size;
	int write_num_elem;
	int read_num_elem;
	int write_flags;
	int read_flags;
	int write_alloc_cnt;
	int read_alloc_cnt;
	int write_queue_cnt;
	int read_queue_cnt;
	int write_seq_num;
	int read_seq_num;
	int write_cnt;
	int read_cnt;
}TmsListPropsT;

// replace 64 bit cnt
// with more efficient
// modulo code?
typedef TmsStruct {
	uint64_t add_cnt;
	uint64_t del_cnt;
}TmsRingPubT;

typedef TmsStruct {
	uint64_t cnt;
	uint32_t overrun;
	TmsMemT *last_node;
}TmsRingSubT;

typedef TmsStruct TmsListCtlT {
	TmsListHeaderT header;
	void *self;
	TmsRingPubT ring_pub[TMS_LIST_PRI_MAX+1];
	TmsLinkT pri[TMS_LIST_PRI_MAX+1];
	ptrdiff_t base;
	ptrdiff_t ring_buf;
	ptrdiff_t pool;
	size_t size;
	int ttl_msec;
	uint32_t qcnt;
	uint32_t seq_num;
	uint32_t read_cnt;
	uint32_t write_cnt;
	int num_elem;
	int isPrimed;
	uint8_t ring[0];
} TmsListCtlT;

typedef TmsStruct TmsListBaseT {
	TmsGuardT guard;
	void *self;
	char name[TMS_PATH_MAX+1];
	char linkedto[TMS_PATH_MAX+1];
	ptrdiff_t writeA;
	ptrdiff_t readA;
	ptrdiff_t writeB;
	ptrdiff_t readB;
	size_t size;
	mode_t perm;
	int ttl;
	int pool_elem;
	int flags;
	int ready;
	int use_destroy;
	TmsListCtlT listctl[0];
}TmsListBaseT;

typedef TmsStruct TmsListT{
	TmsRingSubT ring_sub[TMS_LIST_PRI_MAX+1];
	pthread_mutex_t ring_mutex;
	TmsListBaseT *base;
	TmsListBaseT *link;
	TmsListCtlT *write_list;
	TmsPoolT *write_pool;
	TmsPoolT *list_wpool;
	TmsListCtlT *read_list;
	TmsPoolT *read_pool;
	TmsPoolT *list_rpool;
	int open_flags;
	uint32_t seq_num;
	uint32_t write_cnt;
	uint32_t read_cnt;
} TmsListT;

typedef uint8_t TmsRingT;

typedef TmsStruct TmsThreadListArgT{
	void *(*func) (void *, void *);
	TmsListT *list;
	void *arg;
}TmsThreadListArgT;

typedef TmsStruct TmsThreadListT {
	TmsThreadListArgT data;
	TmsThreadT *threads[0];
} TmsThreadListT;

#define FNV1A_32_PRIME 16777619
#define FNV1A_32_INIT 2166136261

int TmsMakeUname(char *buf, int size);

/////////////////////////////////////////////////////////////

void *TmsMalloc (size_t size);
void *TmsMallocFull (TmsPoolT *pool, size_t size, int flags);
void *TmsRealloc (void *in, size_t size);
void *TmsReallocFull (TmsPoolT *pool, void *in, size_t size, int flags);
int TmsFree(void *ptr);

void *TmsPoolMalloc (TmsPoolT *, size_t size);
int TmsPoolCreate (char *name, int num, size_t size, int flags, mode_t perm);
TmsPoolT *TmsPoolOpen (char *name, int msec);
int TmsPoolDestroy (char *name);
TmsPoolT *TmsPoolInit(void *mem, int num_elem, size_t elem_size, int flags);
int TmsPoolWalk(TmsPoolT *pool, TmsWalkCallbackT callback, void *arg);
int TmsPoolClose(TmsPoolT *pool);

int TmsShmCreate (char *name, size_t size, int flags, mode_t perm);
void *TmsShmOpen (char *name, int oflag, int msec);
int TmsShmDestroy (char *name);
int TmsShmClose(void *ptr);

TmsHashStateT *TmsHashStateCreate (TmsHashT *hash, void *key, int ksize, int flags, int msec);
int TmsHashStateCallback(TmsHashStateT *state, TmsHashCallbackT cb, void *arg, int flags);
int TmsHashStateDestroy (TmsHashStateT *state);
size_t TmsHashCreateSize(int num, int size, int keysize, int flags);
TmsHashBaseT *TmsHashInit(void *ptr, int key_size, int num_elem, int elem_size, int flags);
int TmsHashCreate (char *name, int keysize, int num, int size, int flags, mode_t perm);
int TmsHashDestroy (char *name);
TmsHashT *TmsHashOpen (char *name, int flags, int msec);
int TmsHashClose(TmsHashT *hash);
pthread_t *TmsHashThreadCreate (TmsHashStateT *state, int flags, void (*cleanup)(void *));
int TmsHashThreadDestroy(pthread_t *pthread);
int TmsHashRead (TmsHashT *hash, void *key, int ksize, void *vbuf, int vsize, int msec);
int TmsHashWrite (TmsHashT *hash, void *key, int ksize, void *vbuf, int vsize, int msec);
int TmsHashReadWrite (TmsHashT *hash, void *key, int ksize, void *vbuf, int vsize, TmsHashCallbackT cb, void *arg, int msec);
int TmsHashUnlink(TmsHashT *hash, void *key, int ksize);
int TmsHashStateRead (TmsHashStateT *state, void *vbuf, int vsize);
int TmsHashStateWrite (TmsHashStateT *state, void *vbuf, int vsize);
int TmsHashStateReadWrite (TmsHashStateT *state, void *vbuf, int vsize);
int TmsHashStateUnlink(TmsHashStateT *state);
int TmsHashStat (TmsHashT *hash);

int TmsListCreate (char *name, int num_elem, size_t size, int ttl, int flags, mode_t perm);
int TmsListLink (char *link, char *name, int flags, int msec);
TmsListT *TmsListOpen (char *name, int flags, int msec);
void *TmsListAlloc (TmsListT *list, size_t size, int flags);
int TmsListWrite (TmsListT *plist, void *data, size_t size, int priority, int msec);
void *TmsListRead (TmsListT *plist, size_t *size, int *pri, int msec);
int TmsListDestroy (char *name);
int TmsListWalk (TmsListT *plist, TmsListCallbackT callback, void *arg, int flags, int msec);
size_t TmsListSize(int num, size_t size, int flags);
int TmsListProps(TmsListT *list, TmsListPropsT *props);
int TmsListFlush(TmsListT *plist);
int TmsListClose(TmsListT *list);
TmsListBaseT *TmsListInit(void *ptr, int num_elem, size_t size, mode_t perm, int ttl, int flags);

pthread_t *TmsThreadCreate (void *(*func) (void *), TmsThreadFlagT flags, void *arg, void (*cleanup)(void *));
int TmsThreadJoin(pthread_t *pthread, int msec, void **rc);
int TmsThreadDestroy(pthread_t *pthread);

#if 0
int TmsRwRdLock(pthread_rwlock_t *lock);
int TmsRwWrLock(pthread_rwlock_t *lock);
int TmsRwUnlock(pthread_rwlock_t *lock);
int TmsRwLockCreate(pthread_rwlock_t *rwlock, int flags);
int TmsRwLockDestroy(pthread_rwlock_t *rwlock);
int TmsMutexDestroy(pthread_mutex_t *mutex);
int TmsMutexCreate(pthread_mutex_t *mutex, int flags);
int TmsCvDestroy(pthread_cond_t *cv);
int TmsCvCreate(pthread_cond_t *cv, int flags);
int TmsMutexUnlock(pthread_mutex_t *mutex);
int TmsMutexLock(pthread_mutex_t *mutex);
int TmsMutexTimedlock(pthread_mutex_t *mutex, uint32_t msec);
#endif

int TmsWaitPid(pid_t pid, int sig, int secs);
pid_t TmsFork(void *(*func) (void *), void *arg);

int TmsTestNameClean(void);
int bs_shm(void *ptr);

#endif /* TMS_MEM_H_ */
