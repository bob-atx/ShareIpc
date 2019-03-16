/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/*
 * tms_mem.c
 *
 *  Created on: Nov 1, 2015
 *      Author: bob
 */

#include "shareipc.h"
#include "shm_err.h"
#include "shm_mem.h"

//#include "tms_err.h"
//#include "tms_dbg.h"

#include "shm_tlsf.c"
#include "shm_log.c"
#include "shm_dbg.c"

#define TMS_LOCK_DEBUG(...)  //TMS_DEBUG(__VA_ARGS__)

#ifndef __GNUC__
#define __GNUC__
#endif

#define NAME_OBJ_HEAP 0
#define NAME_OBJ_SHM  1

static pthread_mutex_t _fork_lock = PTHREAD_MUTEX_INITIALIZER;
static TmsNameLinkT _name_link = {.mutex = PTHREAD_MUTEX_INITIALIZER};
static __thread pid_t _tid;
static int _thread_cnt;

#define B2(n) n,     n+1,     n+1,     n+2
#define B4(n) B2(n), B2(n+1), B2(n+1), B2(n+2)
#define B6(n) B4(n), B4(n+1), B4(n+1), B4(n+2)
static uint8_t _bit_count(int v)
{
	static uint8_t _bit_table[256] = {B6(0), B6(1), B6(1), B6(2)};
	return _bit_table[v & 0xff] + _bit_table[(v >> 8) & 0xff] +
		_bit_table[(v >> 16) & 0xff] + _bit_table[v >> 24];
}

#if 0
static uint _power2_floor(uint x) {
    int power = 1;
    while (x >>= 1) power <<= 1;
    return power;
}
#endif

#if 1
static uint _power2_ceil(uint x) {
    if (x <= 1) return 1;
    int power = 2;
    x--;
    while (x >>= 1) power <<= 1;
    return power;
}
#endif

static uint32_t _hash(char *buf)
{
	uint32_t hval = FNV1A_32_INIT;
	while (*buf) {
		hval = (hval ^ *buf++) * FNV1A_32_PRIME;
	}
	return hval;
}

static int _msec_is_elapsed(struct timespec *start, uint32_t msec)
{
	struct timespec stop;
	uint32_t tmp;

	try(start);
	try (!clock_gettime(CLOCK_MONOTONIC, &stop));

	if (start->tv_nsec > stop.tv_nsec){
		tmp = (stop.tv_sec - start->tv_sec - 1) * 1000;
		tmp += (start->tv_nsec - stop.tv_nsec) / 1000000;
	}
	else{
		tmp = (stop.tv_sec - start->tv_sec) * 1000;
		tmp += (stop.tv_nsec - start->tv_nsec) / 1000000;
	}
	return (tmp >= msec) ? 1 : 0;

	catch:
	return -1;
}

static int _msec_to_abstime(int msec, struct timespec *ts, clockid_t clock)
{
	time_t sec;
	long nsec;

	try(ts);
	try (!clock_gettime(clock, ts));

	sec = msec / 1000;
	ts->tv_sec += sec;

	nsec = (msec - sec * 1000) * 1000000;
	ts->tv_nsec += nsec;

	if (ts->tv_nsec >= 1000000000){
		ts->tv_nsec -= 1000000000;
		ts->tv_sec++;
	}
	return 0;

	catch:
	return -1;
}

static uint32_t _get_rand(uint32_t min, uint32_t max)
{
    assert(min <= max);
    return (rand() % (max - min + 1)) + min;
}

static int _rwlock_create(pthread_rwlock_t *rwlock, int flags)
{
	pthread_rwlockattr_t rw_attr;
	CatchAndRelease;

	try_set (CREATE1, !pthread_rwlockattr_init(&rw_attr));
	if (flags & TMS_SHARED){
		try (!pthread_rwlockattr_setpshared(&rw_attr, PTHREAD_PROCESS_SHARED));
	}
	try_set (CREATE2, !pthread_rwlock_init(rwlock, &rw_attr));
	try (!pthread_rwlockattr_destroy(&rw_attr));
	return 0;

	catch:
	release (CREATE1, pthread_rwlockattr_destroy(&rw_attr));
	release (CREATE2, pthread_rwlock_destroy(rwlock));
	return -1;
}

static int _rwlock_destroy(pthread_rwlock_t *rwlock)
{
	try(rwlock);
	try (!pthread_rwlock_destroy(rwlock));
	return 0;

	catch:
	return -1;
}

static int _mutex_destroy(pthread_mutex_t *mutex)
{
	try (mutex);
	try (!pthread_mutex_destroy(mutex));
	return 0;

	catch:
	return -1;
}

static int _mutex_create(pthread_mutex_t *mutex, int flags)
{
	pthread_mutexattr_t attr;
	CatchAndRelease;

	try_set (CREATE1, !pthread_mutexattr_init(&attr));

	if (flags & TMS_SHARED){
		try (!pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED));
	}

	// TBD need repair algorithms
#ifdef TMS_USE_ROBUST_LOCK
	try (!pthread_mutexattr_setrobust(&attr,  PTHREAD_MUTEX_ROBUST));
#endif

	//  TBD kills performance!
	//try (!pthread_mutexattr_setprotocol(&attr, PTHREAD_PRIO_INHERIT));

	try_set (CREATE2, !pthread_mutex_init(mutex, &attr));
	try_clr (CREATE1, !pthread_mutexattr_destroy(&attr));
	return 0;

	catch:
	release (CREATE1, pthread_mutexattr_destroy(&attr));
	release (CREATE2, pthread_mutex_destroy(mutex));
	return -1;
}

static int _cv_destroy(pthread_cond_t *cv)
{
	try(cv);
	try (!pthread_cond_destroy(cv));
	return 0;

	catch:
	return -1;
}

static int _cv_create(pthread_cond_t *cv, int flags)
{
	pthread_condattr_t cv_attr;
	CatchAndRelease;

	try_set (CREATE1, !pthread_condattr_init(&cv_attr));
	if (flags & TMS_SHARED){
		try (!pthread_condattr_setpshared(&cv_attr, PTHREAD_PROCESS_SHARED));
	}
	try (!pthread_condattr_setclock(&cv_attr, CLOCK_MONOTONIC));
	try_set (CREATE2, !pthread_cond_init(cv, &cv_attr));
	try_clr (CREATE1, !pthread_condattr_destroy(&cv_attr));
	return 0;

	catch:
	release (CREATE1, pthread_condattr_destroy(&cv_attr));
	release (CREATE2, pthread_cond_destroy(cv));
	return -1;
}

static int _hash_lock_create(TmsHashLockT *lock, int flags)
{
	CatchAndRelease;
	lock->read_is_pending = 0;
	try_set(CREATE1, !_rwlock_create(&lock->rw_lock, flags));
	try_set(CREATE2, !_cv_create(&lock->read_cv, flags));
	try_set(CREATE3, !_mutex_create(&lock->cv_mutex, flags));
	try_set(CREATE4, !_rwlock_create(&lock->del_lock, flags));
	try_set(ALLOC1, !_rwlock_create(&lock->rmw_lock, flags));
	return 0;

	catch:
	release(ALLOC1, _rwlock_destroy(&lock->rmw_lock));
	release(CREATE4, _rwlock_destroy(&lock->del_lock));
	release(CREATE3, _mutex_destroy(&lock->cv_mutex));
	release(CREATE2, _cv_destroy(&lock->read_cv));
	release(CREATE1, _rwlock_destroy(&lock->rw_lock));
	TMS_ASSERT(0);
	return -1;
}

static int _hash_lock_destroy(TmsHashLockT *lock)
{
	lock->read_is_pending = 0;
	_rwlock_destroy(&lock->rw_lock);
	_rwlock_destroy(&lock->del_lock);
	_rwlock_destroy(&lock->rmw_lock);
	_cv_destroy(&lock->read_cv);
	_mutex_destroy(&lock->cv_mutex);
	return 0;
}

static int _list_lock_create(TmsListLockT *lock, int flags)
{
	CatchAndRelease;

	lock->write_is_pending = 0;
	lock->read_is_pending = 0;
	if (flags & TMS_RING){
		try_set(CREATE1, !_rwlock_create(&lock->rwlock, flags));
	}
	else{
		try_set(CREATE2, !_cv_create(&lock->write_cv, flags));
	}
	try_set(CREATE3, !_cv_create(&lock->read_cv, flags));
	try_set(CREATE4, !_mutex_create(&lock->mutex, flags));
	return 0;

	catch:
	release(CREATE1, _rwlock_destroy(&lock->rwlock));
	release(CREATE2, _cv_destroy(&lock->write_cv));
	release(CREATE3, _cv_destroy(&lock->read_cv));
	release(CREATE4, _mutex_destroy(&lock->mutex));
	TMS_ASSERT(0);
	return -1;
}

static int _list_lock_destroy(TmsListLockT *lock, int flags)
{
	lock->write_is_pending = 0;
	lock->read_is_pending = 0;
	if ((flags & TMS_RING) || (flags & TMS_HASH)){
		_rwlock_destroy(&lock->rwlock);
	}
	else{
		_cv_destroy(&lock->write_cv);
	}
	_cv_destroy(&lock->read_cv);
	_mutex_destroy(&lock->mutex);
	return 0;
}

#define _robust_lock(mutex, repair) \
({\
	static int _r = pthread_mutex_lock(mutex);\
	if (_r == EOWNERDEAD){\
		repair\
		_r = pthread_mutex_consistent(mutex);\
	}\
	_r;\
})

#define _mutex_lock(mutex) \
	TMS_LOCK_DEBUG("try mutex lock\n"); pthread_mutex_lock(mutex); TMS_LOCK_DEBUG("lock mutex %s\n", #mutex);

#define _mutex_unlock(mutex) \
	pthread_mutex_unlock(mutex); TMS_LOCK_DEBUG("unlock mutex %s\n", #mutex);

#define _mutex_set(tag, mutex) \
	tms_set(tag, _mutex_lock(mutex))

#define _mutex_clr(tag, mutex) \
	tms_clr(tag, _mutex_unlock(mutex))

#define _mutex_clr_if_set(tag, mutex) \
	if (tms_is_set(tag)) {tms_clr(tag, _mutex_unlock(mutex));}

#define _release_mutex(tag, mutex)\
	release(tag, _mutex_unlock(mutex));

#define _rwlock_wrlock(mutex) \
	TMS_LOCK_DEBUG("try wrlock\n"); pthread_rwlock_wrlock(mutex); TMS_LOCK_DEBUG("lock wrlock %s\n", #mutex);

#define _rwlock_rdlock(mutex) \
	TMS_LOCK_DEBUG("try rdlock\n"); pthread_rwlock_rdlock(mutex); TMS_LOCK_DEBUG("lock rdlock %s\n", #mutex);

#define _rwlock_unlock(mutex)\
	pthread_rwlock_unlock(mutex); TMS_LOCK_DEBUG("unlock rwlock %s\n", #mutex);

#define _wrlock_set(tag, mutex) \
	tms_set(tag, _rwlock_wrlock(mutex))

#define _rdlock_set(tag, mutex) \
	tms_set(tag, _rwlock_rdlock(mutex))

#define _rwlock_clr(tag, mutex) \
	tms_clr(tag, _rwlock_unlock(mutex))

#define _rwlock_clr_if_set(tag, mutex) \
	if (tms_is_set(tag)) {tms_clr(tag, _rwlock_unlock(mutex));}

#define _release_rwlock(tag, mutex)\
	release(tag, _rwlock_unlock(mutex));

#define _error_log_off() \
		{errno = 0;\
		_tmslog.error_enable = 0;}

#define _error_log_on() \
	{errno = 0;\
	_tmslog.error_enable = 1;}

#if 0
static int _mutex_timedlock(pthread_mutex_t *mutex, int msec)
{
	struct timespec ts;

	if (!msec){
		return pthread_mutex_trylock(mutex);
	}
	else if (msec == -1) {
		return pthread_mutex_lock(mutex);
	}
	try (!_msec_to_abstime(msec, &ts, CLOCK_MONOTONIC));
	return pthread_mutex_timedlock(mutex, &ts);

	catch:
	return -1;
}
#endif

static int _mem_lock(void *ptr, int size, uint8_t flag)
{
	int i;
	char *buf = (char *) ptr;

	try (!mlock(ptr, size));
	if (flag){
		for (i=0; i<size; i += TMS_ALIGN_PAGE) {
			buf[i] = 0;
		}
	}
	return 0;

	catch:
	return -1;
}
#if 0
int TmsRwLockCreate(pthread_rwlock_t *rwlock, int flags){
	return _rwlock_create(rwlock, flags);
}

int TmsRwLockDestroy(pthread_rwlock_t *rwlock){
	return _rwlock_destroy(rwlock);
}

int TmsMutexDestroy(pthread_mutex_t *mutex){
	return _mutex_destroy(mutex);
}

int TmsMutexCreate(pthread_mutex_t *mutex, int flags){
	return _mutex_create(mutex, flags);
}

int TmsCvDestroy(pthread_cond_t *cv){
	return _cv_destroy(cv);
}

int TmsCvCreate(pthread_cond_t *cv, int flags){
	return _cv_create(cv, flags);
}

int TmsMutexUnlock(pthread_mutex_t *mutex){
	return _mutex_unlock(mutex);
}

int TmsMutexLock(pthread_mutex_t *mutex){
	return _mutex_lock(mutex);
}

int TmsRwRdLock(pthread_rwlock_t *lock){
	return _rwlock_rdlock(lock);
}

int TmsRwWrLock(pthread_rwlock_t *lock){
	return _rwlock_wrlock(lock);
}

int TmsRwUnlock(pthread_rwlock_t *lock){
	return _rwlock_unlock(lock);
}

int TmsMutexTimedlock(pthread_mutex_t *mutex, uint32_t msec){
	return _mutex_timedlock(mutex, msec);
}
#endif

static void _name_lock(void)
{
	_mutex_lock(&_fork_lock);
	_mutex_lock(&_name_link.mutex);
}

static void _name_unlock(void)
{
	_mutex_unlock(&_name_link.mutex);
	_mutex_unlock(&_fork_lock);
}

// for shared memory names
static int _shm_make_name(char *buf, char *in, TmsShmNameT type)
{
	#define mem_len (sizeof(TMS_SHM_PREFIX)-1)
	#define lock_len (sizeof(TMS_SHM_DIR)+sizeof(TMS_LOCK_PREFIX)-2)
	int in_len, tot_len;

	try (in && buf);
	if (*in == '/'){
		in++;
	}
	in_len = strnlen(in, TMS_PATH_MAX+1);

	switch(type) {
	case TMS_MEM_NAME:
		try ((tot_len = mem_len + in_len) <= TMS_PATH_MAX);
		memcpy(buf, TMS_SHM_PREFIX, mem_len);
		memcpy(&buf[mem_len], in, in_len + 1);
		break;
	case TMS_LOCK_NAME:
		try ((tot_len = lock_len + in_len) <= TMS_PATH_MAX);
		memcpy(buf, TMS_SHM_DIR TMS_LOCK_PREFIX, lock_len);
		memcpy(&buf[lock_len], in, in_len + 1);
		break;
	default:
		throw(EINVAL, "unknown name type %d\n", type);
		break;
	}
	return tot_len;

	catch:
	return 0;
	#undef mem_len
	#undef lock_len
}

int TmsMakeUname(char *buf, int size)
{
	srand(time(NULL));
	snprintf(buf, size, "%04x%04x%04x%04x", _get_rand(0,0xffff), _get_rand(0,0xffff), _get_rand(0,0xffff), _get_rand(0,0xffff));
	return 0;
}

static void _link_head(void *base, TmsObjDataT *data, TmsLinkT *link)
{
	TmsMemT *old_head;

	tms_dbg("link obj 0x%zx to head\n", data->obj);

	if (!link->head){
		tms_dbg("empty list\n");
		data->next = 0;
		link->head = data->obj;
		link->tail = data->obj;
	}
	else {
		tms_dbg("cur head node obj: 0x%zx\n", link->head);
		old_head = (TmsMemT *) ((uint8_t *) base + link->head);
		old_head->data.prev = data->obj;
		data->next = link->head;
		link->head = data->obj;
	}
	data->prev = 0;
	link->cnt++;
	tms_dbg("new head node obj: 0x%zx\n", link->head);
	tms_dbg("next: 0x%zx\n", data->next);
	tms_dbg("cnt: %d\n", link->cnt);
}

static TmsMemT *_unlink_head(void *base, TmsLinkT *link)
{
	TmsMemT *old_head = NULL, *new_head = NULL;

	//TMS_DEBUG("link %p, cnt in: %d\n", link->self, link->cnt);
	if (link->head){

		old_head = (TmsMemT *) ((uint8_t *) base + link->head);

		//TMS_DEBUG("return head node obj: 0x%zx\n", link->head);

		// if we have more than one on the list, the next element is the new head
		if (old_head->data.next){
			new_head = (TmsMemT *) ((uint8_t *) base + old_head->data.next);
			new_head->data.prev = 0;
			//TMS_DEBUG("new head node obj: 0x%zx\n", old_head->data.next);
		}

		// otherwise we now have an empty list with no tail
		else{
			//TMS_DEBUG("list is now empty\n");
			link->tail = 0;
		}

		// our new head (could be zero if we dequeued last element)
		link->head = old_head->data.next;
		link->cnt--;
	}
	//else{
		//TMS_DEBUG("list is empty, return 0\n");
	//}

	//TMS_DEBUG("cnt out: %d, head 0x%zx, tail 0x%zx\n", link->cnt, link->head, link->tail);
	return old_head;
}

static void _link_tail(void *base, TmsObjDataT *data, TmsLinkT *link)
{
	TmsMemT *old_tail;

	//TMS_DEBUG("link %p, cnt %d, obj 0x%zx to tail\n", link->self, link->cnt, data->obj);

	// do we have an empty list?
	if (!link->tail){
		//TMS_DEBUG("list is empty\n");
		data->prev = 0;
		link->head = data->obj;
		link->tail = data->obj;
	}
	else {
		old_tail = (TmsMemT *) ((uint8_t *) base + link->tail);
		old_tail->data.next = data->obj;
		data->prev = link->tail;
		link->tail = data->obj;
	}
	data->next = 0;
	link->cnt++;

	//TMS_DEBUG("cnt: %d, head: 0x%zx, tail 0x%zx\n", link->cnt, link->head, link->tail);
}

#if 0
static TmsMemT *_unlink_tail(void *base, TmsLinkT *link)
{
	TmsMemT *old_tail, *new_tail;

	if (!link->tail){
		return NULL;
	}

	old_tail = (TmsMemT *) ((uint8_t *) base + link->tail);
	if (old_tail->data.prev){
		new_tail = (TmsMemT *) ((uint8_t *) base + old_tail->data.prev);
		new_tail->data.next = 0;
	}
	else{
		link->head = 0;
	}

	link->tail = old_tail->data.prev;
	link->cnt--;
	return old_tail;
}
#endif

static void _unlink_node(void *base, TmsObjDataT *data, TmsLinkT *link)
{
	TmsMemT *prev, *next;

	//TMS_DEBUG("link %p, unlink obj 0x%zx\n", link->self, data->obj);

	// unlink if node is head of list
	if (!data->prev){
		tms_dbg("node is head\n");
		link->head = data->next;
		tms_dbg("new head: 0x%zx\n", link->head);
		if (data->next){
			next = (TmsMemT *) ((uint8_t *) base + data->next);
			next->data.prev = 0;
		}
		else{
			link->tail = 0;
		}
	}

	// unlink if tail of list
	else if (!data->next){
		tms_dbg("node is tail\n");
		link->tail = data->prev;
		tms_dbg("new tail: 0x%zx\n", link->tail);
		prev = (TmsMemT *) ((uint8_t *) base + data->prev);
		prev->data.next = 0;
	}

	// unlink if in middle of list
	else{
		prev = (TmsMemT *) ((uint8_t *) base + data->prev);
		prev->data.next = data->next;
		next = (TmsMemT *) ((uint8_t *) base + data->next);
		next->data.prev = data->prev;
		tms_dbg("node is between 0x%zx and 0x%zx\n", prev->data.obj, next->data.obj);
	}
	link->cnt--;
	tms_dbg("cnt: %d, head 0x%zx, tail 0x%zx\n", link->cnt, link->head, link->tail);
}

static int _tms_free(TmsPoolT *pool, TmsMemT *node, int pool_lock)
{
	CatchAndRelease;
	ptrdiff_t offset;
	void *ptr;
	size_t usrSize;

	TMS_NODE_PASS(node);

	usrSize = node->usrSize;

	if (TMS_OBJ_IS(node, TMS_OBJ_MLOCK)){
		ptr = (uint8_t *) node + TMS_MEM_NODE_SIZE;
		try (!munlock(ptr, node->usrSize));
	}

	// are we a conventional malloc?
	if (!pool){

		tms_dbg("free conventional\n");

		// point to the data we need to free
		ptr = ((uint8_t *) node - node->data.offset);

		// invalidate the node
		node->guard = ~TMS_MEM_GUARD;

		// conventional free
		free(ptr);
	}

	// we are a pool malloc
	else {

		//TMS_DEBUG("free pool %p, XXXX node 0x%zx, act size %zd\n", pool->self, node->data.obj, node->actSize);

		TMS_GUARD_PASS(pool);

		// point to the data we need to free
		ptr = ((uint8_t *) node - node->data.offset);

		// lock the pool
		if (pool_lock){
			_mutex_set(LOCK1, &pool->mutex);
		}

		// unlink from pool alloc list
		_unlink_node(pool, &node->data, &pool->alloc_list);

		// invalidate the node
		node->guard = ~TMS_MEM_GUARD;

		// we are a free list pool malloc
		if (pool->flags & TMS_FIXED){

			tms_dbg("free fixed\n");

			// reset this to point to our pool
			node->data.obj = (uint8_t *) node - (uint8_t *) pool;

			// link back to free list
			_link_head(pool, &node->data, &pool->free_list);
		}

		// we are a tlsf malloc
		else if (pool->flags & TMS_DYNAMIC){

			tms_dbg("free dynamic\n");

			// compute shm offset
			offset = (uint8_t *) pool - (uint8_t *) pool->self;

			// tlsf free
			offset_free_ex(ptr, pool->start, offset);
		}

		// heap malloc
		else if (pool->flags & TMS_HEAP){

			tms_dbg("free heap\n");

			// free the data
			free(ptr);
		}

		else{
			throw (EINVAL, "unknown pool type.\n");
		}

		// add this back in to free size
		pool->freeSize += usrSize;

		// one less allocated block
		pool->cnt--;

		tms_dbg("pool cnt: %d\n", pool->cnt);

		// signal that we just free'd up some mem
		if (pool->alloc_is_pending){
			pthread_cond_broadcast(&pool->cv);
		}

		// unlock the pool
		if (pool_lock){
			_mutex_clr(LOCK1, &pool->mutex);
		}
	}
	return 0;

	catch:
	_release_mutex(LOCK1, &pool->mutex);
	return -1;
}

static void *_tms_malloc (TmsPoolT *pool, size_t size, int flags, uint8_t lock)
{
	int align;
	TmsMemT *mem, *base;
	uint8_t *ptr = NULL;
	size_t sizeIn = size;
	ptrdiff_t offset;
	CatchAndRelease;

	tms_dbg("%s:%d\n", _func, _lineno);

	try(size);

	if (pool){

		// validate the pool
		try (TMS_OBJ_IS(pool, TMS_OBJ_POOL));

		// save our thread id, used for reaping
		// left over mem from dead thread/process
		if (!_tid){
			_tid = getpid();
		}

		// we use the flags when pool created
		flags = pool->flags;

		// lock the pool
		if (lock){
			_mutex_set(LOCK1, &pool->mutex);
		}

		//TMS_DEBUG("pool %p, cnt %d/%d, free %zd/%zd\n",
			//	pool->self, pool->cnt, pool->num_elem, pool->freeSize, sizeIn);

		// have we reached alloc limit?
		if (pool->cnt >= pool->num_elem){
			//TMS_DEBUG("NO ELEM %d %d\n", pool->cnt, pool->num_elem);
			errno = ENOMEM;
			goto catch;
		}

		// have we reached alloc limit?
		else if (pool->freeSize < sizeIn){
			//TMS_DEBUG("NO SIZE %zd %zd\n", pool->freeSize, sizeIn);
			errno = ENOMEM;
			goto catch;
		}

		// alloc from free list pool (fast path)
		if (pool->flags & TMS_FIXED){

			tms_dbg("fixed pool malloc\n");

			// make sure we don't exceed size
			try (size <= pool->elem_size);

			// we can lock the entire pool but not individual elements
			flags &= TMS_ALIGN_MASK;

			// unlink the list head - should always succeed
			try (base = _unlink_head(pool, &pool->free_list));

			// block size
			size = pool->block_size;

			// our usr data
			ptr = (uint8_t *) base + TMS_MEM_NODE_SIZE;
		}

		// tlsf pool
		else if (pool->flags & TMS_DYNAMIC){

			tms_dbg("dynamic pool malloc\n");

			// we can lock the entire pool but not individual elements
			flags &= TMS_ALIGN_MASK;

			// real size we need to malloc
			size = TMS_MEM_SIZE_ALIGN(sizeIn, align, flags);

			// offset due to shm
			offset = (uint8_t *) pool - (uint8_t *) pool->self;

			// try to alloc
			if (!(base = (TmsMemT *)offset_malloc_ex(size, pool->start, offset))){
				//TMS_DEBUG("pool %p, NO MEM\n", pool->self);
				errno = ENOMEM;
				goto catch;
			}

			// where user data section begins after alignment
			ptr = TMS_ALIGN_PTR((uint8_t *) base + TMS_MEM_NODE_SIZE, align);
		}

		// simple heap pool
		else if (pool->flags & TMS_HEAP){

			tms_dbg("heap pool malloc\n");

			// real size we need to malloc
			size = TMS_MEM_SIZE_ALIGN(size, align, flags);

			// malloc the mem
			catch_if (!(base = (TmsMemT *) malloc(size)));

			// where user data section begins after alignment
			ptr = TMS_ALIGN_PTR((uint8_t *) base + TMS_MEM_NODE_SIZE, align);

			// lock the user section as needed
			if (flags & TMS_MLOCK){
				tms_dbg("using mlock\n");
				try (!_mem_lock(ptr, sizeIn, 1));
			}
		}
		else{
			throw (EINVAL, "unknown pool type.\n");
		}

		// adjust our control block to lie just below aligned data
		mem = (TmsMemT *) (ptr - TMS_MEM_NODE_SIZE);

		// clear our metadata
		memset(mem, 0, TMS_MEM_NODE_SIZE);

		// our distance from pool to node
		mem->data.obj = (uint8_t *) mem - (uint8_t *) pool;

		// our obj type
		mem->guard = TMS_OBJ_POOLNODE;

		// add to our alloc list
		_link_tail(pool, &mem->data, &pool->alloc_list);

		// increment the cnt
		pool->cnt++;

		// decrement the free size
		pool->freeSize -= sizeIn;

		tms_dbg("pool malloc cnt: %d\n", pool->cnt);

		// unlock the pool
		if (lock) {
			_mutex_clr(LOCK1, &pool->mutex);
		}
		//TMS_DEBUG("malloc pool %p, XXXX node 0x%zx, act size %zd\n", pool->self, mem->data.obj, size);
	}

	// we have conventional malloc, no pool
	else{
		tms_dbg("conventional malloc\n");

		tms_dbg("req size: %zd\n", size);

		size = TMS_MEM_SIZE_ALIGN(size, align, flags);

		tms_dbg("act size: %zd\n", size);

		catch_if (!(base = (TmsMemT *) malloc(size)));

		// where user data section begins after alignment
		ptr = TMS_ALIGN_PTR((uint8_t *) base + TMS_MEM_NODE_SIZE, align);

		// lock the section as needed
		if (flags & TMS_MLOCK){
			tms_dbg("using mlock\n");
			try (!_mem_lock(ptr, sizeIn, 1));
		}

		// adjust our control block to lie just below aligned data
		mem = (TmsMemT *) (ptr - TMS_MEM_NODE_SIZE);

		// clear our metadata
		memset(mem, 0, TMS_MEM_NODE_SIZE);

		tms_dbg("node start: %zd\n", (uint8_t *) mem - (uint8_t *) base);
		tms_dbg("usr start: %zd\n", (uint8_t *) ptr - (uint8_t *) base);
	}

#ifdef TMS_USE_ALIGN_CHECK
	try (ALIGN_IS_VALID(ptr, TMS_ALIGN_GET(flags)));
#endif

	// fill in rest of meta data
	mem->guard |= TMS_MEM_GUARD;
	mem->usrSize = sizeIn;
	mem->actSize = size;
	mem->guard |= flags & TMS_MLOCK ? TMS_OBJ_MLOCK : 0;

	// save distance between node and start of physical mem for free
	mem->data.offset = (uint8_t *) mem - (uint8_t *) base;
	mem->data.tid = _tid;

	// memory guard
	*((TmsGuardT *) (ptr + sizeIn)) = TMS_MEM_GUARD;

	tms_dbg("node size: %zd\n", TMS_MEM_NODE_SIZE);
	tms_dbg("align: %zd\n", TMS_ALIGN_GET(flags));
	tms_dbg("size: %zd/%zd\n", sizeIn, size);
	tms_dbg("base: %p/%p\n", base, (uint8_t *) base + size - 1);
	tms_dbg("align ptr: %p/%p\n", ptr, ptr + sizeIn - 1);
	tms_dbg("node: %p\n", mem);
	//TMS_DEBUG("malloc obj: 0x%zx, next 0x%zx, prev 0x%zx\n",
		//	mem->data.obj, mem->data.next, mem->data.prev);

	return (void *) ptr;

	catch:
	_release_mutex (LOCK1, &pool->mutex);
	return NULL;
}

void *TmsMalloc (size_t size)
{
	return _tms_malloc(NULL, size, 0, 0);
}

void *TmsMallocFull (TmsPoolT *pool, size_t size, int flags)
{
	return _tms_malloc(pool, size, flags, 0);
}

static void *_tms_realloc (TmsPoolT *pool, void *in, size_t size, int flags)
{
	TmsPoolT *tpool = NULL;
	TmsMemT *mem;
	void *ptr = NULL;

	try (in || size);

	if (in){
		mem = (TmsMemT *) ((uint8_t *) in - TMS_MEM_NODE_SIZE);
		TMS_NODE_PASS(mem);
		try (!TMS_OBJ_IS(mem, TMS_OBJ_LISTNODE));

		if (TMS_OBJ_IS(mem, TMS_OBJ_POOLNODE)){
			tpool = (TmsPoolT *) ((uint8_t *) mem - mem->data.obj);
			TMS_GUARD_PASS(tpool);
		}

		if (size){
			if (pool){
				TMS_GUARD_PASS(pool);
				try (ptr = _tms_malloc(pool, size, flags, 1));
			}
			else{
				try (ptr = _tms_malloc(tpool, size, flags, 1));
			}
			memcpy(ptr, in, size);
			try (!_tms_free(tpool, mem, 1));
		}
	}
	else {
		try (ptr = _tms_malloc(pool, size, flags, 1));
	}
	return ptr;

	catch:
	return NULL;
}

void *TmsReallocFull (TmsPoolT *pool, void *in, size_t size, int flags)
{
	return _tms_realloc(pool, in, size, flags);
}

void *TmsRealloc (void *in, size_t size)
{
	return _tms_realloc(NULL, in, size, 0);
}

// https://stackoverflow.com/questions/17708885/flock-removing-locked-file-without-race-condition
static TmsFileLockT *_file_lock (char *name)
{
	CatchAndRelease;
	int i;
	struct stat st0;
	TmsFileLockT *lock = NULL;
	mode_t mode = TMS_DEFAULT_SHM_PERM;

	// reserve this name
	_name_lock();

	// make the lock dir if it doesn't exist
	if (mkdir(TMS_LOCK_DIR, 0777)){
		try (errno == EEXIST);
	}
	else {
		try (!chmod(TMS_LOCK_DIR, 0777));
	}

	// alloc a struct for the result
	try_set (ALLOC1, lock = _tms_malloc(NULL, sizeof(TmsFileLockT), 0, 1));

	// full path to lock file
	try (_shm_make_name(lock->name, name, TMS_LOCK_NAME));

	// try to get lock for a few secs
	for(i=0; i<TMS_LOCK_TIMEOUT_SEC; i++) {

		// try to open
		try_set (OPEN1, (lock->fd = open(lock->name, O_CREAT, mode)) != -1);

		// if we are unable to lock, close file and retry
		if (flock(lock->fd, LOCK_EX | LOCK_NB)) {
			close(lock->fd);
			sleep(1);
			continue;
		}

		// we are locked
		release_set(LOCK1);

		// get the file stats
		try (!fstat(lock->fd, &st0));

		// does the file still physically exist?
		// if so, we can return
		if(st0.st_nlink != 0) {
			errno = 0;
			return lock;
		}

		// file was deleted after we obtained lock
		// try again
		close(lock->fd);
	}

catch:
	release (ALLOC1, TmsFree(lock));
	release (OPEN1, close(lock->fd));
	release (LOCK1, flock(lock->fd, LOCK_UN));
	_name_unlock();
	return NULL;
}

// release a file lock
static int _file_unlock(TmsFileLockT *lock)
{
	try (lock);
	try (!unlink(lock->name));
	try (!flock(lock->fd, LOCK_UN));
	try (!close(lock->fd));
	try (!TmsFree(lock));
	_name_unlock();
	return 0;

	catch:
	_name_unlock();
	return -1;
}

// close an existing shared memory object, must exist
static int _shm_close(void *ptr)
{
	TmsShmT *shm;
	TmsObjDataT *data;
	size_t size;

	// is ptr valid?
	try (ptr > (void *) TMS_SHM_NODE_SIZE);

	// find where our mid node starts
	data = (TmsObjDataT *) ((uint8_t *) ptr - sizeof(TmsObjDataT));

	// find where our base node starts
	shm = (TmsShmT *)((uint8_t *) ptr - data->offset);

	// make sure node is valid
	try (TMS_OBJ_PASS(shm, TMS_OBJ_SHM));

	// our section size
	size = shm->actSize;

	// unlock any locked mem
	if (TMS_OBJ_IS(shm, TMS_OBJ_MLOCK)){
		try (!munlock(ptr, shm->usrSize));
	}

	// unmap the section
	try (!munmap(shm, size));
	return 0;

	catch:
	return -1;
}

// return a ptr to an existing shared memory object
static void *_shm_open_by_info(TmsNameInfoT *info, int flags)
{
	char name[TMS_PATH_MAX+1];
	int fd = -1;
	TmsShmT *shm = NULL;
	struct stat xstat;
	void *ptr = NULL;
	int prot = 0;
	CatchAndRelease;

	//TMS_DEBUG("try open: %s\n", info->name);

	if (flags & TMS_RDONLY) {
		prot = PROT_READ;
	}
	else if (flags & TMS_WRONLY) {
		prot = PROT_WRITE;
	}
	else {
		prot = PROT_READ | PROT_WRITE;
	}

	// format the name
	try (_shm_make_name(name, info->name, TMS_MEM_NAME));

	// try to open
	fd = shm_open(name, O_RDWR, S_IRUSR | S_IWUSR);
	if (fd == -1){
		catch_if (errno == ENOENT)
		else throw(errno, "unable to open %s.\n", info->name)
	}

	// we opened the shm object
	release_set(OPEN1);
	try (!fstat(fd, &xstat));
	try (xstat.st_size == TMS_ALIGN_SIZE(xstat.st_size, TMS_ALIGN_PAGE));

	try_set (CREATE1, (shm = (TmsShmT *) mmap(NULL, xstat.st_size, prot, MAP_SHARED, fd, 0)) != (TmsShmT *) -1);

	try_clr (OPEN1, !close(fd));
	ptr = (void *)((uint8_t *) shm + shm->data.offset);

	// sanity check
	try (xstat.st_size == shm->actSize);

	// data ok?
	try (TMS_OBJ_PASS(shm, TMS_OBJ_SHM));
	try (*((TmsGuardT *) ((uint8_t *) ptr + shm->usrSize)) == TMS_MEM_GUARD);

	// do we need to lock?
	if (TMS_OBJ_IS(shm, TMS_OBJ_MLOCK)){
		try_set (LOCK1, !_mem_lock(ptr, shm->usrSize, 0));
	}

	//TMS_DEBUG("shm open %s %p, xstat size %zd, end: %p, guard %p/0x%x\n",
		//	info->name, ptr, xstat.st_size, (uint8_t *)shm + xstat.st_size,
			//(uint8_t *) ptr + shm->usrSize, *(int *)((uint8_t *) ptr + shm->usrSize));

	info->open_base = ptr;
	info->flags = NAME_OBJ_SHM;
	return ptr;

	catch:
	release (OPEN1, close(fd));
	release (CREATE1, munmap(shm, xstat.st_size));
	release (LOCK1, munlock(shm, shm->usrSize));
	return NULL;
}

// destroy an existing shared memory object, must exist
static int _shm_destroy_by_info (TmsNameInfoT *info)
{
	void *ptr;
	TmsShmT *shm;
	TmsObjDataT *data;
	char name[TMS_PATH_MAX+1];

	// open the mem object to destroy the locks and invalidate
	if (!info->open_base){
		try (ptr = _shm_open_by_info(info, TMS_RDWR));
	}
	else{
		ptr = info->open_base;
	}

	// find start of mem
	data = (TmsObjDataT *) ((uint8_t *) ptr - sizeof(TmsObjDataT));
	shm = (TmsShmT *) ((uint8_t *) ptr - data->offset);

	// invalidate
	shm->guard = ~TMS_MEM_GUARD;

	// save the name
	strncpy(name, shm->name, TMS_PATH_MAX);
	name[TMS_PATH_MAX] = '\0';

	// destroy the lock
	try (!_rwlock_destroy(&shm->rwlock));

	// unlock any mem
	if (TMS_OBJ_IS(shm, TMS_OBJ_MLOCK)){
		try (!munlock(ptr, shm->usrSize));
	}

	// unmap (free)
	try (!munmap((uint8_t *) shm, shm->actSize));

	// delete the section
	try (!shm_unlink(name));
	return 0;

	catch:
	return -1;
}

// will find a registered named object by searching for name
static TmsNameInfoT *_name_find_when_locked(char *name)
{
	TmsNameLinkT *base = &_name_link;
	TmsMemT *node;
	TmsNameInfoT *info;
	int i;
	uint32_t hash;

	// null ptr?
	try (name);

	// look past leading slash for shm
	if (*name == '/'){
		name++;
	}

	// proper length?
	try (strnlen(name, TMS_PATH_MAX+1) <= TMS_PATH_MAX);

	// simple hash
	hash = _hash(name);

	// start of our list
	node = (TmsMemT *)((uint8_t *) base + base->link.head);

	// linear search for hash
	for (i=0; i<base->link.cnt; i++){
		info = (TmsNameInfoT *) ((uint8_t *) node + TMS_MEM_NODE_SIZE);
		if (hash == info->hash && !memcmp(name, info->name, info->len)){
			return info;
		}
		node = (TmsMemT *)((uint8_t *) base + node->data.next);
	}
	catch:
	return NULL;
}

// will find a registered named object by searching for pointer
static TmsNameInfoT *_name_find_by_ptr_when_locked(void *ptr)
{
	TmsNameLinkT *base = &_name_link;
	TmsMemT *node;
	TmsNameInfoT *info;
	int i;

	// null ptr?
	try (ptr);

	// start of our list
	node = (TmsMemT *)((uint8_t *) base + base->link.head);

	// linear search for pointer
	for (i=0; i<base->link.cnt; i++){
		info = (TmsNameInfoT *) ((uint8_t *) node + TMS_MEM_NODE_SIZE);
		if (info->open_base == ptr){
			return info;
		}
		node = (TmsMemT *)((uint8_t *) base + node->data.next);
	}
	catch:
	return NULL;
}

static TmsNameInfoT *_name_add_when_locked (char *name, int flags)
{
	TmsNameLinkT *base = &_name_link;
	TmsMemT *node;
	TmsNameInfoT *info;

	// ignore the shm slash
	if (*name == '/'){
		name++;
	}

	// check for unique and valid name
	try (!_name_find_when_locked(name));

	// alloc mem for the info
	try (info = _tms_malloc(NULL, sizeof(TmsNameInfoT), 0, 0));

	// get the len
	info->len = strlen(name);

	// hash the name
	info->hash = _hash(name);

	// save the name
	memcpy(info->name, name, info->len+1);

	// save type flag (heap or shm)
	info->flags = flags;

	// no opens
	info->cnt = 0;

	// no pointer yet
	info->open_base = NULL;

	// link to tail
	node = (TmsMemT *) ((uint8_t *) info - TMS_MEM_NODE_SIZE);
	node->data.obj = (uint8_t *) node - (uint8_t *) base;
	_link_tail(base, &node->data, &base->link);

	// done
	return info;

	catch:
	return NULL;
}

static TmsNameInfoT *_name_add (char *name, int flags)
{
	TmsNameInfoT *info;

	_name_lock();
	try (info = _name_add_when_locked(name, flags));
	catch:
	_name_unlock();
	return info;
}

// will unregister a name created during a create/open call
static int _name_unlink_when_locked(TmsNameInfoT *info)
{
	TmsNameLinkT *base = &_name_link;
	TmsMemT *node;

	memset(info, 0, sizeof(TmsNameInfoT));
	node = (TmsMemT *) ((uint8_t *) info - TMS_MEM_NODE_SIZE);
	_unlink_node(base, &node->data, &base->link);
	try (!_tms_free(NULL, node, 0));
	return 0;

	catch:
	return -1;
}

// will unregister a name created during a create/open call
static int _name_unlink(TmsNameInfoT *info)
{
	_name_lock();
	try (!_name_unlink_when_locked(info));
	_name_unlock();
	return 0;

	catch:
	_name_unlock();
	return -1;
}

// will unregister a name created during a create/open call
static int _name_destroy_by_info_when_locked(TmsNameInfoT *info)
{
	if (info->flags & NAME_OBJ_SHM){
		try (!_shm_destroy_by_info(info));
	}
	else {
		try (!TmsFree(info->open_base));
	}
	_name_unlink_when_locked(info);
	return 0;

	catch:
	return -1;
}

static int _name_destroy (char *name)
{
	TmsFileLockT *filelock;
	TmsNameInfoT *info;
	try (filelock = _file_lock(name));
	try (info = _name_find_when_locked(name));
	try (!_name_destroy_by_info_when_locked(info));
	try (!_file_unlock(filelock));
	return 0;

	catch:
	try (!_file_unlock(filelock));
	return -1;
}

// will return local or shm object, shm will be
// opened if not already in the list
static TmsNameInfoT *_name_open_when_locked (char *name, int flags)
{
	CatchAndRelease;
	TmsNameInfoT *info;
	void *ptr;

	// we have no info on this named object, try to find
	// it and register it
	if (!(info = _name_find_when_locked(name))){
		try_set (ALLOC1, info = _name_add_when_locked(name, flags));
		if (!(ptr = _shm_open_by_info(info, flags))){
			catch_if (errno == ENOENT)
			else throw(errno, "%s\n", name);
		}
	}

	// we've registered this name before, is it open?
	else if (!info->cnt && (info->flags == NAME_OBJ_SHM)){
		if (!(ptr = _shm_open_by_info(info, flags))){
			catch_if (errno == ENOENT)
			else throw(errno, "%s\n", name);
		}
	}

	TMS_ASSERT(info->open_base);

	info->cnt++;
	return info;

	catch:
	release(ALLOC1, _name_unlink_when_locked(info));
	return NULL;
}

static void *_name_open (char *name, int flags, int msec)
{
	struct timespec start;
	TmsNameInfoT *info;
	TmsFileLockT *filelock;

	// lock the name from everyone
	try (filelock = _file_lock(name));

	if (!(info = _name_open_when_locked(name, flags))) {
		try (errno == ENOENT);
		if (!msec){
			errno = EAGAIN;
		}
		// we will block until name is found or timeout
		else {
			if (msec > 0){
				try (!clock_gettime(CLOCK_MONOTONIC, &start));
			}
			while (1){
				errno = 0;
				usleep(TMS_OPEN_POLL_MSEC * 1000);
				try (filelock = _file_lock(name));
				if ((info = _name_open_when_locked(name, flags))){
					break;
				}
				try (errno == ENOENT);
				if ((msec > 0 && _msec_is_elapsed(&start, msec))){
					errno = ETIMEDOUT;
					break;
				}
				try (!_file_unlock(filelock));
			}
		}
	}

	// unlock the name
	try (!_file_unlock(filelock));
	return info->open_base;

	catch:
	_name_unlock();
	return NULL;
}

// called to clean up successful name_open()
static int _name_close_when_locked(void *ptr)
{
	TmsNameInfoT *info;

	try (info = _name_find_by_ptr_when_locked(ptr));
	if (info->cnt){
		info->cnt--;
		if (!info->cnt){
			if (info->flags & NAME_OBJ_SHM){
				try (!_shm_close(info->open_base));
				info->open_base = NULL;
			}
		}
	}
	return 0;

	catch:
	return -1;
}

// called to clean up successful name_open()
static int _name_close(void *ptr)
{
	_name_lock();
	try (!_name_close_when_locked(ptr));
	_name_unlock();
	return 0;

	catch:
	_name_unlock();
	return -1;
}

static void *_name_malloc (char *name, TmsPoolT *pool, size_t size, int flags, uint8_t lock)
{
	CatchAndRelease;
	void *ptr;
	TmsNameInfoT *info;

	try_set (ALLOC1, info = _name_add(name, 0));
	try (ptr = _tms_malloc(pool, size, flags, lock));
	info->open_base = ptr;
	return ptr;

	catch:
	release(ALLOC1, _name_unlink(info));
	return NULL;
}

int TmsTestNameClean(void)
{
	ptrdiff_t next;
	int i, j;
	TmsNameLinkT *nl = &_name_link;
	TmsMemT *node;
	TmsNameInfoT *info;


	_name_lock();
	node = (TmsMemT *)((uint8_t *) nl + nl->link.head);
	for (i=0; i<nl->link.cnt; i++){
		next = node->data.next;
		info = (TmsNameInfoT *) ((uint8_t *) node + TMS_MEM_NODE_SIZE);
		for (j=0; j<info->cnt; j++){
			_name_close_when_locked(info->open_base);
		}
		_tms_free(NULL, node, 0);
		node = (TmsMemT *)((uint8_t *) nl + next);
	}
	memset(&_name_link.link, 0, sizeof(TmsLinkT));
	_name_unlock();

	return 0;
}

static int _pool_flags(char *name, int *flags, mode_t perm)
{
	int bitcnt;

	if (*name == '/'){
		*flags |= TMS_SHARED;
	}

	try ((bitcnt = _bit_count(*flags & TMS_POOL_FLAGS)) < 2);

	if (!bitcnt){
		*flags |= TMS_POOL_DEFAULT;
	}

	if (*flags & TMS_SHARED){
		try (perm);
		*flags |= TMS_RDWR;
		if (*flags & TMS_HEAP){
			*flags &= ~TMS_HEAP;
			*flags |= TMS_SHM_POOL_DEFAULT;
		}
	}
	return 0;

	catch:
	return -1;
}

static int _hash_flags(char *name, int *flags, mode_t perm)
{
	try ((*flags & TMS_HASH_CREATE_FLAGS) == *flags);
	*flags |= TMS_HASH;
	try (!_pool_flags(name, flags, perm));
	return 0;

	catch:
	return -1;
}

static int _list_flags(char *name, int *flags, mode_t perm)
{
	try ((*flags & TMS_LIST_CREATE_FLAGS) == *flags);
	try (!_pool_flags(name, flags, perm));
	try (!((*flags & TMS_NOCOPY) && (*flags & TMS_RING)));
	return 0;

	catch:
	return -1;
}

static int _link_flags(char *name, int *flags, mode_t perm)
{
	if (*name == '/'){
		*flags |= TMS_SHARED;
	}
	try ((*flags & TMS_LIST_LINK_FLAGS) == *flags);
	return 0;

	catch:
	return -1;
}

static size_t _pool_create_size(int num, size_t size, int flags)
{
	size_t x =
	    flags & TMS_LINK ? TMS_LINK_POOL_CREATE_SIZE(num, size, flags)
			: flags & TMS_FIXED ? TMS_FIXED_POOL_CREATE_SIZE(num, size, flags)
			: flags & TMS_DYNAMIC ? TMS_TLSF_POOL_CREATE_SIZE(num, size, flags)
			: flags & TMS_HEAP ? TMS_HEAP_POOL_CREATE_SIZE(num, size, flags)
			: 0;
	return x;
}

static TmsLinkT _fixed_pool_init(TmsPoolT *pool)
{
	TmsLinkT link;
	uint8_t *tmp;
	TmsMemT *node=NULL, *prev=NULL, *mem_block=NULL;
	ptrdiff_t offset;
	int i, align;
	ptrdiff_t pool_dist, prev_dist;

	pool->block_size = TMS_POOL_MEMBER_SIZE(pool->elem_size, pool->flags);
	align = TMS_ALIGN_GET(pool->flags & TMS_ALIGN_MASK);

	for (i=0; i<pool->num_elem; i++){

		// start at next free block
		offset = i * pool->block_size;
		mem_block = (TmsMemT *) ((uint8_t *) pool->start + offset);

		// align it up to the requested alignment to find the user data
		tmp = TMS_ALIGN_PTR((uint8_t *) mem_block + TMS_MEM_NODE_SIZE, align);

		//TMS_DEBUG("block %d, %p %p %p %p\n",
			//	i, mem_block, tmp, tmp + (pool->elem_size - 1),
				//(uint8_t *) mem_block + (pool->block_size - 1));

		// put our node just below this alignment
		node = (TmsMemT *) (tmp - TMS_MEM_NODE_SIZE);

		// distance from pool to node
		pool_dist = (uint8_t *) node - (uint8_t *) pool;

#if 1
		{
			uint8_t *endblock;
			endblock = (uint8_t *) ((uint8_t *) mem_block + pool->block_size);
			uint8_t *endpool = (uint8_t *) ((uint8_t *) pool + pool->total_size);
			TMS_ASSERT(endblock < endpool);
			TMS_ASSERT(tmp + pool->elem_size < endblock - sizeof(TmsGuardT));
		}
#endif

		if (i == 0){
			link.head = pool_dist;
			node->data.prev = 0;
			node->data.next = 0;
		}
		else if (i > 0){
			// previous node points to this node
			prev->data.next = pool_dist;

			// current node points to prev node
			node->data.prev = prev_dist;
		}

		//TMS_DEBUG("fixed init, %d, obj %zx, next %zx, prev %zx\n",
			//	i, pool_dist, node->data.next, node->data.prev);

		// save this for next node
		prev = node;
		prev_dist = pool_dist;
	}

	// clean up
	if (node){
		node->data.next = 0;
		link.tail = pool_dist;
	}
	else{
		link.tail = 0;
	}

	// our list starts full
	link.cnt = pool->num_elem;
	return link;
}

TmsPoolT *TmsPoolInit(void *mem, int num_elem, size_t elem_size, int flags)
{
	TmsPoolT *pool;
	uint8_t *ptr;
	ptrdiff_t offset;
	TmsLinkT free_list = {0}, alloc_list = {0};
	size_t poolsize;

	try(elem_size && num_elem);

	// clear the memory
	poolsize = _pool_create_size(num_elem, elem_size, flags);

	//TMS_DEBUG("pool init %p, end %p, size %zd\n",
		//	mem, (uint8_t *) mem + poolsize - 1, poolsize);

	//memset(mem, 0, poolsize);

	// starting addr
	pool = (TmsPoolT *) mem;

	// point to the pool starting addr
	ptr = TMS_ALIGN_PTR((uint8_t *) mem + TMS_POOL_NODE_SIZE, TMS_ALIGN_POOL);

	// offset to find base mem so we can free it
	offset = (uint8_t *) ptr - (uint8_t *) mem;

	// init our pool attributes
	memset(pool, 0, sizeof(TmsPoolT));
	pool->start = ptr;
	pool->num_elem = num_elem;
	pool->elem_size = elem_size;
	pool->flags = flags;
	pool->freeSize = num_elem * elem_size;
	pool->userSize = pool->freeSize;
	pool->self = pool;
	pool->guard = TMS_MEM_GUARD | TMS_OBJ_POOL;
	pool->offset = offset;
	pool->free_list = free_list;
	pool->alloc_list = alloc_list;
	pool->alloc_is_pending = 0;
	pool->total_size = poolsize;
	pool->cnt = 0;
	pool->use_destroy = 0;
	try (!_cv_create(&pool->cv, flags));

	// locking for malloc/free
	try (!_mutex_create(&pool->mutex, flags));

	// initialize the pool
	if (flags & TMS_FIXED){

		pool->free_list = _fixed_pool_init(pool);

		//TMS_DEBUG("FIXED POOL OVERHEAD: %zd%%, (%d %zd) %zd / %zd bytes\n",
			//((100 * poolsize) / (num_elem * elem_size)) - 100,
			//num_elem, elem_size, num_elem * elem_size, poolsize);
	}
	else if (flags & TMS_DYNAMIC){

		// don't include the offset in the pool size
		poolsize = TMS_TLSF_POOL_INIT_SIZE(num_elem, elem_size, flags) - offset;

		//TMS_DEBUG("tlsf: %p, raw size %zd, pool init size %zd, create size %zd\n",
			//	pool->self, num_elem * elem_size, poolsize,
				//TMS_TLSF_POOL_CREATE_SIZE(num_elem, elem_size, flags));

		try (tlsf_pool_create(poolsize, ptr) != -1);

		//TMS_DEBUG("TLSF POOL OVERHEAD: %zd%%, (%d %zd) %zd / %zd bytes\n",
			//((100 * poolsize) / (num_elem * elem_size)) - 100,
			//num_elem, elem_size, num_elem * elem_size, poolsize);
	}
	return pool;

	catch:
	return NULL;
}

void *TmsPoolMalloc (TmsPoolT *pool, size_t size)
{
	return _tms_malloc(pool, size, 0, 1);
}

int TmsPoolCreate (char *name, int num, size_t size, int flags, mode_t perm)
{
	TmsPoolT *pool;
	void *ptr = NULL;
	size_t poolsize;
	CatchAndRelease;

	try (!_pool_flags(name, &flags, perm));

	poolsize = _pool_create_size(num, size, flags);

	if (flags & TMS_SHARED){
		try_set (CREATE1, !TmsShmCreate(name, poolsize, flags, perm));
		try (ptr = _name_open(name, TMS_RDWR, 0));
		try (pool = TmsPoolInit(ptr, num, size, flags));
		_name_close(ptr);
	}
	else{
		try_set (CREATE1, (ptr = _name_malloc(name, NULL, poolsize, flags, 0)));
		try (pool = TmsPoolInit(ptr, num, size, flags));
	}
	pool->use_destroy = 1;
	return 0;

	catch:
	release (CREATE1, _name_destroy(name));
	return -1;
}

int TmsPoolClose(TmsPoolT *pool)
{
	try (TMS_OBJ_PASS(pool, TMS_OBJ_POOL));
	try (!_name_close(pool));
	return 0;

	catch:
	return -1;
}

TmsPoolT *TmsPoolOpen (char *name, int msec)
{
	CatchAndRelease;
	TmsPoolT *pool = NULL;
	try_set (OPEN1, pool = (TmsPoolT *) _name_open(name, TMS_RDWR, msec));
	try (TMS_OBJ_PASS(pool, TMS_OBJ_POOL));
	return pool;

	catch:
	release (OPEN1, _name_close(pool));
	return NULL;
}

static int _pool_alloc_flush_tid(TmsPoolT *pool, int lock)
{
	CatchAndRelease;
	ptrdiff_t next;
	TmsMemT *node;

	if (lock){
		_mutex_set (LOCK1, &pool->mutex);
	}

	next = pool->alloc_list.head;
	while (next) {
		node = (TmsMemT *) ((uint8_t *) pool + next);
		next = node->data.next;
		if (node->data.tid && _tid && node->data.tid != _tid && kill(node->data.tid, 0)) {
			try (!_tms_free(pool, node, 0));
		}
	}

	_release_mutex(LOCK1, &pool->mutex);
	return 0;

	catch:
	return -1;

}

static int _pool_alloc_flush(TmsPoolT *pool, int lock)
{
	CatchAndRelease;
	TmsMemT *node;
	int i;

	if (lock){
		_mutex_set(LOCK1, &pool->mutex);
	}

	for (i=0; i<pool->alloc_list.cnt; i++) {
		node = (TmsMemT *) ((uint8_t *) pool + pool->alloc_list.head);
		try (!_tms_free(pool, node, 0));
	}

	_release_mutex(LOCK1, &pool->mutex);
	return 0;

	catch:
	_release_mutex(LOCK1, &pool->mutex);
	return -1;
}

static void *_pool_alloc (TmsPoolT *pool, size_t size, int flags, int msec, int reap)
{
	void *ptr;

	// alloc from list pool
	if (!(ptr = _tms_malloc(pool, size, flags, 1))){

		// if we failed to alloc, try to reap orphaned memory
		if (reap){
			_pool_alloc_flush_tid(pool, 1);
		}

		// lock the pool
		_mutex_lock(&pool->mutex);

		// wait for alloc
		//TMS_DEBUG("pool %p, wait for malloc\n", pool->self);
		CV_WAIT(
			&pool->cv, &pool->mutex,
			ptr = _tms_malloc(pool, size, flags, 0),
			pool->alloc_is_pending,
			msec
		);

		// unlock the pool
		_mutex_unlock(&pool->mutex);
	}
	return ptr;
}

int TmsPoolWalk(TmsPoolT *pool, TmsWalkCallbackT callback, void *arg)
{
	CatchAndRelease;
	TmsCbActionT action;
	int rc, cnt;
	ptrdiff_t tmp;
	TmsMemT *node;

	try (TMS_OBJ_PASS(pool, TMS_OBJ_POOL));

	_mutex_set (LOCK1, &pool->mutex);

	cnt = pool->alloc_list.cnt;

	rc = 0;
	while (cnt--)
	{
		if (!(tmp = pool->alloc_list.head)){
			break;
		}

		node = (TmsMemT *) ((uint8_t *) pool + tmp);

		action = callback((uint8_t *) node + TMS_MEM_NODE_SIZE, node->usrSize, arg, &rc);

		try (!(action & ~TMS_CB_MASK));

		if (rc){
			break;
		}
		if (action & TMS_CB_FREE){
			_tms_free(pool, node, 0);
		}
		if (action & TMS_CB_EXIT){
			break;
		}
	}

	_mutex_clr (LOCK1, &pool->mutex);
	return rc;

	catch:
	_release_mutex(LOCK1, &pool->mutex);
	return -1;
}

static int _pool_free_heap (TmsPoolT *pool)
{
	// free anything remaining in a heap pool
	if (pool->flags & TMS_HEAP){
		try (!_pool_alloc_flush(pool, 1));
	}
	return 0;

	catch:
	return -1;
}

int TmsPoolDestroy (char *name)
{
	CatchAndRelease;
	TmsPoolT *pool;

	// open the pool
	try_set (OPEN1, pool = (TmsPoolT *) _name_open(name, TMS_RDWR, 0));
	try (TMS_OBJ_PASS(pool, TMS_OBJ_POOL));

	// need to be created via TmsPoolCreate
	try (pool->use_destroy);

	// free anything remaining in a heap pool
	try (!_pool_free_heap(pool));

	// destroy any memory used to create the pool
	try (!_name_destroy(name));
	return 0;

	catch:
	return -1;
}

// destroy an existing shared memory object, must exist
int TmsShmDestroy (char *name)
{
	try (!_name_destroy(name));
	return 0;

	catch:
	return -1;
}

// close an existing shared memory object, must exist
int TmsShmClose(void *ptr)
{
	try (!_name_close(ptr));
	return 0;

	catch:
	return -1;
}

// return a ptr to an existing shared memory object
void *TmsShmOpen (char *name, int flags, int msec)
{
	void *ptr;

	try (ptr = _name_open(name, flags, msec));
	return ptr;

	catch:
	return NULL;
}

// return a pointer to a new shared memory object
int TmsShmCreate (char *name, size_t size, int flags, mode_t perm)
{
	TmsObjT lock = flags & TMS_MLOCK ? TMS_OBJ_MLOCK : 0;;
	int fd = 0;
	TmsShmT *shm = NULL;
	TmsObjDataT *data;
	void *ptr = NULL;
	char buf[TMS_PATH_MAX+1];
	CatchAndRelease;
	size_t sizeIn = size;
	int align, len;
	TmsFileLockT *filelock = NULL;
	TmsNameInfoT *info = NULL;

	// prevent anyone else from creating this name
	try_set (LOCK1, filelock = _file_lock(name));

	// does the section exist?
	if (!(info = _name_open_when_locked(name, flags))){

		// we don't care if section doesn't exist
		try (errno == ENOENT);
		errno = 0;

		// register the name
		try_set (CREATE1, info = _name_add_when_locked(name, NAME_OBJ_SHM));
	}

	// section exists
	else {

		//we found the section
		release_set(OPEN1);

		// our user space
		ptr = info->open_base;

		// are we supposed to fail if file exists?
		if (flags & TMS_EXFAIL){
			throw(EEXIST, "%s\n", name);
		}

		// do we delete this?
		else if (!(flags & TMS_EXOPEN)) {
			try_clr (OPEN1, !_shm_destroy_by_info(info));
			//TMS_DEBUG("we destroyed %s\n", name);
		}

		// try to use existing section
		else {

			// we have an object node just below our user ptr
			data = (TmsObjDataT *) ((uint8_t *) ptr - sizeof(TmsObjDataT));

			// point to the start of the section, our shm node is here
			shm = (TmsShmT *) ((uint8_t *) ptr - data->offset);

			// make sure we the correct space allocated
			try (shm->actSize == TMS_SHM_CREATE_SIZE(size, align, flags));

			// close the section
			try (!_name_close_when_locked(ptr));

			// unlock the name
			try_clr (LOCK1, !_file_unlock(filelock));

			//TMS_DEBUG("we re-use  %s\n", name);
			return 0;
		}
	}

	// format the name
	try (len = _shm_make_name(buf, name, TMS_MEM_NAME));

	// at this point, no section exists
	// we don't allow zero size
	try (size);

	// do we use default permission?
	if (!perm){
		perm = TMS_DEFAULT_SHM_PERM;
	}

	// make sure we have rw user permission
	else{
		perm |= S_IRUSR | S_IWUSR;
	}

	// open a read/write
	try_set (OPEN2, (fd = shm_open(buf, O_EXCL | O_CREAT | O_TRUNC | O_RDWR, perm)) != -1);
	release_set(OPEN3);

	// tbd: chmod to absolute permission, override umask
	//try(!chmod(tmp, perm));

	// our total size
	size = TMS_SHM_CREATE_SIZE(size, align, flags);

	// set our shm size
	try (!ftruncate(fd, size));

	// map to memory
	try_set (CREATE2, (shm = (TmsShmT *) mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd,  0)) != (TmsShmT *) -1);

	// don't need this open
	try_clr (OPEN2, !close(fd));

	// align the user space
	ptr = TMS_ALIGN_PTR((uint8_t *) shm + TMS_SHM_NODE_SIZE + sizeof(TmsObjDataT), align);

	// create a read write lock
	try_set (CREATE3, !_rwlock_create(&shm->rwlock, TMS_SHARED));

	// we created this
	if (!_tid){
		_tid = getpid();
	}

	memset(&shm->data, 0, TMS_SHM_NODE_SIZE);
	memcpy(shm->name, buf, len+1);
	shm->usrSize = sizeIn;
	shm->actSize = size;
	shm->data.offset = (uint8_t *) ptr - (uint8_t *) shm;
	shm->guard = TMS_MEM_GUARD | TMS_OBJ_SHM | lock;
	shm->data.next = 0;
	shm->data.prev = 0;
	shm->data.tid = _tid;
	shm->data.obj = 0;
	shm->flags = flags;
	shm->perm = perm;
	try (!clock_gettime(CLOCK_MONOTONIC, &shm->data.ts));

	// don't use memcpy, may overlap!
	data = (TmsObjDataT *)((uint8_t *) ptr - sizeof(TmsObjDataT));
	memmove(data, &shm->data, sizeof(TmsObjDataT));

	//TMS_DEBUG("shm %s size %zd / %zd, %p %p %p %p\n",
		//	name, sizeIn, size, shm, ptr, (uint8_t *)ptr+sizeIn-1, (uint8_t *)shm +(size-1));

	// memory guard
	*((TmsGuardT *) ((uint8_t *) ptr + sizeIn)) = TMS_MEM_GUARD;

	// save the ptr
	info->open_base = NULL;

	// close the section
	try_clr (CREATE2, !munmap(shm, size));

	// unlock the file lock
	try_clr (LOCK1, !_file_unlock(filelock));
	return 0;

	catch:
	release (OPEN1, _name_close(ptr));
	release (CREATE3, _rwlock_destroy(&shm->rwlock));
	release (OPEN2, close(fd));
	release (CREATE2, munmap(shm, size));
	release (OPEN3, shm_unlink(buf));
	release (CREATE1, _name_unlink_when_locked(info));
	release (LOCK1, _file_unlock(filelock));
	return -1;
}

//debug
#if 0
static void _hash_walk(TmsHashT *hash, TmsHashTableT *ptr)
{
	TmsHashMemT *mem;

	while (ptr->prev_valid && ptr->hash_idx){
		ptr = _hash_table_by_offset(hash, ptr->prev);
	}
	mem = _hash_mem_by_offset(hash, ptr->mem_idx);
	TMS_DEBUG("hash walk\n");
	while (1){
		TMS_DEBUG("%s root %d idx %d mem %d prev %d/%d next %d/%d occupied %d\n",
				mem->key,
				ptr->root,
				ptr->hash_idx,
				ptr->mem_idx,
				ptr->prev_valid,
				ptr->prev,
				ptr->next_valid,
				ptr->next,
				ptr->hash_idx);

		if (!ptr->next_valid){
			break;
		}

		ptr = _hash_table_by_offset(hash, ptr->next);
		mem = _hash_mem_by_offset(hash, ptr->mem_idx);
	}
}
#else
#define _hash_walk(hash, ptr)
#endif

static uint32_t _hash_lock_mask(uint32_t num)
{
	return _power2_ceil((num * TMS_HASH_SECTIONS_PERCENT)/100) - 1;
}

size_t TmsHashCreateSize(int num, int size, int keysize, int flags)
{
	size_t poolsize;
	size_t tablesize;
	size_t locksize;
	size_t totsize=0;

	catch_if (!size || !num || !keysize);

	// number of locks as a percentage of table size
	locksize = TMS_HASH_LOCK_SIZE(num);

	// get our hash
	tablesize = TMS_HASH_TABLE_SIZE(num);

	// get our pool size
	poolsize = _pool_create_size(num, TMS_HASH_MEMBER_SIZE(size, keysize), flags);

	// add it all up
	totsize = TMS_ALIGN_SIZE(TMS_HASH_BASE_SIZE + locksize + tablesize + poolsize, TMS_ALIGN_DEFAULT);

	catch:
	return totsize;
}

// create a hash table
int TmsHashCreate (char *name, int keysize, int num, int size, int flags, mode_t perm)
{
	TmsHashBaseT *base = NULL;
	CatchAndRelease;
	size_t table_size;
	void *ptr;

	try (num && size && keysize);
	try (!_hash_flags(name, &flags, perm));
	table_size = TmsHashCreateSize(num, size, keysize, flags);

	if (flags & TMS_SHARED){
		try_set (CREATE1, !TmsShmCreate(name, table_size, flags, perm));
		try (ptr = _name_open(name, TMS_RDWR, 0));
		try (base = TmsHashInit(ptr, keysize, num, size, flags));
		strcpy(base->name, name);
		base->use_destroy = 1;
		_name_close(ptr);
	}
	else{
		try_set (CREATE1, (ptr = _name_malloc(name, NULL, table_size, flags, 0)));
		try (base = TmsHashInit(ptr, keysize, num, size, flags));
		strcpy(base->name, name);
		base->use_destroy = 1;
	}
	return 0;

	catch:
	release (CREATE1, _name_destroy(name));
	return -1;
}

// init a hash table
// layout base + locks + table + pool
TmsHashBaseT *TmsHashInit(void *ptr, int key_size, int num_elem, int elem_size, int flags)
{
	TmsHashBaseT *base;
	uint8_t *tptr;
	TmsHashLockT *lock;
	int i=0, j;

	try (num_elem && elem_size && key_size);

	base = (TmsHashBaseT *) ptr;

	base->key_size = key_size;
	base->elem_size = elem_size;
	base->num_elem = num_elem;
	base->align_lock_size = TMS_HASH_LOCK_SIZE(num_elem);
	base->hdr_size = TMS_HASH_HDR_SIZE(key_size);
	base->guard = TMS_MEM_GUARD | TMS_OBJ_HASH;
	base->flags = flags;
	base->modulo_mask = _bit_count(num_elem) == 1 ? base->num_elem - 1 : 0;
	base->collisions = 0;

	// init the shared locks
	// the number of locks = percentage of size
	base->locks = TMS_HASH_BASE_SIZE;
	base->section_mask = _hash_lock_mask(num_elem);

	tptr = (uint8_t *) base + base->locks;
	lock = (TmsHashLockT *) tptr;
	for (i=0; i<=base->section_mask; i++){
		try (!_hash_lock_create(&lock[i], flags));
	}

	// init the hash table
	base->table = TMS_HASH_BASE_SIZE + TMS_HASH_LOCK_SIZE(num_elem);
	tptr = (uint8_t *) base + base->table;
	memset(tptr, 0, TMS_HASH_TABLE_SIZE(num_elem));

	// our mem pool, must be properly aligned
	tptr = TMS_ALIGN_PTR(tptr + TMS_HASH_TABLE_SIZE(num_elem), TMS_ALIGN_POOL);
	base->pool = tptr - (uint8_t *) base;
	try (TmsPoolInit(tptr, num_elem, TMS_HASH_MEMBER_SIZE(elem_size, key_size), flags));
	return base;

	catch:
	tptr = (uint8_t *) base + base->locks;
	lock = (TmsHashLockT *) tptr;
	for (j=0; j<i; j++){
		_hash_lock_destroy(&lock[j]);
	}
	return NULL;
}

TmsHashT *TmsHashOpen (char *name, int flags, int msec)
{
	CatchAndRelease;
	TmsHashBaseT *base = NULL;
	TmsHashT *hash = NULL;

	try_set (OPEN1, base = (TmsHashBaseT *) _name_open(name, TMS_RDWR, msec));
	try (TMS_OBJ_PASS(base, TMS_OBJ_HASH));
	try_set (ALLOC1, hash = _tms_malloc(NULL, sizeof(TmsHashT), 0, 0));
	hash->base = base;
	hash->locks = (TmsHashLockT *) ((uint8_t *) base + base->locks);
	hash->table = (TmsHashTableT *) ((uint8_t *) base + base->table);
	hash->pool = (TmsPoolT *) ((uint8_t *) base + base->pool);
	hash->open_flags = flags;
	return hash;

	catch:
	release (ALLOC1, TmsFree(hash));
	release (OPEN1, _name_close(base));
	return NULL;
}

#define PERCENT(x, y) ((100 * (x)) / (y))
int TmsHashStat (TmsHashT *hash)
{
	char buf[1024];
	TmsHashBaseT *base;

	try (hash && hash->base);
	base = hash->base;

	snprintf(buf, sizeof (buf),
		"\nName: %s\n"
		"Key Size: %u\n"
		"Element Size: %u\n"
		"Number of Elements: %u\n"
		"Occupancy: %u (%u%%)\n"
		"Collisions: %u (%u%%)\n"
		"Mem Type: %s %s\n"
		"Mem Free: %zd (%zd%%)\n\n",
		base->name,
		base->key_size,
		base->elem_size,
		base->num_elem,
		hash->pool->cnt,
		PERCENT(hash->pool->cnt, base->num_elem),
		base->collisions,
		PERCENT(base->collisions, base->num_elem),
		base->flags & TMS_DYNAMIC ? "Dynamic" : base->flags & TMS_FIXED ? "Fixed" : "Heap",
		base->flags & TMS_SHARED ? "Shared" : "Local",
		hash->pool->freeSize,
		PERCENT(hash->pool->freeSize, hash->pool->userSize)
	);
	TMS_DEBUG("%s", buf)
	return 0;

	catch:
	return -1;
}

static int _hash_by_type (TmsHashT *hash, uint8_t *key, int *ksize, uint32_t *hval, TmsHashTableT **table, TmsHashLockT **lock)
{
	uint8_t *start;
	uint32_t i;
	uint32_t _hval = FNV1A_32_INIT;
	uint32_t short_hash;

	if (!*ksize){
		start = key;
		while (*key) {
			_hval = (_hval ^ *key++) * FNV1A_32_PRIME;
		}
		*ksize = key - start;
		try (*ksize && *ksize < hash->base->key_size);
	}
	else {
		try (*ksize <= hash->base->key_size);
		for (i=0; i<*ksize; i++){
			_hval = (_hval ^ *key++) * FNV1A_32_PRIME;
		}
	}
	short_hash = hash->base->modulo_mask ? _hval & hash->base->modulo_mask : _hval % hash->base->num_elem;
	*table = &hash->table[short_hash];
	*lock = &hash->locks[short_hash & hash->base->section_mask];
	*hval = _hval;
	//TMS_DEBUG("XXXXX key %s, ksize %d, _hval 0x%x, table %p, section %d\n", tkey, *ksize, _hval, *table, short_hash & hash->base->section_mask)
	return 0;

	catch:
	return -1;
}

static TmsMemT *_hash_find(TmsHashT *hash, void *key, int ksize, uint32_t full_hash, TmsHashTableT *table)
{
	TmsHashHdrT *hdr;
	TmsMemT *node = NULL;
	ptrdiff_t next;
	int cnt;

	if ((cnt = table->cnt)){
		next = table->head;
		while (cnt--){
			node = (TmsMemT *) ((uint8_t *) hash->pool + next);
			hdr = (TmsHashHdrT *) ((uint8_t *) node + TMS_MEM_NODE_SIZE);
			if (hdr->full_hash == full_hash && !memcmp(key, hdr->key, ksize)){
				return node;
			}
			next = node->data.next;
		}
	}
	return NULL;
}

static void _read_cleanup(TmsHashLockT *lock, uint8_t flag)
{
	if (flag){
		_mutex_unlock(&lock->cv_mutex);
	}
	else {
		_rwlock_unlock(&lock->rw_lock);
	}
	_rwlock_unlock (&lock->del_lock);
}

static TmsMemT *_read_node (TmsHashT *hash, void *key, int ksize, int msec, TmsHashLockT **xlock, int *flag)
{
	CatchAndRelease;
	TmsHashLockT *lock;
	uint32_t full_hash =0;
	TmsMemT *node = NULL;
	TmsHashTableT *table = NULL;

	// get the hash
	try (!_hash_by_type (hash, key, &ksize, &full_hash, &table, &lock));

	// block unlink commands
	_rwlock_rdlock (&lock->del_lock);

	// block writers, allow readers
	_rwlock_rdlock (&lock->rw_lock);

	// try to find node & hdr
	*flag = 0;
	if (!(node = _hash_find (hash, key, ksize, full_hash, table))){

		*flag = 1;

		// we switch wrlock to mutex for cv wait
		_mutex_set(LOCK2, &lock->cv_mutex);
		_rwlock_clr(LOCK1, &lock->rw_lock);

		//TMS_DEBUG("CV WAIT\n");
		catch_if (CV_WAIT(
			&lock->read_cv,
			&lock->cv_mutex,
			node = _hash_find (hash, key, ksize, full_hash, table),
			lock->read_is_pending,
			msec));
		//TMS_DEBUG("GOT DATA FROM CV WAIT\n");
	}

	// check the node
	TMS_NODE_PASS(node);

	// return ptr to locks
	*xlock = lock;

	// return the node
	return node;

	catch:
	_read_cleanup(lock, *flag);
	return NULL;
}

static void _read_state_cleanup(TmsHashStateT *state, uint8_t flag)
{
	if (flag){
		_mutex_unlock(&state->lock->cv_mutex);
	}
	else {
		_rwlock_unlock(&state->lock->rw_lock);
	}
	_rwlock_unlock (&state->lock->del_lock);
	_mutex_unlock(&state->mutex);
}

static TmsMemT *_read_state_node(TmsHashStateT *state, uint8_t *flag)
{
	TmsMemT *node = NULL;
	TmsHashHdrT *hdr = NULL;
	uint8_t wait_for_it = 1;

	*flag = 0;

	// block threads sharing the state
	_mutex_lock(&state->mutex);

	// block unlink commands
	_rwlock_rdlock (&state->lock->del_lock);

	// block writers, allow readers
	_rwlock_rdlock (&state->lock->rw_lock);

	// get the hash node
	if (!(node = _hash_find (state->hash, state->key, state->ksize, state->full_hash, state->table))){

		*flag = 1;

		_mutex_lock (&state->lock->cv_mutex);
		_rwlock_unlock (&state->lock->rw_lock);

		//TMS_DEBUG("CV WAIT\n");
		catch_if (CV_WAIT(
			&state->lock->read_cv,
			&state->lock->cv_mutex,
			node = _hash_find (state->hash, state->key, state->ksize, state->full_hash, state->table),
			state->lock->read_is_pending,
			state->msec));
		//TMS_DEBUG("GOT DATA FROM CV WAIT\n");

		// we don't need to wait for udpate
		wait_for_it = 0;
	}

	// we know where to find our data
	hdr = (TmsHashHdrT *) ((uint8_t *) node + TMS_MEM_NODE_SIZE);

	// sanity check
	TMS_NODE_PASS(node);

	// are we initialized?
	if (!state->init){

		// do we initialize with a read?
		if (!(state->flags & TMS_HASH_NO_INIT)){
			wait_for_it = 0;
		}

		// we are initialized
		state->seq_num = hdr->seq_num;
		state->init = 1;
	}

	// do we need to wait until we have an update?
	if (wait_for_it) {

		*flag = 1;

		_mutex_lock (&state->lock->cv_mutex);
		_rwlock_unlock (&state->lock->rw_lock);

		//TMS_DEBUG("CV WAIT\n");
		catch_if (CV_WAIT(
			&state->lock->read_cv,
			&state->lock->cv_mutex,
			hdr->seq_num != state->seq_num,
			state->lock->read_is_pending,
			state->msec));
		//TMS_DEBUG("GOT DATA FROM CV WAIT\n");
	}
	return node;

	catch:
	_read_state_cleanup(state, *flag);
	return NULL;
}

int TmsHashStateRead (TmsHashStateT *state, void *vbuf, int vsize)
{
	CatchAndRelease;
	TmsHashStatusT status;
	TmsMemT *node;
	TmsHashHdrT *hdr;
	uint32_t size;
	int rc = 0;
	uint8_t flag = 0;

	try (state);
	if (vsize){
		try (vbuf);
	}

	// this sets a bynch of locks!!!
	catch_if (!(node = _read_state_node(state, &flag)));

	// we know where to find our data
	hdr = (TmsHashHdrT *) ((uint8_t *) node + TMS_MEM_NODE_SIZE);

	if (vsize || state->cb){

		// figure out how much data is avaiable
		size = node->usrSize - state->hash->base->hdr_size;

		// allocate memory if needed
		if (!vbuf){
			tms_set(ALLOC1, vbuf = _tms_malloc(NULL, size, 0, 0));
		}

		// truncate size if needed
		else if (size > vsize){
			size = vsize;
		}

		// block rmw writes
		_rwlock_rdlock (&state->lock->rmw_lock);

		// copy the data
		memcpy(vbuf, (uint8_t *) hdr + state->hash->base->hdr_size, size);

		// update state seq num
		state->seq_num = hdr->seq_num;

		// unblock rmw writes
		_rwlock_unlock (&state->lock->rmw_lock);
	}
	else {
		size = 0;
		state->seq_num = hdr->seq_num;
	}

	// clear locks
	_read_state_cleanup(state, flag);

	// we are using state var, check for call back
	if (state->cb){
		status.error = 0;
		status.seq_num = state->seq_num;
		rc = state->cb(vbuf, size, state->arg, &status);
	}

	if (tms_is_set(ALLOC1)){
		TmsFree(vbuf);
	}

	// return the size we handled
	return rc & TMS_CB_EXIT ? -1 : 0;

	catch:
	if (node){
		_read_state_cleanup(state, flag);
	}

	// send error to callback
	if (state->cb) {
		status.error = errno;
		status.seq_num = 0;
		return state->cb(NULL, 0, state->arg, &status) ? -1 : 0;
	}
	return -1;
}

int TmsHashStateReadWrite (TmsHashStateT *state, void *vbuf, int vsize)
{
	CatchAndRelease;
	TmsHashStatusT status;
	TmsMemT *node=NULL;
	TmsHashHdrT *hdr;
	void *value, *buf;
	uint32_t size;
	int rc;
	uint8_t flag;

	// we need a callback
	try (state && state->cb);

	// this sets a bunch of locks !!!!
	catch_if (!(node = _read_state_node(state, &flag)));

	// block writers and some cv wait readers
	if (!flag){
		_mutex_lock(&state->lock->cv_mutex);
		_rwlock_unlock(&state->lock->rw_lock);
		flag = 1;
	}

	// how much data do we read?
	size = node->usrSize - state->hash->base->hdr_size;

	// alloc a copy buffer for the callback
	try_set (ALLOC1, buf = _tms_malloc(NULL, size, 0, 0));

	// we know where to find our data
	hdr = (TmsHashHdrT *) ((uint8_t *) node + TMS_MEM_NODE_SIZE);

	// point to our value in the hash table
	value = (void *) ((uint8_t *) hdr + state->hash->base->hdr_size);

	// block all remaining readers
	_rwlock_wrlock (&state->lock->rmw_lock);

	// copy the data into our callback buffer
	memcpy(buf, value, size);

	// call the callback
	status.error = 0;
	status.seq_num = hdr->seq_num;
	rc = state->cb(buf, size, state->arg, &status);

	if (!(rc & TMS_CB_DISCARD)){

		// write the data back to hash table
		memcpy(value, buf, size);

		// do we return the data?
		if (vbuf){
			memcpy(vbuf, buf, vsize);
		}

		// update seq number
		hdr->seq_num++;
		state->seq_num = hdr->seq_num;

		// signal to pending readers in cv wait
		if (state->lock->read_is_pending){
			//TMS_DEBUG("BROADCAST TO READERS %d\n", lock->read_is_pending);
			pthread_cond_broadcast(&state->lock->read_cv);
		}
	}

	// unblock free readers
	_rwlock_unlock (&state->lock->rmw_lock);

	TmsFree(buf);

	// unblock everyone
	_read_state_cleanup(state, flag);
	return rc;

	catch:
	release (ALLOC1, TmsFree(vbuf));
	if (node){
		_read_state_cleanup(state, flag);
	}

	// send error to callback
	status.error = errno;
	status.seq_num = 0;
	return state->cb(NULL, 0, state->arg, &status);
}

int TmsHashStateWrite (TmsHashStateT *state, void *vbuf, int vsize)
{
	TmsHashStatusT status;
	TmsMemT *node = NULL, *tmp_node = NULL;
	TmsHashHdrT *hdr = NULL;
	uint32_t seq_num = 0;
	int rc = 0;

	try (state && vbuf);

	// block unlink
	_rwlock_rdlock(&state->lock->del_lock);

	// block other readers and writers
	_rwlock_wrlock(&state->lock->rw_lock);

	// block readers in cv wait
	_mutex_lock(&state->lock->cv_mutex);

	// get the node
	if ((node = _hash_find (state->hash, state->key, state->ksize, state->full_hash, state->table))) {

		// is node valid?
		TMS_NODE_PASS(node);

		// our header
		hdr = (TmsHashHdrT *) ((uint8_t *) node + TMS_MEM_NODE_SIZE);

		// sequence number
		seq_num = hdr->seq_num;

		// if using fixed pool, make sure size is correct
		if (state->hash->base->flags & TMS_FIXED){
			try (vsize <= state->hash->base->elem_size);
		}

		// if we are dynamic/heap alloc, we resize as needed
		else if (vsize != node->usrSize - state->hash->base->hdr_size){

			// remove from hash table
			_unlink_node(state->hash->pool, &node->data, state->table);

			// add to pool list
			_link_tail(state->hash->pool, &node->data, &state->hash->pool->alloc_list);

			// save the node in case we need to restore
			tmp_node = node;

			// empty
			node = NULL;
			hdr = NULL;
		}
	}

	// no node, we have to alloc and link to table
	if (!node) {

		// try to get some memory
		catch_if (!(hdr = (TmsHashHdrT *) _pool_alloc(state->hash->pool, state->hash->base->hdr_size + vsize, 0, state->msec, 0)));

		// our node
		node = (TmsMemT *)((uint8_t *) hdr - TMS_MEM_NODE_SIZE);

		// unlink from pool table
		_unlink_node(state->hash->pool, &node->data, &state->hash->pool->alloc_list);

		// link to the hash table
		_link_tail(state->hash->pool, &node->data, state->table);

		// count collisions
		if (state->table->cnt > 1){
			state->hash->base->collisions++;
		}

		// copy our key
		memcpy(hdr->key, state->key, state->ksize);

		// save our hash
		hdr->full_hash = state->full_hash;

		// we no longer need this
		if (tmp_node){
			_tms_free(state->hash->pool, tmp_node, 1);
		}
	}

	// call the callback
	if (state->cb){

		status.error = 0;
		status.seq_num = hdr->seq_num;
		rc = state->cb(vbuf, vsize, state->arg, &status);
		if (!(rc & TMS_CB_DISCARD)){

			// update sequence number
			hdr->seq_num = seq_num + 1;

			// our state seq num
			state->seq_num = hdr->seq_num;

			// copy our value into hash table
			memcpy((uint8_t *) hdr + state->hash->base->hdr_size, vbuf, vsize);

			// signal to pending readers
			if (state->lock->read_is_pending){
				//TMS_DEBUG("BROADCAST TO READERS %d\n", lock->read_is_pending);
				pthread_cond_broadcast(&state->lock->read_cv);
			}
		}
	}

	// free up everyone
	_mutex_unlock(&state->lock->cv_mutex);
	_rwlock_unlock(&state->lock->rw_lock);
	_rwlock_unlock(&state->lock->del_lock);
	return rc;

	catch:

	// restore this if needed
	if (tmp_node){
		_unlink_node(state->hash->pool, &tmp_node->data, &state->hash->pool->alloc_list);
		_link_tail(state->hash->pool, &tmp_node->data, state->table);
	}

	// unlock everything
	_mutex_unlock(&state->lock->cv_mutex);
	_rwlock_unlock(&state->lock->rw_lock);
	_rwlock_unlock(&state->lock->del_lock);

	// callback with error
	if (state->cb){
		status.error = EINVAL;
		status.seq_num = 0;
		return state->cb(NULL, 0, state->arg, &status);
	}
	return -1;
}

int TmsHashStateUnlink(TmsHashStateT *state)
{
	TmsMemT *node = NULL;

	try (state);

	// lock out the writers and readers
	_rwlock_wrlock(&state->lock->del_lock);

	// get the node
	try (node = _hash_find (state->hash, state->key, state->ksize, state->full_hash, state->table));

	// is node valid?
	TMS_NODE_PASS(node);

	// remove from hash table
	_unlink_node(state->hash->pool, &node->data, state->table);

	// add to pool list
	_link_tail(state->hash->pool, &node->data, &state->hash->pool->alloc_list);

	// adjust collision cnt
	if (state->table->cnt > 0){
		state->hash->base->collisions--;
	}

	// free the data
	_tms_free(state->hash->pool, node, 1);

	// clear locks
	_rwlock_unlock(&state->lock->del_lock);
	return 0;

	catch:
	_rwlock_unlock(&state->lock->del_lock);
	return -1;
}

int TmsHashRead (TmsHashT *hash, void *key, int ksize, void *vbuf, int vsize, int msec)
{
	TmsHashLockT *lock;
	TmsMemT *node = NULL;
	TmsHashHdrT *hdr = NULL;
	uint32_t size;
	int flag;

	try (hash && key && vbuf);

	// this sets a bunch of locks !!!!
	catch_if (!(node = _read_node(hash, key, ksize, msec, &lock, &flag)));

	// point to our header
	hdr = (TmsHashHdrT *) ((uint8_t *) node + TMS_MEM_NODE_SIZE);

	// figure out how much data is avaiable
	size = node->usrSize - hash->base->hdr_size;

	if (size > vsize){
		size = vsize;
	}

	// copy the data
	memcpy(vbuf, (uint8_t *) hdr + hash->base->hdr_size, size);

	// clear locks
	_read_cleanup(lock, flag);

	// return the size we handled
	return size;

	catch:
	if (node){
		_read_cleanup(lock, flag);
	}
	return -1;
}

int TmsHashReadWrite (TmsHashT *hash, void *key, int ksize, void *vbuf, int vsize, TmsHashCallbackT cb, void *arg, int msec)
{
	CatchAndRelease;
	TmsHashStatusT status;
	TmsHashLockT *lock;
	TmsMemT *node = NULL;
	TmsHashHdrT *hdr = NULL;
	void *value, *buf = NULL;
	uint32_t size;
	int rc, flag;

	// we need a callback
	try (hash && key && cb);

	// this sets a bunch of locks !!!!
	catch_if (!(node = _read_node(hash, key, ksize, msec, &lock, &flag)));

	// block writers and some cv wait readers
	if (!flag){
		_mutex_lock(&lock->cv_mutex);
		_rwlock_unlock(&lock->rw_lock);
		flag = 1;
	}

	// point to our header
	hdr = (TmsHashHdrT *) ((uint8_t *) node + TMS_MEM_NODE_SIZE);

	// point to our value in the hash table
	value = (void *) ((uint8_t *) hdr + hash->base->hdr_size);

	// figure out how much data is avaiable
	size = node->usrSize - hash->base->hdr_size;

	// alloc a copy buffer for the callback
	try_set (ALLOC1, buf = _tms_malloc(NULL, size, 0, 0));

	// block all remaining readers
	_rwlock_wrlock (&lock->rmw_lock);

	// copy the data into our callback buffer
	memcpy(buf, value, size);

	// call the callback
	status.error = 0;
	status.seq_num = hdr->seq_num;
	rc = cb(buf, size, arg, &status);

	if (!(rc & TMS_CB_DISCARD)){

		// write the data back to hash table
		memcpy(value, buf, size);

		// do we return the data?
		if (vbuf){
			memcpy(vbuf, buf, vsize);
		}

		// update seq number
		hdr->seq_num++;

		// signal to pending readers
		if (lock->read_is_pending){
			//TMS_DEBUG("BROADCAST TO READERS %d\n", lock->read_is_pending);
			pthread_cond_broadcast(&lock->read_cv);
		}
	}

	// unblock all remaining readers
	_rwlock_unlock (&lock->rmw_lock);

	TmsFree(buf);

	_read_cleanup(lock, flag);
	return rc;

	catch:
	if (buf){
		TmsFree(buf);
	}

	if (node){
		_read_cleanup(lock, flag);
	}

	// send error to callback
	if (cb) {
		status.error = errno;
		status.seq_num = 0;
		return cb(NULL, 0, arg, &status) ? -1 : 0;
	}
	return -1;
}

int TmsHashWrite (TmsHashT *hash, void *key, int ksize, void *vbuf, int vsize, int msec)
{
	TmsHashLockT *lock;
	TmsMemT *node = NULL, *tmp_node = NULL;
	TmsHashHdrT *hdr = NULL;
	TmsHashTableT *table = NULL;
	uint8_t *vkey = (uint8_t *) key;
	uint32_t seq_num = 0;
	uint32_t full_hash;

	try (hash && key && vbuf);

	// get the hash
	try (!_hash_by_type (hash, vkey, &ksize, &full_hash, &table, &lock));

	// block unlink
	_rwlock_rdlock(&lock->del_lock);

	// lock out the writers and readers
	_rwlock_wrlock(&lock->rw_lock);

	// lock the list for read cv wait
	_mutex_lock(&lock->cv_mutex);

	// get the node
	if ((node = _hash_find (hash, vkey, ksize, full_hash, table))) {

		// is node valid?
		TMS_NODE_PASS(node);

		// our header
		hdr = (TmsHashHdrT *) ((uint8_t *) node + TMS_MEM_NODE_SIZE);

		// sequence number
		seq_num = hdr->seq_num;

		// if using fixed pool, make sure size is correct
		if (hash->base->flags & TMS_FIXED){
			try (vsize <= hash->base->elem_size);
		}

		// if we are dynamic/heap alloc, we resize as needed
		else if (vsize != node->usrSize - hash->base->hdr_size){

			// remove from hash table
			_unlink_node(hash->pool, &node->data, table);

			// add to pool list
			_link_tail(hash->pool, &node->data, &hash->pool->alloc_list);

			// save the node in case we need to restore
			tmp_node = node;

			// empty
			node = NULL;
			hdr = NULL;
		}
	}

	// no node, we have to alloc and link to table
	if (!node) {

		// point to our hdr
		catch_if (!(hdr = (TmsHashHdrT *) _pool_alloc(hash->pool, hash->base->hdr_size + vsize, 0, msec, 0)));

		// our node
		node = (TmsMemT *)((uint8_t *) hdr - TMS_MEM_NODE_SIZE);

		// unlink from pool table
		_unlink_node(hash->pool, &node->data, &hash->pool->alloc_list);

		// link to the hash table
		_link_tail(hash->pool, &node->data, table);

		// count collisions
		if (table->cnt > 1){
			hash->base->collisions++;
			//if (table->cnt > 2)TMS_DEBUG("XXXXXXXX collision %s, %d\n", (char *)vkey, table->cnt);
		}

		// copy our key
		memcpy(hdr->key, vkey, ksize);

		// save our hash
		hdr->full_hash = full_hash;

		// we no longer need this
		if (tmp_node){
			_tms_free(hash->pool, tmp_node, 1);
		}
	}

	// copy our value into hash table
	memcpy((uint8_t *) hdr + hash->base->hdr_size, vbuf, vsize);

	// update sequence number
	hdr->seq_num = seq_num + 1;

	// signal to pending readers
	if (lock->read_is_pending){
		//TMS_DEBUG("BROADCAST TO READERS %d\n", lock->read_is_pending);
		pthread_cond_broadcast(&lock->read_cv);
	}

	// clear locks
	_mutex_unlock(&lock->cv_mutex);
	_rwlock_unlock(&lock->rw_lock);
	_rwlock_unlock(&lock->del_lock);
	return 0;

	catch:
	// restore this if needed
	if (tmp_node){
		_unlink_node(hash->pool, &tmp_node->data, &hash->pool->alloc_list);
		_link_tail(hash->pool, &tmp_node->data, table);
	}
	_mutex_unlock(&lock->cv_mutex);
	_rwlock_unlock(&lock->rw_lock);
	_rwlock_unlock(&lock->del_lock);
	return -1;
}

int TmsHashUnlink(TmsHashT *hash, void *key, int ksize)
{
	TmsHashLockT *lock;
	TmsMemT *node = NULL;
	TmsHashTableT *table = NULL;
	uint8_t *vkey = (uint8_t *) key;
	uint32_t full_hash;

	try (hash && key);

	// get the hash
	try (!_hash_by_type (hash, vkey, &ksize, &full_hash, &table, &lock));

	// lock out the writers and readers
	_rwlock_wrlock(&lock->del_lock);

	// get the node
	try (node = _hash_find (hash, vkey, ksize, full_hash, table));

	// is node valid?
	TMS_NODE_PASS(node);

	// remove from hash table
	_unlink_node(hash->pool, &node->data, table);

	// add to pool list
	_link_tail(hash->pool, &node->data, &hash->pool->alloc_list);

	// adjust collision cnt
	if (table->cnt > 0){
		hash->base->collisions--;
	}

	// free the data
	_tms_free(hash->pool, node, 1);

	// clear locks
	_rwlock_unlock(&lock->del_lock);
	return 0;

	catch:
	_rwlock_unlock(&lock->del_lock);
	return -1;
}

static void *_hash_thread(void *arg)
{
	TmsHashStateT *state = (TmsHashStateT *) arg;
	int rc = 0;

	while(rc >= 0 && !(rc & TMS_CB_EXIT)){
		rc = state->flags & TMS_HASH_RMW ? TmsHashStateReadWrite(state, NULL, 0) : TmsHashStateRead(state, NULL, 0);
	}
	return NULL;
}

pthread_t *TmsHashThreadCreate (TmsHashStateT *state, int flags, void (*cleanup)(void *))
{
	try (state);
	try (state-> flags & (TMS_HASH_READ | TMS_HASH_RMW));

	return TmsThreadCreate(_hash_thread, flags, state, cleanup);

	catch:
	return NULL;
}

int TmsHashThreadDestroy(pthread_t *pthread)
{
	return TmsThreadDestroy(pthread);
}

TmsHashStateT *TmsHashStateCreate (TmsHashT *hash, void *key, int ksize, int flags, int msec)
{
	TmsHashStateT *state;

	try (hash && key);
	try (state = _tms_malloc(NULL, sizeof(TmsHashStateT), 0, 0));

	// clear it out
	memset(state, 0, sizeof(TmsHashStateT));

	// init vars
	state->key = key;
	state->hash = hash;
	state->ksize = ksize;
	state->flags = flags;
	state->msec = msec < 0 ? -1 : msec;
	_mutex_create(&state->mutex, 0);

	// compute hash, find table root node
	try (!_hash_by_type (hash, (uint8_t *)key, &state->ksize, &state->full_hash, &state->table, &state->lock));

	return state;

	catch:
	return NULL;
}

int TmsHashStateCallback(TmsHashStateT *state, TmsHashCallbackT cb, void *arg, int flags)
{
	state->cb = cb;
	state->arg = arg;
	state->flags |= flags;
	return 0;
}

int TmsHashStateDestroy(TmsHashStateT *state)
{
	return TmsFree(state);
}

int TmsHashClose(TmsHashT *hash)
{
	TmsMemT *node;

	try (hash && TMS_OBJ_PASS(hash->base, TMS_OBJ_HASH));
	try (!_name_close(hash->base));
	node = (TmsMemT *) ((uint8_t *) hash - TMS_MEM_NODE_SIZE);
	try (!_tms_free(NULL, node, 0));
	return 0;

	catch:
	return -1;
}

// destroy a hash table
int TmsHashDestroy (char *name)
{
	TmsHashLockT *lock;
	TmsHashBaseT *base;
	TmsPoolT *pool;
	int i;

	// open the table
	try (base = (TmsHashBaseT *) _name_open(name, TMS_RDWR, 0));
	try (TMS_OBJ_PASS(base, TMS_OBJ_HASH));

	// make sure we used create
	try (base->use_destroy);

	// destroy the list locks
	lock = (TmsHashLockT *) ((uint8_t *) base + base->locks);
	for (i=0; i<=base->section_mask; i++){
		try (!_hash_lock_destroy(&lock[i]));
	}

	// our pool
	pool = (TmsPoolT *) ((uint8_t *) base + base->pool);

	// free up heap allocations
	_pool_free_heap(pool);

	// destroy the pool lock
	_mutex_destroy(&pool->mutex);

	// finally free the name list
	try (!_name_destroy(name));
	return 0;

	catch:
	return -1;
}

static int _list_flush_ttl(TmsListT *plist, int lock)
{
	CatchAndRelease;
	TmsListCtlT *list;
	TmsMemT *node;
	TmsPoolT *pool;
	int i, cnt;

	list = plist->write_list;
	if (!list->ttl_msec){
		return 0;
	}

	pool = plist->list_wpool;

	if (lock){
		_mutex_set (LOCK1, &list->header.lock.mutex);
		_mutex_set (LOCK2, &pool->mutex);
	}

	for (i=0; i<=TMS_LIST_PRI_MAX; i++) {
		cnt = list->pri[i].cnt;
		while (cnt--){

			// remove a node
			node = _unlink_head(pool, &list->pri[i]);

			// did we exceed our timeout? put back on pool alloc list and free
			if (_msec_is_elapsed(&node->data.ts, list->ttl_msec)){
				_link_tail(pool, &node->data, &pool->alloc_list);
				try (!_tms_free(pool, node, 0));
				list->qcnt--;
			}
			// else, place back on the list
			else{
				_link_tail(pool, &node->data, &list->pri[i]);
			}
		}
	}

	if (lock){
		_mutex_clr(LOCK2, &pool->mutex);
		_mutex_clr(LOCK1, &list->header.lock.mutex);
	}
	return 0;

	catch:
	_release_mutex(LOCK2, &pool->mutex);
	_release_mutex(LOCK1, &list->header.lock.mutex);
	return -1;
}

static int _list_reap(TmsListT *plist)
{
	_list_flush_ttl(plist, 1);
	_pool_alloc_flush_tid(plist->list_wpool, 1);
	return 0;
}

static size_t _list_ctlsize(int num, int flags)
{
	int duplex = TMS_IS_DUPLEX(flags);
	int ringsize = flags & TMS_RING ? TMS_RING_ARRAY_SIZE(num) : 0;
	return duplex * (TMS_LIST_CTL_SIZE + ringsize);
}

static size_t _list_poolsize(int num, size_t size, int flags)
{
	int duplex = TMS_IS_DUPLEX(flags);
	if (flags & TMS_NOCOPY){
		return _pool_create_size(duplex * num, size, flags);
	}
	else{
		return duplex * _pool_create_size(num, size, flags);
	}
}

size_t TmsListCreateSize(int num, size_t size, int flags)
{
	size_t poolsize;
	size_t ctlsize;
	size_t totsize;

	if (!size || !num){
		return 0;
	}

	// get our list ctl size
	ctlsize = _list_ctlsize(num, flags);

	// get our pool size
	poolsize = _list_poolsize(num, size, flags);

	// add it all up
	totsize = TMS_ALIGN_SIZE(TMS_LIST_BASE_SIZE + ctlsize + poolsize, TMS_ALIGN_DEFAULT);

	return totsize;
}

TmsListBaseT *TmsListInit(void *ptr, int num_elem, size_t size, mode_t perm, int ttl, int flags)
{
	int duplex = TMS_IS_DUPLEX(flags);
	TmsListCtlT *list[2];
	TmsListBaseT *base;
	size_t offset;
	int i;
	uint8_t *ring, *pool;

	try(ptr);
	base = (TmsListBaseT *) ptr;
	memset(base, 0, sizeof(TmsListBaseT));

	base->guard = TMS_MEM_GUARD | TMS_OBJ_LIST;
	base->flags = flags;
	base->pool_elem = num_elem;
	base->size = size;
	base->ttl = ttl;
	base->perm = perm;
	base->self = ptr;
	base->use_destroy = 0;

	offset = TMS_LIST_BASE_SIZE;

	for (i=0; i<duplex; i++) {

		list[i] = (TmsListCtlT *) ((uint8_t *) base + offset);
		memset(list[i], 0, sizeof(TmsListCtlT));

#ifdef TMS_USE_ALIGN_CHECK
		TMS_ASSERT(ALIGN_IS_VALID(list[i], TMS_ALIGN_DEFAULT));
#endif

		try(!_list_lock_create(&list[i]->header.lock, flags));
		list[i]->base = (uint8_t *) list[i] - (uint8_t *) ptr;
		list[i]->header.flags = flags;
		list[i]->num_elem = num_elem;
		list[i]->size = size;
		list[i]->ttl_msec = ttl;
		list[i]->self = list[i];
		offset += TMS_LIST_CTL_SIZE;

		if (flags & TMS_RING){
			ring = (uint8_t *) base + offset;

#ifdef TMS_USE_ALIGN_CHECK
			TMS_ASSERT(ALIGN_IS_VALID(ring, TMS_ALIGN_DEFAULT));
#endif

			list[i]->ring_buf = ring - (uint8_t *) list[i];
			offset += TMS_RING_ARRAY_SIZE(list[i]->num_elem);
		}
	}

	if (!(flags & TMS_LINK)){

		pool = TMS_ALIGN_PTR(((uint8_t *) base + offset), TMS_ALIGN_POOL);

	#ifdef TMS_USE_ALIGN_CHECK
				TMS_ASSERT(ALIGN_IS_VALID(pool, TMS_ALIGN_POOL));
	#endif

		if (flags & TMS_NOCOPY){
			try (TmsPoolInit(pool, duplex * num_elem, size, flags));
			list[0]->pool = (uint8_t *) pool - (uint8_t *) list[0];

			if (flags & TMS_DUPLEX){
				list[1]->pool = (uint8_t *) pool - (uint8_t *) list[1];
			}
		}
		else {
			try (TmsPoolInit(pool, num_elem, size, flags));
			list[0]->pool = (uint8_t *) pool - (uint8_t *) list[0];

			if (flags & TMS_DUPLEX){
				offset += _pool_create_size(num_elem, size, flags);
				pool = TMS_ALIGN_PTR(((uint8_t *) base + offset), TMS_ALIGN_POOL);

	#ifdef TMS_USE_ALIGN_CHECK
				TMS_ASSERT(ALIGN_IS_VALID(pool, TMS_ALIGN_POOL));
	#endif

				try (TmsPoolInit(pool, num_elem, size, flags));
				list[1]->pool = (uint8_t *) pool - (uint8_t *) list[1];
			}
		}
	}

	if (flags & TMS_DUPLEX){
		base->writeA  = (uint8_t *) list[0] - (uint8_t *) base;
		base->readA = (uint8_t *) list[1] - (uint8_t *) base;
		base->writeB  = base->readA;
		base->readB = base->writeA;
	}
	else {
		base->writeA  = (uint8_t *) list[0] - (uint8_t *) base;
		base->readA = base->writeA;
		base->writeB  = 0;
		base->readB = 0;
	}
	return base;

	catch:
	return NULL;
}

int TmsListCreate (char *name, int num_elem, size_t size, int ttl, int flags, mode_t perm)
{
	void *ptr = NULL;
	size_t list_size;
	TmsListBaseT *base;
	CatchAndRelease;

	//TMS_DEBUG("%s\n", flags & TMS_DUPLEX ? "FULL DUPLEX" : "HALF DUPLEX");
	try (!_list_flags(name, &flags, perm));
	list_size = TmsListCreateSize(num_elem, size, flags);

	if (flags & TMS_SHARED){
		try_set (CREATE1, !TmsShmCreate(name, list_size, flags, perm));
		try_set (OPEN1, ptr = _name_open(name, TMS_RDWR, 0));
		try (base = TmsListInit(ptr, num_elem, size, perm, ttl, flags));
		strcpy(base->name, name);
		base->use_destroy = 1;
		_name_close(ptr);
	}
	else{
		try_set (CREATE1, (ptr = _name_malloc(name, NULL, list_size, flags, 0)));
		try (base = TmsListInit(ptr, num_elem, size, 0, ttl, flags));
		strcpy(base->name, name);
		base->use_destroy = 1;
	}
	return 0;

	catch:
	release (CREATE1, _name_destroy(name));
	return -1;
}

int TmsListLink (char *link, char *name, int flags, int msec)
{
	TmsListCtlT *list1, *list2;
	void *ptr = NULL;
	size_t list_size;
	TmsListBaseT *base1=NULL, *base2=NULL;
	CatchAndRelease;

	//TMS_DEBUG("CREATE %s\n", flags & TMS_DUPLEX ? "FULL DUPLEX LINK" : "HALF DUPLEX LINK");

	try_set (OPEN1, base1 = (TmsListBaseT *) _name_open(name, TMS_RDWR, msec));
	try (TMS_OBJ_PASS(base1, TMS_OBJ_LIST));

	try (base1->flags & TMS_NOCOPY);
	try (!_link_flags(name, &flags, base1->perm));

	// link size = list size without pool
	flags |= TMS_LINK | TMS_NOCOPY;
	list_size = TmsListCreateSize(base1->pool_elem, base1->size, flags);

	// alloc memory for the new link
	if (flags & TMS_SHARED){
		try_set (CREATE1, !TmsShmCreate(link, list_size, flags, base1->perm));
		try (ptr = _name_open(link, TMS_RDWR, 0));
		try (base2 = TmsListInit(ptr, base1->pool_elem, base1->size, base1->perm, base1->ttl, flags));
	}
	else{
		try_set (CREATE1, (ptr = _name_malloc(link, NULL, list_size, flags, 0)));
		try (base2 = TmsListInit(ptr, base1->pool_elem, base1->size, 0, base1->ttl, flags));
	}
	base2->use_destroy = 1;

	// save our link name
	strcpy(base2->name, link);

	// save our pool list
	strcpy(base2->linkedto, name);

	// set the pool pointers for the link to the original list
	list1 = (TmsListCtlT *) ((uint8_t *) base1 + base1->readA);
	list2 = (TmsListCtlT *) ((uint8_t *) base2 + base2->readA);
	list2->pool = list1->pool;

	list1 = (TmsListCtlT *) ((uint8_t *) base1 + base1->writeA);
	list2 = (TmsListCtlT *) ((uint8_t *) base2 + base2->writeA);
	list2->pool = list1->pool;

	list1 = (TmsListCtlT *) ((uint8_t *) base1 + base1->readB);
	list2 = (TmsListCtlT *) ((uint8_t *) base2 + base2->readB);
	list2->pool = list1->pool;

	list1 = (TmsListCtlT *) ((uint8_t *) base1 + base1->writeB);
	list2 = (TmsListCtlT *) ((uint8_t *) base2 + base2->writeB);
	list2->pool = list1->pool;

	if (flags & TMS_SHARED){
		_name_close(ptr);
	}
	_name_close(base1);
	return 0;

	catch:
	TMS_ERROR("unable to link %s to %s\n", name, link);
	release (CREATE1, _name_destroy(link));
	release (OPEN1, _name_close(name));
	return -1;
}

TmsListT *TmsListOpen (char *name, int flags, int msec)
{
	TmsListBaseT *base = NULL;
	TmsListBaseT *base2 = NULL;
	size_t poolsize;
	TmsListT *list = NULL;
	TmsListCtlT *write_link, *read_link;
	void *rptr=NULL, *wptr=NULL;
	int bitcnt;
	CatchAndRelease;

	try_set (OPEN1, base = (TmsListBaseT *) _name_open(name, TMS_RDWR, msec));
	try (TMS_OBJ_PASS(base, TMS_OBJ_LIST));
	try (!((flags & TMS_OPEN_B) && !(base->flags & TMS_DUPLEX)));

	if (base->flags & TMS_NOCOPY){
		try ((flags & TMS_LIST_NOCOPY_FLAGS) == flags);
	}
	else {
		try ((flags & TMS_LIST_OPEN_FLAGS) == flags);
		try (_bit_count(flags & TMS_ALIGN_FLAGS) < 2);
		try ((bitcnt = _bit_count(flags & TMS_POOL_FLAGS)) < 2);
		if (!bitcnt){
			flags |= TMS_HEAP;
		}
		if (base->flags & TMS_RING){
			flags |= TMS_COPY_OUT;
		}
	}

	try_set (ALLOC1, list = _tms_malloc(NULL, sizeof(TmsListT), 0, 0));
	memset(list, 0, sizeof(TmsListT));

	if (flags & TMS_RING){
		_mutex_create(&list->ring_mutex, 0);
	}

	flags |= base->flags & (TMS_LINK | TMS_NOCOPY);
	list->open_flags = flags;
	list->base = base;

	if (flags & TMS_OPEN_B) {
		list->write_list = (TmsListCtlT *) ((uint8_t *) base + base->writeB);
		list->read_list = (TmsListCtlT *) ((uint8_t *) base + base->readB);
	}
	else {
		list->write_list = (TmsListCtlT *) ((uint8_t *) base + base->writeA);
		list->read_list = (TmsListCtlT *) ((uint8_t *) base + base->readA);
	}

	list->write_pool = NULL;
	list->read_pool = NULL;

	if (!(flags & TMS_LINK)){
		list->list_wpool = (TmsPoolT *) ((uint8_t *) list->write_list + list->write_list->pool);
		list->list_rpool = (TmsPoolT *) ((uint8_t *) list->read_list + list->read_list->pool);
		//list->write_pool = list->list_wpool;
		//list->read_pool = list->list_rpool;

		if (!(flags & TMS_NOCOPY)){
			if (!(flags & TMS_RDONLY)){
				poolsize = _pool_create_size(base->pool_elem, base->size, flags);
				try_set (ALLOC2, wptr = _tms_malloc(NULL, poolsize, flags, 0));
				try (list->write_pool = TmsPoolInit(wptr, base->pool_elem, base->size, flags));
			}

			if (!(flags & TMS_WRONLY) && (flags & TMS_COPY_OUT)){
				poolsize = _pool_create_size(base->pool_elem, base->size, flags);
				try_set (ALLOC3, rptr = _tms_malloc(NULL, poolsize, flags, 0));
				try (list->read_pool = TmsPoolInit(rptr, base->pool_elem, base->size, flags));
			}
		}
		else if (!(flags & TMS_WRONLY)){
			list->read_pool = list->list_rpool;
		}
		else if (!(flags & TMS_RDONLY)){
			list->write_pool = list->list_wpool;
		}
	}

	// we link to the originating list pool
	else {
		try_set (OPEN2, base2 = (TmsListBaseT *) _name_open(base->linkedto, TMS_RDWR, msec));
		try (TMS_OBJ_PASS(base2, TMS_OBJ_LIST));

		// full duplex B side
		if (flags & TMS_OPEN_B){
			write_link = (TmsListCtlT *) ((uint8_t *) base2 + base2->writeB);
			read_link = (TmsListCtlT *) ((uint8_t *) base2 + base2->readB);
		}

		// full duplex A side
		else if (flags & TMS_DUPLEX){
			write_link = (TmsListCtlT *) ((uint8_t *) base2 + base2->writeA);
			read_link = (TmsListCtlT *) ((uint8_t *) base2 + base2->readA);
		}

		// single duplex, just one list (we use A side)
		else {
			write_link = (TmsListCtlT *) ((uint8_t *) base2 + base2->writeA);
			read_link = (TmsListCtlT *) ((uint8_t *) base2 + base2->readA);
		}

		list->link = base2;
		list->list_wpool = (TmsPoolT *) ((uint8_t *) write_link + write_link->pool);
		list->list_rpool = (TmsPoolT *) ((uint8_t *) read_link + read_link->pool);
		list->write_pool = !(flags & TMS_RDONLY) ? list->list_wpool : NULL;
		list->read_pool = !(flags & TMS_WRONLY) ? list->list_rpool : NULL;
	}

	//TMS_DEBUG("%s %s read %p / %p, write %p / %p\n",
		//	base->name, flags & TMS_LINK ? "LINK" : "NOT LINK",
		//	list->read_list->self, list->list_rpool->self,
		//	list->write_list->self, list->list_wpool->self);

	return list;

	catch:
	release(OPEN2, _name_close(base2));
	release(ALLOC2, TmsFree(wptr));
	release(ALLOC3, TmsFree(rptr));
	release(ALLOC1, TmsFree(list));
	return NULL;
}

int TmsListClose(TmsListT *list)
{
	TmsMemT *node;

	//TMS_DEBUG("list %p close, r %p, w %p\n", list, list->read_pool, list->write_pool);

	// make sure we have a valid list
	try (list && TMS_OBJ_PASS(list->base, TMS_OBJ_LIST));

	// close the list we are linked to
	if (list->base->flags & TMS_LINK){
		try (TMS_OBJ_PASS(list->link, TMS_OBJ_LIST));
		try (!_name_close(list->link));
	}

	// destroy our intra-thread lock
	if (list->base->flags & TMS_RING){
		_mutex_destroy(&list->ring_mutex);
	}

	// close the named obj (shm or heap)
	try (!_name_close(list->base));

	// free up any lingering allocs from our local write
	if (list->write_pool && !(list->open_flags & TMS_NOCOPY)){
		try (!_pool_free_heap(list->write_pool));
		try (!TmsFree(list->write_pool));
	}

	// free up any lingering allocs from our local read pool
	if (list->read_pool && (list->open_flags & TMS_COPY_OUT)){
		try (!_pool_free_heap(list->read_pool));
		try (!TmsFree(list->read_pool));
	}

	// free up our context
	node = (TmsMemT *) ((uint8_t *) list - TMS_MEM_NODE_SIZE);
	try (!_tms_free(NULL, node, 0));
	return 0;

	catch:
	return -1;
}

static int _list_flush(TmsListCtlT *list)
{
	TmsMemT *node;
	TmsPoolT *pool;
	int i;

	pool = (TmsPoolT *) ((uint8_t *) list + list->pool);
	for (i=0; i<=TMS_LIST_PRI_MAX; i++) {

		while (list->pri[i].cnt){
			node = _unlink_head(pool, &list->pri[i]);
			_link_tail(pool, &node->data, &pool->alloc_list);
			try (!_tms_free(pool, node, 0));
			list->qcnt--;
		}
	}
	return 0;

	catch:
	return -1;
}

void _list_pool_cleanup(TmsListCtlT *list)
{
	TmsPoolT *pool;

	if (list->header.flags & TMS_LINK){
		return;
	}

	// our pool
	pool = (TmsPoolT *) ((uint8_t *) list + list->pool);

	// free up any unqueued allocations
	_pool_free_heap(pool);

	// destroy the pool lock
	_mutex_destroy(&pool->mutex);
}

static int _list_cleanup(TmsListBaseT *base)
{
	CatchAndRelease;
	TmsPoolT *pool;
	int duplex;
	int i, flags;
	TmsListCtlT *list;

	// list flags
	flags = base->flags;

	// duplex?
	duplex = TMS_IS_DUPLEX(flags);

	// we clear each leg of the list
	list = (TmsListCtlT *) ((uint8_t *) base + base->writeA);
	pool = (TmsPoolT *) ((uint8_t *) list + list->pool);
	for (i=0; i<duplex; i++) {

		// flush the list, clear the ring
		if (!(base->flags & TMS_LINK)){
			_wrlock_set (LOCK1, &list->header.lock.rwlock);
			_mutex_set (LOCK2, &list->header.lock.mutex);
			_mutex_set (LOCK3, &pool->mutex);

			try(!_list_flush(list));
			memset(list->ring_pub, 0, sizeof(list->ring_pub));

			_mutex_clr (LOCK3, &pool->mutex);
			_mutex_clr (LOCK2, &list->header.lock.mutex);
			_rwlock_clr (LOCK1, &list->header.lock.rwlock);
		}

		// destroy the list locks
		try (!_list_lock_destroy(&list->header.lock, flags));

		if (i == 0){
			_list_pool_cleanup(list);
		}
		else if (!(flags & TMS_NOCOPY)){
			_list_pool_cleanup(list);
		}

		// our other duplex list
		list = (TmsListCtlT *) ((uint8_t *) base + base->writeB);
		pool = (TmsPoolT *) ((uint8_t *) list + list->pool);
	}
	return 0;

	catch:
	_release_mutex (LOCK3, &pool->mutex);
	_release_mutex (LOCK2, &list->header.lock.mutex);
	_release_rwlock (LOCK3, &list->header.lock.rwlock);
	return -1;
}

int TmsListDestroy (char *name)
{
	TmsListBaseT *base;

	// open the list
	try (base = (TmsListBaseT *) _name_open(name, TMS_RDWR, 0));
	try (TMS_OBJ_PASS(base, TMS_OBJ_LIST));

	// make sure we used create
	try (base->use_destroy);

	// reset the list
	try (!_list_cleanup(base));

	// finally free the list
	try (!_name_destroy(name));
	return 0;

	catch:
	return -1;
}

int TmsListProps(TmsListT *plist, TmsListPropsT *props)
{
	TmsPoolT *pool;
	try (TMS_LIST_PASS(plist));

	_mutex_lock(&plist->read_list->header.lock.mutex);
	pool = plist->list_rpool;
	props->read_size = plist->read_list->size;
	props->read_num_elem = plist->read_list->num_elem;
	props->read_queue_cnt = plist->read_list->qcnt;
	props->read_alloc_cnt = pool->alloc_list.cnt;
	props->read_flags = plist->read_list->header.flags;
	props->read_seq_num = plist->read_list->seq_num;
	props->read_cnt = plist->read_cnt;
	_mutex_unlock(&plist->read_list->header.lock.mutex);

	_mutex_lock(&plist->write_list->header.lock.mutex);
	pool = plist->list_wpool;
	props->write_size = plist->write_list->size;
	props->write_num_elem = plist->write_list->num_elem;
	props->write_queue_cnt = plist->write_list->qcnt;
	props->write_alloc_cnt = pool->alloc_list.cnt;
	props->write_flags = plist->write_list->header.flags;
	props->write_seq_num = plist->write_list->seq_num;
	props->write_cnt = plist->write_cnt;
	_mutex_unlock(&plist->write_list->header.lock.mutex);
	return 0;

	catch:
	return -1;
}

static void *_list_alloc (TmsListT *plist, size_t size, int flags, int msec, int reap)
{
	TmsPoolT *pool;
	void *ptr;

	pool = plist->list_wpool;

	// alloc from list pool
	if (!(ptr = _tms_malloc(pool, size, flags, 1))){

		// if we failed to alloc, we are out of mem
		// try to reap orphaned memory
		if (reap){
			_list_reap(plist);
		}

		// lock the pool
		_mutex_lock(&pool->mutex);

		// wait for alloc
		//TMS_DEBUG("list %p, pool %p, wait for malloc\n", plist->write_list->self, pool->self);
		CV_WAIT(
			&pool->cv, &pool->mutex,
			ptr = _tms_malloc(pool, size, flags, 0),
			pool->alloc_is_pending,
			msec
		);

		// unlock the pool
		_mutex_unlock(&pool->mutex);
	}
	return ptr;
}

// writes element on list
static int _ring_write (TmsListT *plist, void *data, int priority, int msec)
{
	TmsListCtlT *list;
	TmsPoolT *pool;
	TmsMemT *node;
	TmsListLockT *lock = NULL;
	TmsRingT *ring_array;
	void *ptr=NULL;
	int flags, pri;
	CatchAndRelease;

	// priority
	try (priority <= TMS_LIST_PRI_MAX);

	// list control block
	list = plist->write_list;

	// our list pool
	pool = plist->list_wpool;

	// our locks
	lock = &list->header.lock;

	// list flags
	flags = list->header.flags;

	// point to ring array
	ring_array = (TmsRingT *) ((uint8_t *) list + list->ring_buf);

	// lock the list for readers
	_wrlock_set(LOCK1, &lock->rwlock);

	// lock the list for cv wait
	_mutex_set (LOCK2, &lock->mutex);

	// validate list
	try (TMS_LIST_PASS(plist));

	// if list is primed, we free the oldest element
	if (list->isPrimed) {

		// find oldest priority on queue
		pri = ring_array[list->seq_num];

		// find oldest element on queue
		node =_unlink_head(pool, &list->pri[pri]);

		// make sure we found a node
		TMS_NODE_PASS(node);

		//TMS_DEBUG("discarding head, pool %p, node %zx, pri %d, cnt %d, dis cnt %"PRIu64"\n",
			//	pool->self, node->data.obj, pri, list->pri[pri].cnt, list->ring_pub[pri].del_cnt);

		// count number of discards/wraps
		list->ring_pub[pri].del_cnt++;

		// lock the pool
		_mutex_set(LOCK3, &pool->mutex);

		// write node back on the allocation list
		_link_tail(pool, &node->data, &pool->alloc_list);

		// free the node
		try (!_tms_free(pool, node, 0));

		// unlock the pool
		_mutex_clr (LOCK3, &pool->mutex);

		// one less element
		list->qcnt--;
	}

	// our input data node
	node = (TmsMemT *) ((uint8_t *) data - TMS_MEM_NODE_SIZE);

	// allocate our copy buffer
	catch_if (!(ptr = _list_alloc(plist, node->usrSize, flags, msec, 0)));
	release_set (ALLOC1);

	// our new data node
	node = (TmsMemT *) ((uint8_t *) ptr - TMS_MEM_NODE_SIZE);

	// copy the data
	memcpy(ptr, data, node->usrSize);

	// we are a list node object
	node->guard |= TMS_OBJ_LISTNODE;

	// lock the pool
	_mutex_lock (&pool->mutex);

	// unlink from pool alloc list
	_unlink_node(pool, &node->data, &pool->alloc_list);

	// unlock the pool
	_mutex_unlock (&pool->mutex);

	// link to the queue
	_link_tail(pool, &node->data, &list->pri[priority]);

	// add pri to ring array
	ring_array[list->seq_num] = priority;

	// update pri cnt
	list->ring_pub[priority].add_cnt++;

	// our time stamp for time to live and benchmarking
	try (!clock_gettime(CLOCK_MONOTONIC, &node->data.ts));

	// one more on the list
	list->qcnt++;

	// total cnt
	list->write_cnt++;

	// instance cnt
	plist->write_cnt++;

	// adjust our sequence number
	if (list->seq_num == list->num_elem - 1){
		list->seq_num = 0;
		list->isPrimed = 1;
		tms_dbg("list is primed\n");
	}
	else{
		list->seq_num++;
	}

	//TMS_DEBUG("ring, write list %p, pri %d, pool %p, node: %p, node obj: 0x%zx\n",
		//	list->self, priority, pool->self, node, node->data.obj);

	// signal to pending readers
	if (lock->read_is_pending){
		//TMS_DEBUG("BROADCAST TO READERS %d\n", lock->read_is_pending);
		pthread_cond_broadcast(&lock->read_cv);
	}

	// unlock the list for cv wait
	_mutex_clr(LOCK2, &lock->mutex);

	// unlock the list for readers
	_rwlock_clr(LOCK1, &lock->rwlock);
	return 0;

	catch:
	_release_mutex (LOCK3, &pool->mutex);
	_release_mutex (LOCK2, &lock->mutex);
	_release_rwlock (LOCK1, &lock->rwlock);
	release (ALLOC1, TmsFree(ptr));
	return -1;
}

static TmsMemT *_ring_node(TmsListT *plist, TmsListCtlT *list, int *ipri)
{
	TmsMemT *node = NULL;
	TmsRingPubT *pub;
	TmsRingSubT *sub;
	TmsLinkT *link;
	ptrdiff_t next=0;
	int i;

	// search for highest priority node
	for (i=0; i<=TMS_LIST_PRI_MAX; i++){

		link = &list->pri[i];

		// our producer ring state
		pub = &list->ring_pub[i];

		// our local ring state
		sub = &plist->ring_sub[i];

		if (!link->head){
			if (sub->cnt < pub->add_cnt){
				//TMS_ERROR("PRI %d, LOST ALL DATA\n", i);
				sub->overrun += pub->add_cnt - sub->cnt;
			}
			sub->cnt = 0;
		}
		else{
			/*
			TMS_DEBUG("pri %d, pub %"PRIu64"/%"PRIu64", sub %"PRIu64"\n",
					i, pub->add_cnt, pub->del_cnt, sub->cnt);
			*/
			// do we have more data to read?
			if (pub->add_cnt > sub->cnt){
				/*
				TMS_DEBUG("pri %d, pub %"PRIu64"/%"PRIu64", sub %"PRIu64"\n",
						i, pub->add_cnt, pub->del_cnt, sub->cnt);
				*/
				// we were empty, now we have new data
				if (!sub->cnt || pub->del_cnt >= sub->cnt) {
					if (pub->del_cnt > sub->cnt){
						sub->overrun += (int)(pub->del_cnt - sub->cnt);
						/*
						TMS_ERROR("PRI %d, LOST SOME DATA %d/%d     \n",
						i, sub->overrun, (int)(pub->del_cnt - sub->cnt));
						*/
					}
					next = link->head;
					sub->cnt = pub->del_cnt + 1;
					//TMS_DEBUG("re-init, using head node obj 0x%zx\n", next);
				}
				// we have more to read before empty
				else  {
					next = sub->last_node->data.next;
					/*
					TMS_DEBUG("using last node %p/%zx, next 0x%zx, %d/%d/%d\n",
						sub->last_node, sub->last_node->data.obj, next,
						(int)pub->add_cnt, (int)pub->del_cnt, (int)sub->cnt);
					*/
					sub->cnt++;
				}

				// we should have data at this point
				node = (TmsMemT *) ((uint8_t *) plist->list_rpool + next);
				//TMS_DEBUG("pri %d, found node %p/%zx, no loss\n", i, node, node->data.obj);
				sub->last_node = node;
				*ipri = i;
				break;
			}
		}
	}

	//if (!node) TMS_DEBUG("NO DATA FOUND\n");
	return node;
}

// removes element from list
static void *_ring_read (TmsListT *plist, size_t *size, int *pri, int msec)
{
	TmsListCtlT *list;
	TmsMemT *node = NULL;
	TmsListLockT *lock;
	int flags;
	void *ptr;
	int ipri;
	CatchAndRelease;

	// our local linked list structure
	list = plist->read_list;

	// our locks
	lock = &list->header.lock;

	// flags
	flags = list->header.flags;

	// protect list from readers sharing same context
	_mutex_set(LOCK3, &plist->ring_mutex);

	// protect the list from writers
	_rdlock_set (LOCK1, &lock->rwlock);

	// validate list
	try (TMS_LIST_PASS(plist));

	//TMS_DEBUG("read qcnt: %d, pool %p\n", list->qcnt, plist->list_rpool->self);

	// wait for a something to show up on list
	if (!(node = _ring_node(plist, list, &ipri))) {

		// protect from writers and cv wait
		_mutex_set (LOCK2, &lock->mutex);

		// allow writers (once in cv wait)
		_rwlock_clr (LOCK1, &lock->rwlock);

		//TMS_DEBUG("CV WAIT\n");
		catch_if (CV_WAIT(
			&lock->read_cv,
			&lock->mutex,
			node = _ring_node(plist, list, &ipri),
			lock->read_is_pending,
			msec));

		//TMS_DEBUG("GOT DATA FROM CV WAIT\n");
	}

	//TMS_DEBUG("ring, read list %p, pri %d, pool %p, node: %p, node obj: 0x%zx\n",
		//	list->self, ipri, plist->list_rpool->self, node, node->data.obj);

	// validate node
	TMS_NODE_PASS(node);

	// update our local seq num
	plist->seq_num = plist->seq_num == list->num_elem - 1 ? 0 : plist->seq_num + 1;

	// count for this instance
	plist->read_cnt++;

	// make sure we can alloc a copy buffer
	// alloc from local pool
	catch_if (!(ptr = _pool_alloc(plist->read_pool, node->usrSize, flags, msec, 0)));

	// copy data from the list to the user buf
	memcpy(ptr, (uint8_t *) node + TMS_MEM_NODE_SIZE, node->usrSize);

	// return the size
	if (size){
		*size = node->usrSize;
	}

	// return the priority
	if (pri){
		*pri = ipri;
	}

	// unlock for cv wait
	if (tms_is_set(LOCK2)){
		_mutex_clr(LOCK2, &lock->mutex);
	}
	// unlock for writers
	else{
		_rwlock_clr(LOCK1, &lock->rwlock);
	}

	// unlock for readers sharing same context
	_mutex_clr(LOCK3, &plist->ring_mutex);
	return ptr;

	catch:
	_release_mutex (LOCK2, &lock->mutex);
	_release_rwlock (LOCK1, &lock->rwlock);
	_release_mutex (LOCK3, &plist->ring_mutex);
	return NULL;
}

void *TmsListAlloc (TmsListT *plist, size_t size, int msec)
{
	TmsListCtlT *list;
	TmsMemT *node;
	int flags;
	void *ptr;
	int objflags = 0;

	// validate list
	try (TMS_LIST_PASS(plist));

	// make sure we can write to list
	try (!(plist->open_flags & TMS_RDONLY));

	// our local linked list structure
	list = plist->write_list;

	// make sure we are doing something reasonable
	try (size <= list->size * list->num_elem);

	// list flags
	flags = list->header.flags;

	// default object flags
	objflags = TMS_OBJ_LISTNODE;

	// alloc from list pool
	if (flags & TMS_NOCOPY){
		catch_if (!(ptr = _list_alloc(plist, size, flags, msec, 1)));
		objflags |= TMS_OBJ_NOCOPY;
	}
	else{
		catch_if (!(ptr = _pool_alloc(plist->write_pool, size, flags, msec, 0)));
	}

	// where our node starts
	node = (TmsMemT *) ((uint8_t *) ptr - TMS_MEM_NODE_SIZE);

	tms_dbg("pool node data obj: 0x%zx\n", node->data.obj);

	// we are a list node object
	node->guard |= objflags;

	tms_dbg("list node data obj: 0x%zx\n", node->data.obj);
	return ptr;

	catch:
	return NULL;
}

// writes element on list
int TmsListWrite (TmsListT *plist, void *data, size_t size, int priority, int msec)
{
	int rc;
	TmsPoolT *pool;
	TmsListCtlT *list;
	TmsMemT *node;
	TmsListLockT *lock = NULL;
	void *ptr=NULL;
	int flags;
	CatchAndRelease;

	// validate args
	try (data);

	// validate list
	try (TMS_LIST_PASS(plist));

	// make sure we can write to list
	try (!(plist->open_flags & TMS_RDONLY));

	// make sure we have proper list
	list = plist->write_list;

	// ring buffer?
	if (list->header.flags & TMS_RING){
		rc = _ring_write(plist, data, priority, msec);
		return rc;
	}

	// priority
	try (priority <= TMS_LIST_PRI_MAX);

	// our locks
	lock = &list->header.lock;

	// list flags
	flags = list->header.flags;

	// our list pool
	pool = plist->list_wpool;

	TMS_GUARD_PASS(pool);

#if 0
	{
		node = (TmsMemT *) ((uint8_t *) data - TMS_MEM_NODE_SIZE);
		TMS_DEBUG("write in, list %p, pool %p, pri %d, list node obj 0x%zx, node size %zd, user size %zd\n",
			list->self, pool->self, priority, node->data.obj, node->actSize, node->usrSize);
	}
#endif

	// in-place buffer will be queued on list
	if (flags & TMS_NOCOPY){

		node = (TmsMemT *) ((uint8_t *) data - TMS_MEM_NODE_SIZE);

		// this has to be a nocopy node
		try (TMS_OBJ_IS(node, TMS_OBJ_NOCOPY));
	}

	// copy into a new buffer
	else {

		// can we get a list element of the right size from pool?
		catch_if (!(ptr = _list_alloc(plist, size, flags, msec, 1)));

		// we may need to free this
		release_set(ALLOC1);

		// copy the data
		memcpy(ptr, data, size);

		// set node
		node = (TmsMemT *) ((uint8_t *) ptr - TMS_MEM_NODE_SIZE);
	}

	// validate node
	TMS_NODE_PASS(node);

	// we are a list node object
	node->guard |= TMS_OBJ_LISTNODE;

	// lock the list
	_mutex_set (LOCK1, &lock->mutex);

	// we have to check for room on queue
	if (list->qcnt >= list->num_elem){

		// unlock the list
		_mutex_clr (LOCK1, &lock->mutex);

		// reap orphaned elements
		_list_reap(plist);

		// lock the list
		_mutex_set (LOCK1, &lock->mutex);

		// try one more time, then give up
		catch_if (CV_WAIT(
			&lock->write_cv, &lock->mutex,
			list->qcnt < list->num_elem,
			lock->write_is_pending, msec
		));
	}

	// lock the pool
	_mutex_lock(&pool->mutex);

	// unlink from pool alloc list
	_unlink_node(pool, &node->data, &pool->alloc_list);

	// unlock the pool
	_mutex_unlock(&pool->mutex);

	// link to the queue
	_link_tail(pool, &node->data, &list->pri[priority]);

	// adjust our sequence number
	list->seq_num = list->seq_num == list->num_elem - 1 ? 0 : list->seq_num + 1;

	// one more on the list
	list->qcnt++;

	//TMS_DEBUG("WRITE %s, size %zd, qcnt %d, head %zx, cnt %d\n",
		//	plist->base->name, size, list->qcnt, list->pri[priority].head, list->pri[priority].cnt);

	// total cnt
	list->write_cnt++;

	// instance cnt
	plist->write_cnt++;

	// our time stamp for time to live and benchmarking
	try (!clock_gettime(CLOCK_MONOTONIC, &node->data.ts));

	// signal to pending readers
	if (lock->read_is_pending){
		//TMS_DEBUG("BROADCAST TO READ %d\n", lock->read_is_pending);
		pthread_cond_broadcast(&lock->read_cv);
	}
	//else {
		//TMS_DEBUG("NO ONE WATING\n");
	//}

	//TMS_DEBUG("write out, pri %d, qcnt %d, list node obj 0x%zx, node size %zd, user size %zd\n",
		//	priority, list->qcnt, node->data.obj, node->actSize, node->usrSize);

	// unlock the list
	_mutex_clr (LOCK1, &lock->mutex);
	return 0;

	catch:
	release (ALLOC1, TmsFree(ptr));
	_release_mutex (LOCK1, &lock->mutex);
	return -1;
}

// removes element from list
void *TmsListRead (TmsListT *plist, size_t *size, int *pri, int msec)
{
	TmsPoolT *pool;
	TmsListCtlT *list;
	TmsMemT *node = NULL;
	TmsListLockT *lock;
	int ipri;
	void *ptr, *ptr1;
	size_t tmp_size;
	int flags;
	CatchAndRelease;

	// validate list
	try (TMS_LIST_PASS(plist));

	// make sure we can read list
	try (!(plist->open_flags & TMS_WRONLY));

	// our linked list structure
	list = plist->read_list;

	// our pool
	pool = plist->list_rpool;

	// validate list
	try (TMS_LIST_PASS(plist));

	// validate the pool
	TMS_GUARD_PASS(pool);

	// our locks
	lock = &list->header.lock;

	// list flags
	flags = list->header.flags;

	if (flags & TMS_RING) {
		ptr = _ring_read(plist, size, pri, msec);
		return ptr;
	}

	// lock the list
	_mutex_set (LOCK1, &lock->mutex);

	//TMS_DEBUG("read in, list %p, pool %p, qcnt %d\n", list->self, pool->self, list->qcnt);

	// wait for a something to show up on list
	catch_if (CV_WAIT(
			&lock->read_cv,
			&lock->mutex,
			list->qcnt > 0,
			lock->read_is_pending,
			msec));

	// search for highest priority node
	for (ipri=0; ipri<=TMS_LIST_PRI_MAX; ipri++){
		if (list->pri[ipri].head){
			node =_unlink_head(pool, &list->pri[ipri]);
			break;
		}
	}

	try (ipri <= TMS_LIST_PRI_MAX);

	// make sure we found a node
	TMS_NODE_PASS(node);

	// we may use this later
	tmp_size = node->usrSize;

	// we now own the data
	if (!_tid){
		_tid = getpid();
	}

	// our thread id
	node->data.tid = _tid;

	// lock the pool
	_mutex_lock(&pool->mutex);

	// write node back on the allocation list
	_link_tail(pool, &node->data, &pool->alloc_list);

	// unlock the pool
	_mutex_unlock(&pool->mutex);

	tms_dbg("node obj: 0x%zx\n", node->data.obj);

	ptr = (uint8_t *) node + TMS_MEM_NODE_SIZE;

	// conventional list, copy out
	// copy the node, mark the node as not busy, not on list
	if (plist->open_flags & TMS_COPY_OUT) {

		TMS_GUARD_PASS(plist->read_pool);

		if ((ptr1 = _pool_alloc(plist->read_pool, node->usrSize, flags, msec, 0))){

			memcpy(ptr1, ptr, node->usrSize);

			// we can free this
			if (!(flags & TMS_NOCOPY)){
				try (!_tms_free(pool, node, 1));
			}

			// our buffer
			ptr = ptr1;

			node = (TmsMemT *) ((uint8_t *) ptr1 - TMS_MEM_NODE_SIZE);

			// this is a valid list node
			node->guard |= TMS_OBJ_LISTNODE;
		}

		// failed to alloc, restore node to list
		else {

			TMS_ERROR("failed to alloc copy out buf\n");

			// lock the pool
			_mutex_lock(&pool->mutex);

			// pull the node from the allocation list
			_unlink_node(pool, &node->data, &pool->alloc_list);

			// unlock the pool
			_mutex_unlock(&pool->mutex);

			// put back on the list
			_link_head(pool, &node->data, &list->pri[ipri]);

			goto catch;
		}
	}

	// notify anyone waiting to write
	if (lock->write_is_pending){
		//TMS_DEBUG("BROADCAST TO WRITE %d\n", lock->write_is_pending);
		pthread_cond_broadcast(&lock->write_cv);
	}

	// one less on the queue
	list->qcnt--;

	// total count
	list->read_cnt++;

	// count for this instance
	plist->read_cnt++;

	//TMS_DEBUG("read out, pri %d, qcnt %d, list node obj 0x%zx, node size %zd, user size %zd\n",
	//		ipri, list->qcnt, node->data.obj, node->actSize, node->usrSize);

	// unlock the list
	_mutex_clr (LOCK1, &lock->mutex);

	if (size){
		*size = tmp_size;
	}

	if (pri) {
		*pri = ipri;
	}
	return ptr;

	catch:
	_release_mutex (LOCK1, &lock->mutex);
	return NULL;
}

int TmsListWalk (TmsListT *plist, TmsListCallbackT callback, void *arg, int flags, int msec)
{
	CatchAndRelease;
	TmsListT *xlist;
	TmsMemT *node;
	TmsLinkT putback[TMS_LIST_PRI_MAX+1] = {0};
	int rc;
	TmsCbActionT action;
	void *data;
	size_t size;
	int pri=0, i, j;
	int pb_flag = 0;

	try (TMS_LIST_PASS(plist));
	try (!(plist->base->flags & TMS_RING));
	try_set (ALLOC1, xlist = _tms_malloc(NULL, sizeof(TmsListT), 0, 0));

	memcpy(xlist, plist, sizeof(TmsListT));

	// are we walking a "write" list on a full duplex connection?
	// if so, we need to walk the other leg since we can only read from the read list
	if ((flags & TMS_OPEN_B) && (plist->base->flags & TMS_DUPLEX)){
		xlist->read_list = plist->write_list;
		xlist->read_pool = plist->write_pool;
	}

	rc = 0;
	while((data = TmsListRead(xlist, &size, &pri, msec))) {

		action = callback(data, size, pri, arg, &rc);

		try (!(action & ~TMS_CB_MASK));

		if (action == TMS_CB_PUTBACK){
			node = (TmsMemT *) ((uint8_t *) data - TMS_MEM_NODE_SIZE);
 			_link_tail(xlist, &node->data, &putback[pri]);
 			pb_flag = 1;
		}
		else {
			TmsFree(data);
		}

		if (rc || (action & TMS_CB_EXIT)){
			break;
		}
	}

	// restore any putbacks to their proper list
	if (pb_flag){
		for (i=0; i<=TMS_LIST_PRI_MAX; i++){
			for (j=0; j<putback[i].cnt; j++){
				node = _unlink_head(xlist, &putback[i]);
				data = (void *) ((uint8_t *) node + TMS_MEM_NODE_SIZE);
				TmsListWrite(xlist, data, node->usrSize, i, msec);
				if (!(plist->base->flags & TMS_NOCOPY)){
					TmsFree(data);
				}
			}
		}
	}

	try (!TmsFree(xlist));
	return rc;

	catch:
	release (ALLOC1, TmsFree(xlist));
	return -1;
}

int TmsListFlush(TmsListT *plist)
{
	CatchAndRelease;
	TmsListCtlT *list;
	TmsPoolT *pool;
	int i;

	list = plist->read_list;

	if (list->header.flags & TMS_RING){
		_rwlock_rdlock(&list->header.lock.rwlock);
		for (i=0; i<=TMS_LIST_PRI_MAX; i++) {
			plist->ring_sub[i].cnt = list->ring_pub[i].add_cnt;
			plist->ring_sub[i].last_node = NULL;
		}
		_rwlock_unlock(&list->header.lock.rwlock);
	}
	else {
		pool = (TmsPoolT *) ((uint8_t *) list + list->pool);

		_mutex_set (LOCK1, &list->header.lock.mutex);
		_mutex_set (LOCK2, &pool->mutex);

		try(!_list_flush(list));

		_mutex_clr (LOCK2, &pool->mutex);
		_mutex_clr (LOCK1, &list->header.lock.mutex);
	}
	return 0;

	catch:
	_release_mutex (LOCK2, &pool->mutex);
	_release_mutex (LOCK1, &list->header.lock.mutex);
	return -1;
}

static void _threadEnder(void *arg)
{
	TmsThreadT *thread = (TmsThreadT *) arg;

	if (thread->cleanup){
		thread->cleanup(thread->user);
	}
	free(thread);
}

static void *_threadStarter(void *arg)
{
    //sigset_t set;
	TmsThreadT *thread;

	// dereference the starter
	thread = (TmsThreadT *) arg;

	// print info about this thread
	// TmsThreadInfo();

	//sigemptyset(&set);
	//sigaddset(&set, SIGRTMIN);
    //pthread_sigmask(SIG_UNBLOCK, &set, NULL);

	if (thread->cleanup){
		pthread_cleanup_push(_threadEnder, thread->user);
		thread->rc = thread->func(thread->user);
		pthread_cleanup_pop(1);
	}
	else{
		thread->rc = thread->func(thread->user);
	}

	if (thread->flags & TMS_THREAD_JOINABLE){
		error_if (pthread_mutex_lock(&thread->lock.mutex));
		thread->join = 1;
		error_if (pthread_cond_broadcast(&thread->lock.cv));
		error_if (pthread_mutex_unlock(&thread->lock.mutex));
	}
	else{
		thread->join = 1;
	}
	return NULL;
}

int TmsThreadJoin(pthread_t *pthread, int msec, void **rc)
{
	TmsThreadT *tms = (TmsThreadT *) pthread;
	TmsThreadLockT *lock;
	CatchAndRelease;

	try(TMS_OBJ_IS(tms, TMS_OBJ_THREAD));
	try (tms && (tms->flags & TMS_THREAD_JOINABLE));

	lock = &tms->lock;

	_mutex_set(LOCK1, &lock->mutex);
	catch_if (CV_WAIT (
			&lock->cv,
			&lock->mutex,
			tms->join,
			lock->is_pending,
			msec));
	_mutex_clr(LOCK1, &lock->mutex);

	if (rc){
		*rc = tms->rc;
	}

	try (!pthread_join(*pthread, NULL));
	return 0;

	catch:
	_release_mutex (LOCK1, &lock->mutex);
	return -1;
}

pthread_t *TmsThreadCreate (void *(*func) (void *), TmsThreadFlagT flags, void *arg, void (*cleanup)(void *))
{
	TmsThreadT *thread = NULL;
	struct sched_param sched;
	int policy;
	pthread_attr_t attr;
	CatchAndRelease;

	try (func);
	tms_set(LOCK1, _mutex_lock(&_fork_lock));

	thread = (TmsThreadT *) _tms_malloc(NULL, sizeof(TmsThreadT), 0, 0);
	thread->func = func;
	thread->user = arg;
	thread->cleanup = cleanup;
	thread->flags = flags;
	thread->join = 0;
	thread->guard = TMS_MEM_GUARD | TMS_OBJ_THREAD;

	// initialize attributes
	try_set (CREATE1, !pthread_attr_init(&attr));
	if (flags & TMS_THREAD_JOINABLE) {
		try (!pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE));
		try_set (CREATE2, !_cv_create(&thread->lock.cv, 0));
		try_set (CREATE3, !_mutex_create(&thread->lock.mutex, 0));
	}
	else {
		try (!pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED));
	}

	// set priority
	if (flags & TMS_THREAD_FIFO_PRILOW) {
		sched.sched_priority = TMS_RTPRIORITY_LOW;
		policy = SCHED_FIFO;
	}
	else if (flags & TMS_THREAD_FIFO_PRIMED) {
		sched.sched_priority = TMS_RTPRIORITY_MED;
		policy = SCHED_FIFO;
	}
	else if (flags & TMS_THREAD_FIFO_PRIHIGH) {
		sched.sched_priority = TMS_RTPRIORITY_HIGH;
		policy = SCHED_FIFO;
	}
	else if (flags & TMS_THREAD_RR_PRILOW) {
		sched.sched_priority = TMS_RTPRIORITY_LOW;
		policy = SCHED_RR;
	}
	else if (flags & TMS_THREAD_RR_PRIMED) {
		sched.sched_priority = TMS_RTPRIORITY_MED;
		policy = SCHED_RR;
	}
	else if (flags & TMS_THREAD_RR_PRIHIGH) {
		sched.sched_priority = TMS_RTPRIORITY_HIGH;
		policy = SCHED_RR;
	}
	else{
		sched.sched_priority =  0;
		policy = 0;
	}

	if (sched.sched_priority) {
		try (!pthread_attr_setinheritsched(&attr, PTHREAD_EXPLICIT_SCHED));
		try (!pthread_attr_setschedpolicy(&attr, policy));
		try (!pthread_attr_setschedparam(&attr, &sched));
	}

	try_set (CREATE4, !pthread_create(&thread->pthread, &attr, _threadStarter, thread));
	try (!pthread_attr_destroy(&attr));
	_thread_cnt++;
	tms_clr(LOCK1, _mutex_unlock(&_fork_lock));
	return &thread->pthread;

	catch:
	release (CREATE1, pthread_attr_destroy(&attr));
	release (CREATE2, _cv_destroy(&thread->lock.cv));
	release (CREATE3, _mutex_destroy(&thread->lock.mutex));
	release (CREATE4, TmsThreadDestroy((pthread_t *)thread));
	release (LOCK1, _mutex_unlock(&_fork_lock));
	return NULL;
}

// cancels the thread
int TmsThreadDestroy(pthread_t *pthread)
{
	CatchAndRelease;
	TmsThreadT *tms = (TmsThreadT *) pthread;

	try (TMS_OBJ_IS(tms, TMS_OBJ_THREAD));

	_mutex_set (LOCK1, &_fork_lock);
	//pthread_cancel(thread->pthread);
	//if (thread->flags & TMS_THREAD_JOINABLE){
	//	pthread_join(thread->pthread, NULL);
	//}
	memset(tms, 0, sizeof(TmsThreadT));
	try (!TmsFree(pthread));
	_thread_cnt--;
	_mutex_unlock(&_fork_lock);
	return 0;

	catch:
	_release_mutex(LOCK1, &_fork_lock);
	return -1;
}

#if 0
static void *_thread_list_func(void *arg)
{
	TmsThreadListArgT *thread = (TmsThreadListArgT *) arg;
	void *data;

	while(1){

		// wait for a list member to be available
		try (data = TmsListWait(thread->list, TMS_LIST_HEAD, -1));

		// call the function
		thread->func(data, thread->arg);

		// free the list element
		try (!TmsListFreeNode(data));
	}

	catch:
	return NULL;
}

TmsThreadListT *TmsThreadListCreate(void *(*func) (void *, void *), int num, TmsThreadFlagT flags, void *arg, void (*cleanup)(void *))
{
	int i;
	TmsThreadListT *tlist;
	CatchAndRelease;

	try_set (ALLOC1, tlist = (TmsThreadListT *) TmsMalloc(sizeof(TmsThreadListT) + (num * sizeof(TmsThreadT *))));
	//try_set (LIST_ALLOC, tlist->data.list = TmsListCreate(TMS_LIST_MAX, TMS_MEM_SIGNAL));
	tlist->data.arg = arg;
	tlist->data.func = func;
	for (i=0; i<num; i++){
		try (tlist->threads[i] = TmsThreadCreate(_thread_list_func, flags, &tlist->data, NULL));
	}
	return tlist;

	catch:
	for (i=0; i<num; i++){
		if (tlist->threads[i]){
			TmsThreadDestroy(tlist->threads[i]);
		}
	}
	release (LIST_ALLOC, TmsListDestroy(tlist->data.list));
	release (ALLOC1, TmsFree(tlist));
	return NULL;
}

#endif

#define TMS_MAX_SCM_RIGHTS_FDS 10
union cmsgfd {
	struct cmsghdr hdr;
	unsigned char buf[CMSG_SPACE(sizeof(int) * TMS_MAX_SCM_RIGHTS_FDS)];
};

int TmsScmRightsSend(int sock, int *fds, int nfds, void *data, size_t data_size)
{
    struct msghdr msghdr = {0};
    struct iovec msg_iov[2] = {0};
    union cmsgfd cmsgfd = {0};
    struct cmsghdr *cmsg;
    int fdsize = nfds * sizeof(int);

    try (nfds <= TMS_MAX_SCM_RIGHTS_FDS);

    // set up the data pointer
    msg_iov[0].iov_base = &nfds;
    msg_iov[0].iov_len = sizeof(nfds);

	if (data && data_size) {
		msg_iov[1].iov_base = data;
		msg_iov[1].iov_len = data_size;
		msghdr.msg_iovlen = 2;
	}
	else{
		msghdr.msg_iovlen = 1;
	}

    // set up the msg
    msghdr.msg_iov = msg_iov;
    msghdr.msg_name = NULL;
    msghdr.msg_namelen = 0;
    msghdr.msg_flags = 0;
    msghdr.msg_controllen = CMSG_SPACE(fdsize);
    msghdr.msg_control = &cmsgfd;

    // set up the control data to hold the fd
    cmsg = CMSG_FIRSTHDR(&msghdr);
    cmsg->cmsg_len = CMSG_LEN(fdsize);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    memcpy(CMSG_DATA(cmsg), fds, fdsize);

	// send the msg to client
	try (sendmsg(sock, &msghdr, 0) != -1);
	return 0;

	catch:
	return -1;
}

int TmsScmRightsRecv(int sock, int *fds, int nfds, void *data, int data_size)
{
	union cmsgfd cmsgfd = {0};
	struct msghdr msghdr = {0};
	struct iovec msg_iov[2] = {0};
	struct cmsghdr *cmsg;
    int fdsize = TMS_MAX_SCM_RIGHTS_FDS * sizeof(int);
    int rd_nfds;

    try (fds && nfds && nfds <= TMS_MAX_SCM_RIGHTS_FDS);

	// set up the resp pointer
	msg_iov[0].iov_base = &rd_nfds;
	msg_iov[0].iov_len = sizeof(rd_nfds);

	if (data && data_size) {
		msg_iov[1].iov_len = data_size;
		msghdr.msg_iovlen = 2;
	}
	else{
		msghdr.msg_iovlen = 1;
	}

	// set up the msg
	msghdr.msg_iov = msg_iov;
	msghdr.msg_name = NULL;
	msghdr.msg_namelen = 0;
	msghdr.msg_flags = 0;
	msghdr.msg_control = &cmsgfd;
    msghdr.msg_controllen = CMSG_SPACE(fdsize);

	// set up the control data to hold the event fd
	cmsg = CMSG_FIRSTHDR(&msghdr);
	cmsg->cmsg_len = CMSG_LEN(fdsize);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;

	try (recvmsg(sock, &msghdr, 0) != -1);
    if (rd_nfds > nfds){
    	rd_nfds = nfds;
    }

    memcpy(fds, CMSG_DATA(cmsg), sizeof(int) * rd_nfds);
    return rd_nfds;

    catch:
	return -1;
}

int TmsFree(void *ptr)
{
	TmsPoolT *pool = NULL;
	TmsMemT *node;

	if (!ptr){
		return -1;
	}

	node = (TmsMemT *) ((uint8_t *) ptr - TMS_MEM_NODE_SIZE);

	// are we a pool object
	if (TMS_OBJ_IS(node, TMS_OBJ_POOLNODE)) {
		pool = (TmsPoolT *) ((uint8_t *) node - node->data.obj);
	}

	// try to free the node
	try (!_tms_free(pool, node, 1));

	// done
	return 0;

	catch:
	return -1;
}

int TmsWaitPid(pid_t pid, int sig, int msec)
{
	struct timespec ts;
	pid_t ret;

	if (!pid){
		return 0;
	}

	if (msec == -1){
		return waitpid(pid, NULL, 0);
	}
	else if (msec == 0){
		return waitpid(pid, NULL, WNOHANG);
	}

	try (!clock_gettime(CLOCK_MONOTONIC, &ts));

	while (!_msec_is_elapsed(&ts, msec)){
		if ((ret = waitpid(pid, NULL, WNOHANG))){
			return ret == pid ? 0 : -1;
		}
		usleep(TMS_WAITPID_POOL_USEC);
	}

	if (!sig){
		return -1;
	}

	if (kill(pid, sig) == EPERM){
		return -1;
	}

	try (!clock_gettime(CLOCK_MONOTONIC, &ts));

	while (!_msec_is_elapsed(&ts, msec)){
		if ((ret = waitpid(pid, NULL, WNOHANG))){
			return ret == pid ? 0 : -1;
		}
		usleep(TMS_WAITPID_POOL_USEC);
	}

	catch:
	return -1;
}

pid_t TmsFork(void *(*func) (void *), void *arg)
{
	pid_t pid=0;
	int rc;

	_mutex_lock(&_fork_lock);
	try (func && !_thread_cnt);
	if (!(pid = fork())){
		_mutex_unlock(&_fork_lock);
		_tid = getpid();
		TmsTestNameClean();
		rc = func(arg) ? 1 : 0;
		TmsTestNameClean();
		exit(rc);
	}
	try (pid != -1);
	_mutex_unlock(&_fork_lock);
	return pid;

	catch:
	_mutex_unlock(&_fork_lock);
	if (pid){
		return -1;
	}
	else{
		exit(2);
	}
}
