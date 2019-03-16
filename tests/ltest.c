#include "shareipc.h"
#include "shm_err.h"
#include "shm_dbg.h"

//#define DEBUG(...) TMS_DEBUG(__VA_ARGS__)

#ifndef DEBUG
#define DEBUG(...)
#define DEBUG_ONLY(x)
#define PRINT_MASK (!(i & 0x3fff))
//#define PRINT_MASK (0)
#define PRINT_TERM "\r"
#else
#define DEBUG_ONLY(x) x
#define PRINT_MASK (1)
#define PRINT_TERM "\n"
#endif

#define MAX_SLAVES 100
#define TMS_SHM_PERM (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)
#define NUM_TEST_BUF 256
#define MAX_TEST_BUF_SIZE (8192 * 1)
#define TIMEOUT 30000

typedef struct {
	uint32_t idx;
	char *name;
} strflag_t;

typedef struct {
	uint32_t idx;
	uint8_t *data;
} testbuf_t;

typedef struct{
	uint32_t cnt;
	uint32_t size;
	int pri;
	int id;
	int bufidx;
	int kill;
	uint8_t data[0];
} payload_t;

typedef struct {
	TmsListT *list;
	pthread_t *thread;
	void *user;
	void *(*main_thread) (void *);
	void *(*slave_proc) (void *);
	pid_t pid;
	int size;
	int id;
	int num_iters;
	int num_slaves;
	int num_procs;
	int num_elem;
	int cnt[MAX_SLAVES];
	int total;
	int dead;
	int accum;
	int open_flags;
	int list_flags;
	int num_links;
} pidlist_t;

#define STRFLAG(x) {x, #x}

static strflag_t strflag[] = {
	STRFLAG(TMS_PAGE_ALIGN),
	STRFLAG(TMS_CACHE_ALIGN),
	STRFLAG(TMS_MLOCK),
	STRFLAG(TMS_NOCOPY),
	STRFLAG(TMS_COPY_OUT),
	STRFLAG(TMS_DUPLEX),
	STRFLAG(TMS_FIXED),
	STRFLAG(TMS_DYNAMIC),
	STRFLAG(TMS_HEAP),
	STRFLAG(TMS_RING),
	STRFLAG(TMS_OPEN_A),
	STRFLAG(TMS_OPEN_B),
	STRFLAG(TMS_THREAD),
	STRFLAG(TMS_PROC),
	STRFLAG(TMS_SHARED),
	STRFLAG(TMS_RDONLY),
	STRFLAG(TMS_WRONLY)
};

static uint32_t copy_parms[] =
	{0, TMS_NOCOPY};

static uint32_t ocopy_parms[] =
	{0, TMS_COPY_OUT};

static uint32_t pool_parms[] =
	{0, TMS_DYNAMIC, TMS_FIXED};

static uint32_t align_parms[] =
	{0, TMS_PAGE_ALIGN, TMS_CACHE_ALIGN};

static uint32_t shm_parms[] =
	{0, TMS_SHARED};

#define NUM_PARMS(x) (sizeof(x) / sizeof(uint32_t))
#define NUM_FLAGS (sizeof(strflag) / sizeof(strflag_t))
#define GET_PARM(x) (x)[GET_RAND(0, NUM_PARMS(x)-1)]

static testbuf_t testbuf[NUM_TEST_BUF];
static pidlist_t pid[MAX_SLAVES];

static int _create_flags()
{
	return
		TMS_EXFAIL
		| GET_PARM(copy_parms)
		| GET_PARM(pool_parms)
		| GET_PARM(align_parms)
		| GET_PARM(shm_parms);
}

static int _open_flags(int flags)
{
	return flags & TMS_NOCOPY ? 0 : GET_PARM(ocopy_parms) | GET_PARM(pool_parms) | GET_PARM(align_parms);
}

static char *strflags(int flags, char *buf)
{
	char *tmp = buf;
	int i, j, bit=1, test;

	*buf = '\0';
	tmp += sprintf(tmp, "(0x%x) ", flags);
	for (i=0; i<31; i++){
		if ((test = flags & bit)){
			for (j=0; j<NUM_FLAGS; j++){
				if (strflag[j].idx == test){
					tmp += sprintf(tmp, "%s ", strflag[j].name);
				}
			}
		}
		bit <<= 1;
	}
	return buf;
}

static int _clean(pidlist_t *arg)
{
	int i;
	int rc = 0;
	pidlist_t *p;

	// clean the pids and tids
	for (i=0; i<arg->num_slaves; i++){
		p = &pid[i];
		if (p->open_flags & TMS_PROC){
			DEBUG("waiting to kill proc %d, %d\n", i, p->pid);
			if (p->pid && TmsWaitPid(p->pid, SIGTERM, TIMEOUT) == -1){
				TMS_ERROR ("SLAVE PROC %d, %d, UNABLE TO KILL\n", i, p->pid);
				rc |= -1;
			}
			else{
				DEBUG("joined proc %d\n", i);
			}
		}
		else if (p->open_flags & TMS_THREAD){
			DEBUG("waiting to kill thread %d\n", i);
			if (p->thread && TmsThreadJoin(p->thread, TIMEOUT, NULL)){
				TMS_ERROR ("SLAVE THREAD %d, UNABLE TO JOIN\n", i);
				rc |= -1;
			}
			else{
				DEBUG("joined thread %d\n", i);
				rc |= TmsThreadDestroy(p->thread);
			}
		}
		else if (p->open_flags){
			TMS_ASSERT(0);
		}
	}

	for (i=0; i<NUM_TEST_BUF; i++){
		TmsFree(testbuf[i].data);
	}

	// done
	return rc;
}

static void *_slave_exit(int flags, uint8_t ret)
{
	int i;
	if (flags & TMS_PROC){
		for (i=0; i<NUM_TEST_BUF; i++){
			TmsFree(testbuf[i].data);
		}
	}
	return (ret ? (void *) -1 : NULL);
}

static int _main_exit(pidlist_t *arg)
{
	char link_name[256];
	int i;

	// join our loopback thread
	TmsThreadJoin(arg->thread, TIMEOUT, NULL);
	DEBUG("MASTER JOINED THREAD, CLEANING UP, DEAD %d\n", arg->dead);

	// join/wait for slaves
	try (!_clean(arg));

	// destroy our main thread
	try (!TmsThreadDestroy(arg->thread));

	// close our list
	try (!TmsListClose(arg->list));

	// destroy our main list
	try (!TmsListDestroy("tms_list_buf.0"));

	// destroy all remaining lists
	for (i=1; i<arg->num_links; i++){
		sprintf(link_name, "tms_list_buf.%d", i);
		try (!TmsListDestroy(link_name));
	}

	// test the final result
	try (arg->accum == arg->num_iters);

	TMS_DEBUG("\n");
	TMS_DEBUG("PASS %d/%d\n", arg->accum, arg->num_iters);
	return 0;

	catch:
	TMS_DEBUG("\n");
	TMS_DEBUG("FAIL %d/%d\n", arg->accum, arg->num_iters);
	exit(1);
}

static int _init_test(int num_iters, int num_slaves, int num_elem, int use_links,
		int flags, pidlist_t *arg, void *(*slave) (void *), void *(*thread) (void *))
{
	char buf[256];
	int i, j, open_flags;
	pidlist_t *p;

	DEBUG("IN iters %d, slaves %d, elem %d\n", num_iters, num_slaves, num_elem);

	try(num_slaves <= MAX_SLAVES);

	// clear options
	memset(arg, 0, sizeof(pidlist_t));

	// create our random test buffers
	memset(testbuf, 0, sizeof(testbuf));

	// pid data for results
	memset(pid, 0, sizeof(pid));

	// load test buffers
	for (i=0; i<NUM_TEST_BUF; i++){
		try (testbuf[i].data = TmsMalloc(MAX_TEST_BUF_SIZE));
		testbuf[i].idx = i;
		for (j=0; j<MAX_TEST_BUF_SIZE; j++){
			testbuf[i].data[j] = GET_RAND(0, 255);
		}
	}

	// our default list flags
	arg->list_flags = _create_flags() | flags;

	// number of elements in queue
	arg->num_elem = GET_RAND(1, num_elem);

	// number of slaves
	arg->num_slaves = GET_RAND(1, num_slaves);

	// num of procs
	arg->num_procs = arg->list_flags & TMS_SHARED ? GET_RAND(1, arg->num_slaves) : 0;

	// number of iterations
	num_iters = num_iters < arg->num_slaves ? arg->num_slaves : num_iters;
	arg->num_iters = GET_RAND(arg->num_slaves, num_iters);

	// our max element size
	arg->size = sizeof(payload_t) + MAX_TEST_BUF_SIZE;

	// our main thread function
	arg->main_thread = thread;

	// our slave function
	arg->slave_proc = slave;

	// create a full-duplex list
	try (!TmsListCreate("tms_list_buf.0", arg->num_elem, arg->size, 0, arg->list_flags | TMS_DUPLEX, TMS_SHM_PERM));
	DEBUG("created tms_list_buf.0\n");
	open_flags = _open_flags(arg->list_flags) | TMS_WRONLY;

	TMS_DEBUG("MASTER: slaves %d (p: %d), iters %d, elems %d\n",
			arg->num_slaves, arg->num_procs, arg->num_iters, arg->num_elem);
	TMS_DEBUG("MASTER: list flags %s\n", strflags(arg->list_flags, buf));
	TMS_DEBUG("MASTER: open flags %s\n", strflags(open_flags, buf));

	// create our chain
	// m0 -> l0 -> p0 -> l1 -> p1 -> l0 -> m0  half duplex
	// m0 -> l0 -> p0 -> l1 -> p1 -> l1 -> p0 -> l0 -> m0  full duplex
	if (use_links){
		flags |= arg->list_flags & TMS_SHARED ? TMS_SHARED : 0;
		for (arg->num_links=1; arg->num_links<arg->num_slaves; arg->num_links++){
			sprintf(buf, "tms_list_buf.%d", arg->num_links);
			if (arg->list_flags & TMS_NOCOPY){
				try (!TmsListLink(buf, "tms_list_buf.0", flags, 0));
				DEBUG("linked %s\n", buf);
			}
			else{
				try (!TmsListCreate(buf, arg->num_elem, arg->size, 0, arg->list_flags | flags, TMS_SHM_PERM));
				DEBUG("created %s\n", buf);
			}
		}
	}

	// start our slaves
	for (i=0; i<arg->num_slaves; i++){

		p = &pid[i];
		memcpy(p, arg, sizeof(pidlist_t));

		// our open flags
		p->open_flags = _open_flags(arg->list_flags);

		// our process id
		p->id = i;

		// start a middleman process
		if (i<arg->num_procs){
			p->open_flags |= TMS_PROC;
			p->pid = TmsFork(arg->slave_proc, p);
		}
		// start a middleman thread
		else{
			p->open_flags |= TMS_THREAD;
			try (p->thread = TmsThreadCreate(arg->slave_proc, TMS_THREAD_JOINABLE, p, NULL));
		}
		DEBUG("START %d: %s\n", i, strflags(p->open_flags, buf));
	}

	// create our loopback thread
	try (arg->thread = TmsThreadCreate(thread, TMS_THREAD_JOINABLE, arg, NULL));

	// open our list
	try (arg->list = TmsListOpen("tms_list_buf.0", open_flags, 0));
	return 0;

	catch:
	return -1;
}

static int _safe_free(TmsListT *list, void *data){
	return list->base->flags & TMS_NOCOPY ? 0 : TmsFree(data);
}

static void *_main_thread(void *arg)
{
	CatchAndRelease;
	size_t size;
	int pri;
	pidlist_t *parm = (pidlist_t *) arg;
	payload_t *rx;
	TmsListT *list;
	DEBUG_ONLY(char flagbuf[256]);
	int flags;

	flags = _open_flags(parm->list_flags) | TMS_OPEN_A | TMS_RDONLY;
	try_set (OPEN1, list = TmsListOpen("tms_list_buf.0", flags, 0));
	DEBUG("master thread open %s, %s\n", "tms_list_buf.0", strflags(flags, flagbuf));

	parm->accum = 0;
	while(parm->accum != parm->num_iters){

		DEBUG("THREAD waiting to take\n");
		try_set (ALLOC1, rx = TmsListRead(list, &size, &pri, TIMEOUT));

		DEBUG("THREAD GOT SLAVE ID %d, DATA CNT %d, PRI %d/%d, SIZE %d/%zd, KILL %d\n",
			rx->id, rx->cnt, rx->pri, pri, rx->size, size, rx->kill);

		// last buffer should have kill flag set
		if (parm->accum == parm->num_iters-1){
			try (rx->kill);
		}

		try (pri == rx->pri && size == rx->size);
		try (!memcmp(testbuf[rx->bufidx].data, rx->data, size - sizeof(payload_t)));
		parm->accum++;
		parm->cnt[rx->id]++;
		try_clr (ALLOC1, !TmsFree(rx));
	}
	TmsListClose(list);
	parm->dead = 1;
	return NULL;

	catch:
	release (ALLOC1, TmsFree(rx));
	release (OPEN1, TmsListClose(list));
	parm->dead = 1;
	return (void *) -1;
}

////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////

void *_list_slave1(void *arg)
{
	CatchAndRelease;
	int id;
	pidlist_t *parm = (pidlist_t *) arg;
	size_t size;
	int pri;
	payload_t *rx=NULL;
	TmsListT *list;
	int kill_flag=0;
	DEBUG_ONLY(
		char flagbuf[256];
		int rx_cnt;
	)

	try_set (OPEN1, list = TmsListOpen("tms_list_buf.0", parm->open_flags | TMS_OPEN_B, 0));
	DEBUG("START SLAVE %d %s\n", parm->id, strflags(list->open_flags | TMS_OPEN_B, flagbuf));

	id = parm->id;
	while(!kill_flag){

		DEBUG("SLAVE %d waiting to take\n", id);
		try_set (ALLOC1, (rx = TmsListRead(list, &size, &pri, TIMEOUT)));

		DEBUG("SLAVE %d GOT MASTER ID %d, DATA CNT %d, SIZE %zd, PRI %d/%d, kill %d\n",
			id, rx->id, rx->cnt, size, pri, rx->pri, rx->kill);

		try (rx->pri == pri && rx->id == 1234);
		try (!memcmp(rx->data, testbuf[rx->bufidx].data, size - sizeof(payload_t)));
		kill_flag = rx->kill;
		rx->id = id;
		kill_flag = rx->kill;
		DEBUG_ONLY(rx_cnt = rx->cnt;)

		DEBUG("SLAVE %d, waiting to put %d\n", id, rx->kill);
		try (!TmsListWrite(list, rx, size, pri, TIMEOUT));
		try_clr (ALLOC1, !_safe_free(list, rx));

		DEBUG("SLAVE %d SENT ACK, DATA CNT %d, PRI %d, SIZE %zd, KILL %d\n",
			id, rx_cnt, pri, size, kill_flag);
	}

	DEBUG("SLAVE %d DONE, CAUGHT KILL\n", id);
	try (!TmsListClose(list));
	return _slave_exit(parm->open_flags, 0);

	catch:
	TMS_ERROR("SLAVE %d ERROR, EXITING!\n", id);
	release (ALLOC1, _safe_free(list, rx));
	release(OPEN1, TmsListClose(list));
	return _slave_exit(parm->open_flags, 1);
}

static int _list_test1(int num_iters, int num_slaves, int num_elem)
{
	CatchAndRelease;
	payload_t *payload = NULL;
	testbuf_t *buf;
	int i;
	size_t size;
	static pidlist_t arg;
	int pri, cnt, kill_flag;

	// init the test vars
	try (!_init_test(num_iters, num_slaves, num_elem, 0, 0, &arg, _list_slave1, _main_thread));

	// start sending data
	for (i=0; i<arg.num_iters && !arg.dead; i++){

		// point to a test buf
		buf = &testbuf[GET_RAND(0, NUM_TEST_BUF-1)];

		// set the total size
		size = sizeof(payload_t) + GET_RAND(0, MAX_TEST_BUF_SIZE);

		//allocate the payload
		try_set (ALLOC1, payload = TmsListAlloc(arg.list, size, TIMEOUT));

		// copy the data
		memcpy(payload->data, buf->data, size - sizeof(payload_t));

		// set the header
		payload->bufidx = buf->idx;
		payload->id = 1234;
		payload->cnt = i;
		payload->size = size;

		if (i < arg.num_iters - arg.num_slaves){
			payload->pri = GET_RAND(0, TMS_LIST_PRI_MAX);
			payload->kill = 0;
		}
		else{
			payload->pri = 9;
			payload->kill = 1;
		}

		pri = payload->pri;
		cnt = payload->cnt;
		kill_flag = payload->kill;

		// write to the list
		if (TmsListWrite(arg.list, payload, size, pri, TIMEOUT)){
			throw(errno, "MASTER ERROR!!!!\n");
		}

		try_clr (ALLOC1, !_safe_free(arg.list, payload));

		if (PRINT_MASK || i == arg.num_iters-1){
			TMS_DEBUG("MASTER SENT DATA, PRI %d, DATA CNT %d, SIZE %zd, KILL %d         " PRINT_TERM,
					pri, cnt, size, kill_flag);
		}
	}

	catch:
	return _main_exit(&arg);
}

////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////

void *_list_slave2(void *arg)
{
	CatchAndRelease;
	char name1[256];
	char name2[256];
	int id;
	pidlist_t *parm = (pidlist_t *) arg;
	size_t size;
	int pri;
	payload_t *rx = NULL;
	TmsListT *list1, *list2 = NULL;
	int kill_flag=0;
	DEBUG_ONLY(char flagbuf[256]; int rx_cnt;)

	id = parm->id;
	if (parm->num_slaves == 1){
		sprintf(name1, "tms_list_buf.0");
		try_set (OPEN1, list1 = TmsListOpen(name1, parm->open_flags | TMS_OPEN_B, 0));
		sprintf(name2, "tms_list_buf.0");
		list2 = list1;
	}
	else if (id == 0){
		sprintf(name1, "tms_list_buf.0");
		try_set (OPEN1, list1 = TmsListOpen(name1, parm->open_flags | TMS_OPEN_B | TMS_RDONLY, 0));
		sprintf(name2, "tms_list_buf.1");
		try_set (OPEN2, list2 = TmsListOpen(name2, parm->open_flags, 0));
	}
	else if (id == parm->num_slaves-1){
		sprintf(name1, "tms_list_buf.%d", id);
		try_set (OPEN1, list1 = TmsListOpen(name1, parm->open_flags, 0));
		sprintf(name2, "tms_list_buf.0");
		try_set (OPEN2, list2 = TmsListOpen(name2, parm->open_flags | TMS_OPEN_B | TMS_WRONLY, 0));
	}
	else{
		sprintf(name1, "tms_list_buf.%d", id);
		try_set (OPEN1, list1 = TmsListOpen(name1, parm->open_flags, 0));
		sprintf(name2, "tms_list_buf.%d", id+1);
		try_set (OPEN2, list2 = TmsListOpen(name2, parm->open_flags, 0));
	}

	DEBUG("START SLAVE %d, %s: %s\n", id, name1, strflags(list1->open_flags, flagbuf));
	DEBUG("START SLAVE %d, %s: %s\n", id, name2, strflags(list2->open_flags, flagbuf));

	while(!kill_flag){

		DEBUG("SLAVE %d waiting to take\n", id);
		try_set (ALLOC1, (rx = TmsListRead(list1, &size, &pri, TIMEOUT)));
		DEBUG("SLAVE %d GOT MASTER ID %d, DATA CNT %d, SIZE %zd, PRI %d/%d, kill %d\n",
				id, rx->id, rx->cnt, size, pri, rx->pri, rx->kill);

		try (rx->pri == pri);
		try (!memcmp(rx->data, testbuf[rx->bufidx].data, size - sizeof(payload_t)));
		kill_flag = rx->kill;
		rx->id = id;
		DEBUG_ONLY(rx_cnt = rx->cnt;)

		DEBUG("SLAVE %d, waiting to put %d\n", id, rx->kill);
		try (!TmsListWrite(list2, rx, size, pri, TIMEOUT));
		try_clr (ALLOC1, !_safe_free(list1, rx));

		DEBUG("SLAVE %d SENT ACK ID, DATA CNT %d, PRI %d, SIZE %zd, KILL %d\n",
				id, rx_cnt, pri, size, kill_flag);
	}

	DEBUG("SLAVE %d DONE, CAUGHT KILL\n", id);
	try_clr (OPEN1, !TmsListClose(list1));
	if (tms_is_set(OPEN2)){
		try_clr (OPEN2, !TmsListClose(list2));
	}
	return _slave_exit(parm->open_flags, 0);

	catch:
	TMS_ERROR("SLAVE %d ERROR, EXITING!\n", id);
	release (ALLOC1, _safe_free(list1, rx));
	release(OPEN1, TmsListClose(list1));
	release (OPEN2, TmsListClose(list2));
	return _slave_exit(parm->open_flags, 1);
}

static int _list_test2(int num_iters, int num_slaves, int num_elem)
{
	CatchAndRelease;
	payload_t *payload = NULL;
	testbuf_t *buf;
	int i;
	static pidlist_t arg;
	int pri, cnt, kill_flag;
	size_t size;

	// init the test vars
	try (!_init_test(num_iters, num_slaves, num_elem, 1, 0, &arg, _list_slave2, _main_thread));

	// start sending data
	for (i=0; i<arg.num_iters && !arg.dead; i++){

		// point to a test buf
		buf = &testbuf[GET_RAND(0, NUM_TEST_BUF-1)];

		// set the total size
		size = sizeof(payload_t) + GET_RAND(0, MAX_TEST_BUF_SIZE);

		//allocate the payload
		try_set (ALLOC1, payload = TmsListAlloc(arg.list, size, TIMEOUT));

		// copy the data
		memcpy(payload->data, buf->data, size - sizeof(payload_t));

		// set the header
		payload->bufidx = buf->idx;
		payload->id = 1234;
		payload->cnt = i;
		payload->size = size;

		if (i < arg.num_iters-1){
			payload->pri = GET_RAND(0, TMS_LIST_PRI_MAX);
			payload->kill = 0;
		}
		else{
			payload->pri = 9;
			payload->kill = 1;
		}

		cnt = payload->cnt;
		pri = payload->pri;
		kill_flag = payload->kill;

		// write to the list
		if (TmsListWrite(arg.list, payload, size, payload->pri, TIMEOUT)){
			throw(errno, "MASTER ERROR!!!!\n");
		}

		try_clr (ALLOC1, !_safe_free(arg.list, payload));

		// progress to screen
		if (PRINT_MASK || kill_flag){
			TMS_DEBUG("MASTER SENT DATA, PRI %d, DATA CNT %d, SIZE %zd, KILL %d         " PRINT_TERM,
					pri, cnt, size, kill_flag);
		}
	}

	catch:
	return _main_exit(&arg);
}

////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////

void *_list_slave3(void *arg)
{
	CatchAndRelease;
	pthread_t *thread = NULL;
	TmsListT *lists[2], **arglist;
	char name[256];
	int id;
	pidlist_t *parm = (pidlist_t *) arg;
	size_t size;
	int pri;
	payload_t *rx = NULL;
	int kill_flag=0;
	DEBUG_ONLY(char flagbuf[256]; int rx_cnt;)
	int thread_id;

	id = parm->id;

	if (!parm->user){
		sprintf(name, "tms_list_buf.%d", id);
		try_set (OPEN1, lists[0] = TmsListOpen(name, parm->open_flags | TMS_OPEN_B, 0));
		DEBUG("START SLAVE %d.0, %s\n", parm->id, strflags(lists[0]->open_flags, flagbuf));
		DEBUG("SLAVE %d.0, OPEN B %s\n", id, name);
		if (id == parm->num_slaves-1){
			lists[1] = lists[0];
		}
		else {
			sprintf(name, "tms_list_buf.%d", id+1);
			try_set (OPEN2, lists[1] = TmsListOpen(name, parm->open_flags | TMS_OPEN_A, 0));
			DEBUG("SLAVE %d.0, OPEN A %s\n", id, name);
			parm->user = lists;
			try (thread = TmsThreadCreate(_list_slave3, TMS_THREAD_JOINABLE, parm, NULL));
		}
		thread_id = 0;
	}
	else{
		arglist = (TmsListT **) parm->user;
		lists[0] = arglist[1];
		lists[1] = arglist[0];
		DEBUG("START SLAVE %d.1 THREAD, %s\n", parm->id, strflags(lists[1]->open_flags, flagbuf));
		thread_id = 1;
	}

	while(!kill_flag){

		DEBUG("SLAVE %d.%d waiting to take1\n", id, thread_id);
		try_set (ALLOC1, (rx = TmsListRead(lists[0], &size, &pri, TIMEOUT)));

		DEBUG("SLAVE %d.%d GOT LIST1 ID %d, DATA CNT %d, SIZE %zd, PRI %d/%d, kill %d\n",
				id, thread_id, rx->id, rx->cnt, size, pri, rx->pri, rx->kill);

		kill_flag = rx->kill;
		try (rx->pri == pri);
		try (!memcmp(rx->data, testbuf[rx->bufidx].data, size - sizeof(payload_t)));
		rx->id = id;
		DEBUG_ONLY(rx_cnt = rx->cnt;)

		DEBUG("SLAVE %d.%d, waiting to put1 %d\n", id, thread_id, kill_flag);
		try (!TmsListWrite(lists[1], rx, size, pri, TIMEOUT));
		try_clr (ALLOC1, !_safe_free(lists[0], rx));

		DEBUG("SLAVE %d.%d SENT ACK1, DATA CNT %d, PRI %d, SIZE %zd, KILL %d\n",
				id, thread_id, rx_cnt, pri, size, kill_flag);
	}

	DEBUG("SLAVE %d.%d DONE, CAUGHT KILL\n", id, thread_id);

	if (thread_id == 0){
		DEBUG("SLAVE %d.0 WAITING FOR JOIN\n", id);
		if (thread){
			try (!TmsThreadJoin(thread, TIMEOUT, NULL));
			DEBUG("SLAVE %d.0 JOINED SLAVE THREAD\n", id);
			try (!TmsThreadDestroy(thread));
			DEBUG("SLAVE %d.0 THREAD 1 DESTROYED\n", id);
			try_clr (OPEN2, !TmsListClose(lists[1]));
		}
		try_clr (OPEN1, !TmsListClose(lists[0]));
		DEBUG("SLAVE %d.0 DONE, exiting!\n", id);
		return _slave_exit(parm->open_flags, 0);
	}
	else{
		DEBUG("SLAVE %d.1 DONE, exiting!\n", id);
		return _slave_exit(TMS_THREAD, 0);
	}

	catch:
	TMS_ERROR("SLAVE %d.%d ERROR, EXITING!\n", id, thread_id);
	release (ALLOC1, _safe_free(lists[0], rx));
	release(OPEN1, TmsListClose(lists[0]));
	release (OPEN2, TmsListClose(lists[1]));
	return _slave_exit(parm->open_flags, 1);
}

static int _list_test3(int num_iters, int num_slaves, int num_elem)
{
	CatchAndRelease;
	payload_t *payload = NULL;
	testbuf_t *buf;
	int i;
	size_t size;
	static pidlist_t arg;
	int pri, cnt, kill_flag;

	// init our test vars
	try (!_init_test(num_iters, num_slaves, num_elem, 1, TMS_DUPLEX, &arg, _list_slave3, _main_thread));

	// start sending data
	for (i=0; i<arg.num_iters && !arg.dead; i++){

		// point to a test buf
		buf = &testbuf[GET_RAND(0, NUM_TEST_BUF-1)];

		// set the total size
		size = sizeof(payload_t) + GET_RAND(0, MAX_TEST_BUF_SIZE);

		//allocate the payload
		try_set (ALLOC1, payload = TmsListAlloc(arg.list, size, TIMEOUT));

		// copy the data
		memcpy(payload->data, buf->data, size - sizeof(payload_t));

		// set the header
		payload->bufidx = buf->idx;
		payload->id = 1234;
		payload->cnt = i;
		payload->size = size;

		if (i < arg.num_iters-1){
			payload->pri = GET_RAND(0, TMS_LIST_PRI_MAX);
			payload->kill = 0;
		}
		else{
			payload->pri = 9;
			payload->kill = 1;
		}

		kill_flag = payload->kill;
		cnt = payload->cnt;
		pri = payload->pri;

		// write to the list
		if (TmsListWrite(arg.list, payload, size, payload->pri, TIMEOUT)){
			throw(errno, "MASTER ERROR!!!!\n");
		}

		try_clr (ALLOC1, !_safe_free(arg.list, payload));

		// progress to screen
		if (PRINT_MASK || i == arg.num_iters-1){
			TMS_DEBUG("MASTER SENT DATA, PRI %d, DATA CNT %d %d, SIZE %zd, KILL %d         " PRINT_TERM,
					pri, cnt, arg.accum, size, kill_flag);
		}
	}

	catch:
	return _main_exit(&arg);
}

////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////

#define test(x) {\
	TMS_DEBUG("%s, start\n", #x);\
	x; \
	TMS_DEBUG("%s, pass\n", #x);\
}

int main(int argc, char **argv)
{
	int i=0, cnt=0, num_loops=1000000;

	srand(time(NULL));

	try (!system("rm -Rf /dev/shm/tms*"));

	for (i=0; i<num_loops; i++) {
		printf("\n");
		TMS_DEBUG("========= Loop %4d ============\n", cnt);
		//test (_list_test1(1024*1024, 100, 1024));
		//printf("\n");
		//test (_list_test2(1024*1024, 100, 1024));
		//printf("\n");
		//test (_list_test3(1024*512, 64, 1024));
		test (_list_test1(1024*10, 100, 1024));
		printf("\n");
		test (_list_test2(1024*10, 100, 1024));
		printf("\n");
		test (_list_test3(1024*10, 64, 1024));
		TMS_DEBUG("================================\n");
		printf("\n");
		cnt++;
	}
	exit(0);

	catch:
	exit(1);
}
