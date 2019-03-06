#include "tms_include.h"
#include "tms_err.h"
#include "tms_dbg.h"

//#define DEBUG(...) TMS_DEBUG(__VA_ARGS__)

#ifndef DEBUG
#define DEBUG(...)
#define DEBUG_ONLY(x)
#define PRINT_MASK (!(i & 0x1ff))
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
#define TIMEOUT -1

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
	char name[256];
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
static pidlist_t pid[MAX_SLAVES][2];

static int _create_flags(int flags)
{
	return GET_PARM(pool_parms) | GET_PARM(align_parms) | GET_PARM(shm_parms) | flags;
}

static int _open_flags(int flags)
{
	return flags & TMS_NOCOPY ? 0 : GET_PARM(pool_parms) | GET_PARM(align_parms);
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
		p = pid[i];
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

static int _test_exit(pidlist_t *arg)
{
	// join our loopback thread
	if (arg->thread){
		TmsThreadJoin(arg->thread, TIMEOUT, NULL);
		DEBUG("MASTER JOINED THREAD, CLEANING UP\n");

		// destroy our main thread
		try (!TmsThreadDestroy(arg->thread));
	}

	// join/wait for slaves
	try (!_clean(arg));

	// close & destroy our inbound list (half duplex)
	if (!(arg->list_flags & TMS_DUPLEX)){
		try (!TmsListClose(arg[1].list));
		try (!TmsListDestroy(arg[1].name));
	}

	// close & destroy our outbound list
	try (!TmsListClose(arg->list));
	try (!TmsListDestroy(arg->name));

	// test the final result
	try (arg->accum == arg->num_iters * arg->num_slaves);

	TMS_DEBUG("\n");
	DEBUG("PASS %d/%d\n", arg->accum, arg->num_iters * arg->num_slaves);
	return 0;

	catch:
	TMS_DEBUG("\n");
	TMS_DEBUG("FAIL %d/%d\n", arg->accum, arg->num_iters * arg->num_slaves);
	exit(1);
}

static int _init_args(pidlist_t *arg, char *name, int num_iters, int num_slaves, int num_elem, int flags)
{
	try(num_slaves <= MAX_SLAVES);

	// store the name
	strcpy(arg->name, name);

	// our default list flags
	arg->list_flags = _create_flags(flags);

	// number of slaves
	arg->num_slaves = GET_RAND(1, num_slaves);

	// number of elements in queue
	arg->num_elem = GET_RAND(1, num_elem);

	// num of procs
	arg->num_procs = arg->num_slaves && (arg->list_flags & TMS_SHARED) ? GET_RAND(1, arg->num_slaves) : 0;

	// number of iterations
	arg->num_iters = GET_RAND(1, num_iters);

	// our max element size - we pad this out to make proper pool size for responses
	arg->size = (sizeof(payload_t) + MAX_TEST_BUF_SIZE);
	return 0;

	catch:
	return -1;
}

static int _create_list(pidlist_t *arg, int flags)
{
	int open_flags;
	char buf[256];

	// create a master list
	try (!TmsListCreate(arg->name, arg->num_elem, arg->size, 0, arg->list_flags, TMS_SHM_PERM));
	DEBUG("created %s\n", arg->name);

	// open our list
	open_flags = _open_flags(arg->list_flags) | flags;
	try (arg->list = TmsListOpen(arg->name, open_flags, 0));

	TMS_DEBUG("MASTER: %s\n", arg->name);
	TMS_DEBUG("MASTER: slaves %d (p: %d), iters %d, elems %d\n",
			arg->num_slaves, arg->num_procs, arg->num_iters, arg->num_elem);
	TMS_DEBUG("MASTER: list flags %s\n", strflags(arg->list_flags, buf));
	TMS_DEBUG("MASTER: open flags %s\n", strflags(open_flags, buf));
	return 0;

	catch:
	return -1;
}

static int _start_procs(pidlist_t *arg, void *(*slave) (void *))
{
	pidlist_t *p;
	int i, j;
	DEBUG_ONLY(char buf[256];)

	try (arg->num_slaves);

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

	// start our slaves
	for (i=0; i<arg->num_slaves; i++){

		p = pid[i];
		memcpy(p, arg, 2 * sizeof(pidlist_t));

		// our open flags
		p->open_flags = _open_flags(arg->list_flags);

		// our process id
		p->id = i;

		// start a middleman process
		if (i < arg->num_procs){
			p->open_flags |= TMS_PROC;
			try (p->pid = TmsFork(slave, p));
			DEBUG("started proc %d, %d\n", i, p->pid);
		}

		// start a middleman thread
		else{
			p->open_flags |= TMS_THREAD;
			try (p->thread = TmsThreadCreate(slave, TMS_THREAD_JOINABLE, p, NULL));
			DEBUG("started thread %d\n", i);
		}

		DEBUG("START %d: %s\n", i, strflags(p->open_flags, buf));
	}
#if 0
	// create our loopback thread
	if (thread){
		try (arg->thread = TmsThreadCreate(thread, TMS_THREAD_JOINABLE, arg, NULL));
	}
#endif
	return 0;

	catch:
	return -1;
}

static int _clone_args(pidlist_t *dst, pidlist_t *src, char *name, int flags)
{
	memcpy(dst, src, sizeof(pidlist_t));
	strcpy(dst->name, name);
	dst->list_flags = _create_flags(flags);
	return 0;
}

////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////

void *_ring_slave1(void *arg)
{
	CatchAndRelease;
	int id;
	pidlist_t *parm = (pidlist_t *) arg;
	size_t size;
	int pri;
	payload_t *rx=NULL;
	TmsListT *list;
	int kill_flag=0;
	DEBUG_ONLY(char flagbuf[256]; int rx_cnt;)

	//parm->open_flags = parm->id == 0 ? 0x4000080 : 0x4000082;
	try_set (OPEN1, list = TmsListOpen("tms_list_buf.0", parm->open_flags | TMS_OPEN_B, 0));
	DEBUG("START SLAVE %d %s\n", parm->id, strflags(list->open_flags, flagbuf));

	id = parm->id;
	while(!kill_flag){

		DEBUG("SLAVE %d waiting to take\n", id);
		try_set (ALLOC1, rx = (payload_t *) TmsListRead(list, &size, &pri, TIMEOUT));

		DEBUG("SLAVE %d GOT LIST1 ID %d, DATA CNT %d, SIZE %zd, PRI %d/%d, kill %d\n",
				id, rx->id, rx->cnt, size, pri, rx->pri, rx->kill);

		kill_flag = rx->kill;
		try (rx->pri == pri);
		try (!memcmp(rx->data, testbuf[rx->bufidx].data, size - sizeof(payload_t)));
		rx->id = id;
		DEBUG_ONLY(rx_cnt = rx->cnt;)

		DEBUG("SLAVE %d, waiting to put %d\n", id, kill_flag);
		try (!TmsListWrite(list, rx, size, pri, TIMEOUT));
		try_clr (ALLOC1, !TmsFree(rx));

		DEBUG("SLAVE %d SENT ACK1, DATA CNT %d, PRI %d, SIZE %zd, KILL %d\n",
				id, rx_cnt, pri, size, kill_flag);
	}

	DEBUG("SLAVE %d DONE, CAUGHT KILL\n", id);
	try (!TmsListClose(list));
	return _slave_exit(parm->open_flags, 0);

	catch:
	TMS_ERROR("SLAVE %d ERROR, EXITING!\n", id);
	release (ALLOC1, TmsFree(rx));
	release(OPEN1, TmsListClose(list));
	return _slave_exit(parm->open_flags, 1);
}

static int _ring_test1(int num_iters, int num_slaves, int num_elem)
{
	CatchAndRelease;
	payload_t *payload = NULL;
	testbuf_t *buf;
	int i;
	size_t size;
	static pidlist_t arg;
	int pri, kill_flag, flags;

	// clear options
	memset(&arg, 0, sizeof(arg));

	// init the test vars
	flags = TMS_DUPLEX | TMS_RING;

	// init test args
	try (!_init_args(&arg, "tms_list_buf.0", num_iters, num_slaves, num_elem, flags));

	// adjust number of elements in queue
	arg.num_elem = arg.num_elem < num_slaves ? num_slaves : arg.num_elem;

	// create the master list
	try (!_create_list(&arg, 0));

	// start procs
	try (!_start_procs(&arg, _ring_slave1));

	// start sending data
	for (i=0; i<arg.num_iters; i++){

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

		if (i == arg.num_iters - 1){
			payload->kill = 1;
			payload->pri = 9;
		}
		else{
			payload->kill = 0;
			payload->pri = GET_RAND(0, TMS_LIST_PRI_MAX);
		}

		pri = payload->pri;
		kill_flag = payload->kill;

		// write to the list
		if (TmsListWrite(arg.list, payload, size, pri, TIMEOUT)){
			throw(errno, "MASTER ERROR!!!!\n");
		}

		try_clr (ALLOC1, !TmsFree(payload));

		if (PRINT_MASK || i == arg.num_iters-1){
			TMS_DEBUG("MASTER SENT DATA, PRI %d, DATA CNT %d, SIZE %zd, KILL %d         " PRINT_TERM,
					pri, i, size, kill_flag);
		}

		while(arg.accum != (i+1) * arg.num_slaves){

			DEBUG("MASTER waiting to take\n");
			try_set (ALLOC1, payload = TmsListRead(arg.list, &size, &pri, TIMEOUT));

			DEBUG("MASTER GOT SLAVE ID %d, DATA CNT %d, PRI %d/%d, SIZE %d/%zd, KILL %d\n",
					payload->id, payload->cnt, payload->pri, pri, payload->size, size, payload->kill);

			// sanity check
			try (pri == payload->pri && size == payload->size);

			// last buffer should have kill flag set
			if (payload->cnt == arg.num_iters-1){
				try (payload->kill && pri == 9);
			}

			// payload check
			try (!memcmp(testbuf[payload->bufidx].data, payload->data, size - sizeof(payload_t)));

			try_clr (ALLOC1, !TmsFree(payload));

			arg.accum++;
		}
	}

	catch:
	return _test_exit(&arg);
}

////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////
#if 1
void *_ring_slave2(void *arg)
{
	CatchAndRelease;
	int id;
	pidlist_t *parm = (pidlist_t *) arg;
	size_t size;
	int pri;
	payload_t *rx=NULL;
	TmsListT *list0, *list1 = NULL;
	int kill_flag=0;
	DEBUG_ONLY(char flagbuf[256]; int rx_cnt;)

	try_set (OPEN1, list0 = TmsListOpen(parm[0].name, parm[0].open_flags, 0));
	DEBUG("START SLAVE %d, LIST 0, %s, %s\n", parm[0].id, parm[0].name, strflags(list0->open_flags, flagbuf));

	try_set (OPEN2, list1 = TmsListOpen(parm[1].name, parm[1].open_flags, 0));
	DEBUG("START SLAVE %d, LIST 1, %s, %s\n", parm[1].id, parm[1].name, strflags(list1->open_flags, flagbuf));

	id = parm->id;
	while(!kill_flag){

		DEBUG("SLAVE %d waiting to take\n", id);
		try_set (ALLOC1, rx = (payload_t *) TmsListRead(list0, &size, &pri, TIMEOUT));

		DEBUG("SLAVE %d GOT LIST1 ID %d, DATA CNT %d, SIZE %zd, PRI %d/%d, kill %d\n",
				id, rx->id, rx->cnt, size, pri, rx->pri, rx->kill);

		kill_flag = rx->kill;
		try (rx->pri == pri);
		try (!memcmp(rx->data, testbuf[rx->bufidx].data, size - sizeof(payload_t)));
		rx->id = id;
		DEBUG_ONLY(rx_cnt = rx->cnt;)

		DEBUG("SLAVE %d, waiting to put %d\n", id, kill_flag);
		try (!TmsListWrite(list1, rx, size, pri, TIMEOUT));

		try_clr (ALLOC1, !TmsFree(rx));

		DEBUG("SLAVE %d SENT ACK1, DATA CNT %d, PRI %d, SIZE %zd, KILL %d\n",
				id, rx_cnt, pri, size, kill_flag);
	}

	DEBUG("SLAVE %d DONE, CAUGHT KILL\n", id);
	try (!TmsListClose(list0));
	try (!TmsListClose(list1));
	return _slave_exit(parm->open_flags, 0);

	catch:
	TMS_ERROR("SLAVE %d ERROR, EXITING!\n", id);
	release (ALLOC1, TmsFree(rx));
	release(OPEN1, TmsListClose(list0));
	release(OPEN2, TmsListClose(list1));
	return _slave_exit(parm->open_flags, 1);
}

static int _ring_test2(int num_iters, int num_slaves, int num_elem)
{
	CatchAndRelease;
	payload_t *payload = NULL;
	testbuf_t *buf;
	int i;
	size_t size;
	static pidlist_t arg[2];
	int pri, kill_flag, flags;

	// clear options
	memset(arg, 0, sizeof(arg));

	flags = TMS_RING | TMS_SHARED;

	num_elem = 2;

	// init outbound args
	try (!_init_args(&arg[0], "tms_list_buf.0", num_iters, num_slaves, num_elem, flags));

	// adjust number of elements in queue
	arg[0].num_elem = arg[0].num_elem < num_slaves ? num_slaves : arg[0].num_elem;

	// create the outbound list
	try (!_create_list(&arg[0], 0));

	// init inbound args
	try (!_clone_args(&arg[1], &arg[0], "tms_list_buf.1", flags));

	// create the inbound list
	try (!_create_list(&arg[1], 0));

	// start procs
	try (!_start_procs(&arg[0], _ring_slave2));

	// start sending data
	for (i=0; i<arg[0].num_iters; i++){

		// point to a test buf
		buf = &testbuf[GET_RAND(0, NUM_TEST_BUF-1)];

		// set the total size
		size = sizeof(payload_t) + GET_RAND(0, MAX_TEST_BUF_SIZE);

		//allocate the payload
		try_set (ALLOC1, payload = TmsListAlloc(arg[0].list, size, TIMEOUT));

		// copy the data
		memcpy(payload->data, buf->data, size - sizeof(payload_t));

		// set the header
		payload->bufidx = buf->idx;
		payload->id = 1234;
		payload->cnt = i;
		payload->size = size;

		if (i == arg[0].num_iters - 1){
			payload->kill = 1;
			payload->pri = 9;
		}
		else{
			payload->kill = 0;
			payload->pri = GET_RAND(0, TMS_LIST_PRI_MAX);
		}

		pri = payload->pri;
		kill_flag = payload->kill;

		DEBUG("MASTER waiting to send\n");

		// write to the list
		if (TmsListWrite(arg[0].list, payload, size, pri, TIMEOUT)){
			throw(errno, "MASTER ERROR!!!!\n");
		}

		try_clr (ALLOC1, !TmsFree(payload));

		if (PRINT_MASK || i == arg[0].num_iters-1){
			TMS_DEBUG("MASTER SENT DATA, PRI %d, DATA CNT %d, SIZE %zd, KILL %d         " PRINT_TERM,
					pri, i, size, kill_flag);
		}

		while(arg[0].accum != (i+1) * arg[0].num_slaves){

			DEBUG("MASTER waiting to take\n");
			try_set (ALLOC1, payload = TmsListRead(arg[1].list, &size, &pri, TIMEOUT));

			DEBUG("MASTER GOT SLAVE ID %d, DATA CNT %d, PRI %d/%d, SIZE %d/%zd, KILL %d\n",
					payload->id, payload->cnt, payload->pri, pri, payload->size, size, payload->kill);

			// sanity check
			try (pri == payload->pri && size == payload->size);

			// last buffer should have kill flag set
			if (payload->cnt == arg[0].num_iters-1){
				try (payload->kill && pri == 9);
			}

			// payload check
			try (!memcmp(testbuf[payload->bufidx].data, payload->data, size - sizeof(payload_t)));

			try_clr (ALLOC1, !TmsFree(payload));

			arg[0].accum++;
		}
	}

	catch:
	DEBUG("MASTER END %d/%d\n", arg->accum, arg->num_iters * arg->num_slaves);
	return _test_exit(arg);
}
#endif

#define test(x) {\
	TMS_DEBUG("%s, start\n", #x);\
	x; \
	TMS_DEBUG("%s, pass\n", #x);\
}

int main(int argc, char **argv)
{
	int i=0, cnt=0, num_loops=999999;

	srand(time(NULL));

	try (!system("rm -Rf /dev/shm/tms*"));

	for (i=0; i<num_loops; i++) {
		printf("\n");
		TMS_DEBUG("========= Loop %4d ============\n", cnt);
		test (_ring_test1(1024*10, 100, 1024));
		printf("\n");
		test (_ring_test2(1024*10, 100, 1024));
		TMS_DEBUG("================================\n");
		printf("\n");
		cnt++;
	}
	exit(0);

	catch:
	exit(1);
}
