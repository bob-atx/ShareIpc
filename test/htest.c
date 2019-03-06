#include "tms_include.h"
#include "tms_err.h"
#include "tms_dbg.h"

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
#define TIMEOUT 30000

typedef struct {
	uint32_t idx;
	char *name;
} strflag_t;

typedef struct{
	uint32_t t[MAX_SLAVES];
	uint32_t mod;
} cb_data_t;

typedef struct{
	int id;
	int max_procs;
	int num_elem;
	int num_iters;
} cb_arg_t;

typedef struct {
	pid_t pid;
	pthread_t *thread;
	TmsHashStateT *state;
	int type;
	int id;
	int cmd;
} proc_info_t;

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

static int _create_flags()
{
	return
		GET_PARM(pool_parms)
		| GET_PARM(align_parms)
		| GET_PARM(shm_parms);
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

static int _clean(proc_info_t *proc, int max_procs, int msec)
{
	int i, rc=0;

	// clean the pids and tids
	for (i=0; i<max_procs; i++) {
		if (proc[i].type == TMS_PROC) {
			DEBUG("waiting to kill proc %d, %d\n", i, proc_info[i].pid);
			if (proc[i].pid && TmsWaitPid(proc[i].pid, SIGTERM, msec) == -1){
				TMS_ERROR ("SLAVE PROC %d, %d, UNABLE TO KILL\n", i, proc[i].pid);
				rc |= -1;
			}
			else{
				DEBUG("joined proc %d, %d\n", i, proc_info[i].pid);
			}
		}
		else {
			DEBUG("waiting to kill thread %d\n", i);
			if (proc[i].thread && TmsThreadJoin(proc[i].thread, msec, NULL)){
				TMS_ERROR ("SLAVE THREAD %d, UNABLE TO JOIN\n", i);
				rc |= -1;
			}
			else{
				DEBUG("joined thread %d\n", i);
				rc |= TmsThreadDestroy(proc[i].thread);
				rc |= TmsHashStateDestroy(proc[i].state);
			}
		}
	}
	return rc;
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

#define MAX_PROCS 8
#define MAX_ITERS 102400
#define MAX_ELEM 1024
#define KEY_SIZE 32
#define CMD_SET 0
#define CMD_CLR 1

static int _hash_rmw3(void *buf, int size, void *arg, TmsHashStatusT *status)
{
	uint64_t *vbuf = (uint64_t *) buf, mask;
	proc_info_t *info = (proc_info_t *) arg;

	if (status->error){
		throw (EINVAL, "hash error found in callback\n");
	}

	mask = 1 << info->id;
	if (info->cmd == CMD_SET){
		*vbuf |= mask;
	}
	else if (info->cmd == CMD_CLR){
		*vbuf &= ~mask;
	}
	else{
		throw(EINVAL, "unknown command %d\n", info->cmd);
	}
	return 0;

	catch:
	return -1;
}

static void *_hash_slave3(void *arg)
{
	CatchAndRelease;
	proc_info_t *info = (proc_info_t *) arg;
	TmsHashT *hash;
	TmsHashStateT *state;
	uint64_t id, vbuf = 0;
	char key[KEY_SIZE];
	int i;

	// open our hash table
	try_set (OPEN1, hash = TmsHashOpen ("test_hash", 0, 0));

	// create a state for init
	try_set (CREATE1, state = TmsHashStateCreate(hash, "start_stop", 0, 0, -1));

	// our bit mask
	id = 1 << info->id;

	// wait for start
	while (!(vbuf & id)){
		try (!TmsHashStateRead(state, &vbuf, sizeof(vbuf)));
	}

	// init the keys
	info->cmd = 0;
	for (i=0; i<MAX_ELEM; i++) {
		sprintf(key, "key%d", i);
		try (!TmsHashReadWrite(hash, key, 0, NULL, 0, _hash_rmw3, info, -1));
	}

	// indicate we are done
	info->cmd = 1;
	try (!TmsHashReadWrite(hash, "start_stop", 0, NULL, 0, _hash_rmw3, info, -1));
	try (!TmsHashStateDestroy(state));
	try (!TmsHashClose(hash));
	return NULL;

	catch:
	release	(CREATE1, TmsHashStateDestroy(state));
	release (OPEN1, TmsHashClose(hash));
	return NULL;
}

static int hash_test3()
{
	proc_info_t info = {0};
	int num_procs = GET_RAND(0, MAX_PROCS);
	int i;
	TmsHashT *hash;
	TmsHashStateT *state;
	int num_elem = MAX_ELEM + 1;
	size_t elem_size = sizeof(uint64_t);
	proc_info_t proc_info[MAX_PROCS];
	char key[KEY_SIZE];
	uint64_t vbuf = 0;
	int rc = 0;
	uint64_t mask;

	// create our hash table
	try (!TmsHashCreate("test_hash", KEY_SIZE, num_elem, elem_size, TMS_SHARED, TMS_SHM_PERM));

	// start our procs
	for (i=0; i<num_procs; i++){
		proc_info[i].id = i;
		proc_info[i].thread = NULL;
		proc_info[i].type = TMS_PROC;
		proc_info[i].pid = TmsFork(_hash_slave3, &proc_info[i]);
	}

	// start our threads
	for (i=num_procs; i<MAX_PROCS; i++){
		proc_info[i].id = i;
		proc_info[i].pid = 0;
		proc_info[i].thread =  TmsThreadCreate(_hash_slave3, TMS_THREAD_JOINABLE, &proc_info[i], NULL);
		proc_info[i].type = TMS_THREAD;
	}

	// open the hash table
	try (hash = TmsHashOpen ("test_hash", 0, 0));

	// create a state for our start/stop flag
	try (state = TmsHashStateCreate(hash, "start_stop", 0, 0, -1));

	// our flag buffer
	vbuf = 0;

	// clear the start flag
	try (!TmsHashStateWrite(state, &vbuf, elem_size));

	// init the keys
	for (i=0; i<MAX_ELEM; i++) {
		sprintf(key, "key%d", i);
		try (!TmsHashWrite(hash, key, 0, &vbuf, elem_size, -1));
	}

	// start procs going, one bit at a time
	info.cmd = CMD_SET;
	for (i=0; i<num_procs; i++){
		info.id = i;
		try (!TmsHashReadWrite(hash, "start_stop", 0, NULL, 0, _hash_rmw3, &info, -1));
		vbuf |= (1<<i);
	}

	// save the mask
	mask = vbuf;

	// wait for each proc to complete their task
	while (vbuf) {
		try (TmsHashStateRead(state, &vbuf, elem_size) > 0);
	}

	// check the memory
	for (i=0; i<MAX_ELEM; i++){
		sprintf(key, "key%d", i);
		try (!TmsHashRead(hash, key, 0, &vbuf, elem_size, 0));
		try (vbuf == mask);
	}

	// clean the pids and tids
	for (i=0; i<num_procs; i++){
		DEBUG("waiting to kill proc %d, %d\n", i, proc_info[i].pid);
		if (proc_info[i].pid && TmsWaitPid(proc_info[i].pid, SIGTERM, TIMEOUT) == -1){
			TMS_ERROR ("SLAVE PROC %d, %d, UNABLE TO KILL\n", i, proc_info[i].pid);
			rc |= -1;
		}
		else{
			DEBUG("joined proc %d, %d\n", i, proc_info[i].pid);
		}
	}

	for (i=num_procs; i<MAX_PROCS; i++){
		DEBUG("waiting to kill thread %d\n", i);
		if (proc_info[i].thread && TmsThreadJoin(proc_info[i].thread, TIMEOUT, NULL)){
			TMS_ERROR ("SLAVE THREAD %d, UNABLE TO JOIN\n", i);
			rc |= -1;
		}
		else{
			DEBUG("joined thread %d\n", i);
			rc |= TmsThreadDestroy(proc_info[i].thread);
		}
	}

	TmsHashStateDestroy(state);
	TmsHashClose(hash);
	TmsHashDestroy("test_hash");
	return rc;

	catch:
	return -1;
}

static int _hash_cb(void *buf, int size, void *arg, TmsHashStatusT *status)
{
	cb_data_t *data = (cb_data_t *) buf;
	cb_arg_t *xarg = (cb_arg_t *) arg;

	if(status->error){
		return TMS_CB_EXIT;
	}

	else if (data->mod == xarg->id){
		data->t[xarg->id]++;
		//TMS_DEBUG("SLAVE %d: 0x%x 0x%x 0x%x 0x%x\n",
			//	xarg->id, data->t[0], data->t[1], data->t[2], data->t[3]);
		data->mod = (data->mod + 1) % xarg->max_procs;

		if (data->t[xarg->id] == xarg->num_iters){
			return TMS_CB_EXIT;
		}

	}
	return TMS_CB_OK;
}

static void *_fork_cb(void *arg)
{
	CatchAndRelease;
	TmsHashT *hash;
	TmsHashStateT *state;

	try_set (OPEN1, hash = TmsHashOpen ("test_hash", 0, 0));
	try_set (CREATE1, state = TmsHashStateCreate(hash, "test_key", 0,  0, TIMEOUT));
	try (!TmsHashStateCallback(state, _hash_cb, arg, TMS_HASH_RMW));

	while (!TmsHashStateReadWrite(state, NULL, 0));

	catch:
	release (CREATE1, TmsHashStateDestroy(state));
	release (OPEN1, TmsHashClose(hash));
	return NULL;
}

static int _hash_test2(void)
{
	int i, j, x;
	TmsHashT *hash;
	int num_elem;
	size_t size = sizeof(cb_data_t);
	cb_data_t cb_data = {0};
	cb_arg_t arg[MAX_PROCS]={{0}};
	int num_procs;
	int max_procs;
	int num_iters;
	proc_info_t proc[MAX_PROCS];
	char buf[32];

	num_elem = 5;
	max_procs = GET_RAND(2, MAX_PROCS);
	num_procs = GET_RAND(0, max_procs);
	num_iters = GET_RAND(0, MAX_ITERS);

	try (!TmsHashCreate("test_hash", KEY_SIZE, num_elem, size, TMS_SHARED, TMS_SHM_PERM));
	try (hash = TmsHashOpen ("test_hash", 0, 0));

	TMS_DEBUG("sections: %d\n", hash->base->section_mask+1);

	// force use of one locked section
	//hash->base->section_mask = 0;

	/////////////////////////////////////////////

	try (!TmsHashWrite(hash, "test_key", 0, &cb_data, size, 0));

	for (i=0; i<max_procs; i++){
		arg[i].id = i;
		arg[i].max_procs = max_procs;
		arg[i].num_elem = num_elem;
		arg[i].num_iters = num_iters;
		if (i < num_procs){
			proc[i].type = TMS_PROC;
			try (proc[i].pid = TmsFork(_fork_cb, &arg[i]));
		}
		else{
			proc[i].type = TMS_THREAD;
			try (proc[i].state = TmsHashStateCreate(hash, "test_key", 0,  0, TIMEOUT));
			try (!TmsHashStateCallback(proc[i].state, _hash_cb, &arg[i], TMS_HASH_RMW));
			try (proc[i].thread = TmsHashThreadCreate(proc[i].state, TMS_THREAD_JOINABLE, NULL));
		}
	}

	for (i=0; i<num_iters; i++) {
		for (j=0; j<4; j++) {
			sprintf(buf, "junk%d\n", j);
			try (!TmsHashWrite(hash, buf, 0, &j, sizeof(j), 0));
			try (TmsHashRead(hash, buf, 0, &x, sizeof(x), 0) == sizeof(x));
			try (TmsHashRead(hash, "test_key", 0, &cb_data, size, 0) == size);
			TMS_DEBUG("RW 1 %d %d %d\n", i, j, cb_data.t[0]);
			try (x == j);
		}

		for (j=0; j<4; j++) {
			sprintf(buf, "junk%d\n", j);
			try (!TmsHashWrite(hash, buf, 0, &j, sizeof(j), 0));
			try (TmsHashRead(hash, buf, 0, &x, sizeof(x), 0) == sizeof(x));
			try (x == j);
			try (!TmsHashUnlink(hash, buf, 0));
		}
	}

	////////////////////////////////////////////////////////////////////////

	try (!_clean(proc, max_procs, TIMEOUT));
	try (!TmsHashUnlink(hash, "test_key", 0));
	try (!TmsHashClose(hash));
	try (!TmsHashDestroy("test_hash"));

	/////////////////////////////////////////////
	return 0;

	catch:
	return -1;
}

int _hash_test1(void)
{
	int i, j;
	TmsHashT *hash;
	int data;
	char buf[KEY_SIZE];
	int num_elem;
	size_t size = sizeof(int);
	int ksize = 0;

	num_elem = GET_RAND(0, MAX_ELEM);

	try (!TmsHashCreate("test_hash", KEY_SIZE, num_elem, size, TMS_SHARED, TMS_SHM_PERM));
	try (hash = TmsHashOpen ("test_hash", 0, 0));

	size = sizeof(data);
	for (j=0; j < 128; j++){

		i = 2000;
		memset(buf, 0, KEY_SIZE); sprintf(buf, "key.0");
		try (!TmsHashWrite(hash, buf, ksize, &i, size, 0));
		try (TmsHashRead(hash, buf, ksize, &data, size, 0) != -1);
		try(i == data);

		for (i=0; i<num_elem; i++){
			memset(buf, 0, KEY_SIZE); sprintf(buf, "key.%d", i);
			try (!TmsHashWrite(hash, buf, ksize, &i, size, 0));
		}

		for (i=0; i<num_elem; i++){
			memset(buf, 0, KEY_SIZE); sprintf(buf, "key.%d", i);
			try (TmsHashRead(hash, buf, ksize, &data, size, 0) != -1);
			try(i == data);
		}

		i = 1000;
		memset(buf, 0, KEY_SIZE); sprintf(buf, "key.0");
		try (!TmsHashWrite(hash, buf, ksize, &i, size, 0));
		try (TmsHashRead(hash, buf, ksize, &data, size, 0) != -1);
		try(i == data);

		if (j==0){
			TmsHashStat(hash);
		}

		for (i=0; i<num_elem; i++){
			sprintf(buf, "key.%d", i);
			try (!TmsHashUnlink(hash, buf, ksize));
		}
	}
	TmsHashStat(hash);

	catch:
	exit(0);
}

int main(int argc, char **argv)
{
	int i=0, cnt=0, num_loops=1000000;

	srand(time(NULL));
	try (!system("rm -Rf /dev/shm/tms*"));

	_hash_test2();


#if 0
	for (i=0; i<num_loops; i++) {
		printf("\n");
		TMS_DEBUG("========= Loop %4d ============\n", cnt);
		test (_list_test1(1024*10, 100, 1024));
		TMS_DEBUG("================================\n");
		printf("\n");
		cnt++;
	}
#endif

	exit(0);

	catch:
	TMS_ASSERT(0);
	exit(1);
}
