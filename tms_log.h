/*
 * tms_log.h
 *
 *  Created on: Nov 1, 2015
 *      Author: bob
 */

#ifndef TMS_LOG_H_
#define TMS_LOG_H_

//#define TMS_TAG {printf("<<< TAG %s.%d    %d:%d >>>\n", __FUNCTION__, __LINE__, (int) getpid(), (int)syscall(SYS_gettid)); fflush(stdout);}
#define TMS_TAG {TMS_DEBUG("<<< TAG    %d   %d:%d >>>\n", errno, (int) getpid(), (int)syscall(SYS_gettid));}
#define TMS_LOG_DEPTH 16
#define TMS_LOG_LINE_SIZE 256
#define TMS_LOG_PRINT_SIZE ((TMS_LOG_LINE_SIZE+8) * TMS_LOG_DEPTH)
#define TMS_LOG_STRERROR_SIZE 256
#define TMS_LOG_TIME TmsLogHms(_tmslog.hms, sizeof(_tmslog.hms))
#define TMS_ERROR(fmt, ...) ({TMS_LOG("ERROR", fmt, ##__VA_ARGS__); -1;})
#define TMS_MAX_INDENT 16

#define tms_err TMS_ERROR

#if 0
#define tms_dbg(...) TMS_DEBUG(__VA_ARGS__)
#define tms_enter TMS_ENTER
#define tms_exit TMS_EXIT
#else
#define tms_dbg(...)
#define tms_enter
#define tms_exit
#endif

#define TMS_LOG(sev, fmt, ...)\
if (_tmslog.error_enable){\
	int xerr = errno;\
	_tmslog.estr = xerr && !_tmslog.first_errno ? TmsLogStrError(xerr) : (char *)"";\
	snprintf(_tmslog.line, TMS_LOG_LINE_SIZE, sev " %s %d:%s:%d %s " fmt,\
			TMS_LOG_TIME,\
			(int)syscall(SYS_gettid),\
			__FUNCTION__, \
			__LINE__, \
			_tmslog.estr,\
			##__VA_ARGS__);\
	TmsLog(_tmslog.line, xerr);\
	errno = xerr;\
}

#define TMS_STDERR(fmt, ...) \
if (_tmslog.enable){\
	fflush(stdout);\
	fprintf(stderr, "ERROR %s %d:%s:%d " fmt, \
			TMS_LOG_TIME, (int)syscall(SYS_gettid), __FUNCTION__, __LINE__, ##__VA_ARGS__);\
	fflush(stderr);\
}

#define TMS_DEBUG(fmt, ...) \
if (_tmslog.enable){\
	uint32_t indent_ = _tmslog.indent_cnt > TMS_MAX_INDENT-1 ? TMS_MAX_INDENT-1 : _tmslog.indent_cnt;\
	TmsDebugPrefix(__FUNCTION__, __LINE__);\
	fprintf(stdout, "%-50s %s" fmt, _tmslog.line, _tmslog.indent[indent_], ##__VA_ARGS__);\
	fflush(stdout);\
}

#define TMS_ENTER {\
		TMS_DEBUG("ENTER %s\n", __FUNCTION__);\
		_tmslog.indent_cnt++;\
}

#define TMS_EXIT {\
		_tmslog.indent_cnt--;\
		TMS_DEBUG("EXIT  %s\n", __FUNCTION__);\
}

#define TMS_ASSERT(x) {\
	if (!(x)){\
		TmsLogDump(stderr); \
	}\
	assert(x);\
}

#define TMS_ASSERT_LOG(x, ...) {\
	if (!(x)){\
		TMS_ERROR(__VA_ARGS__);\
		TmsLogDump(stderr); \
		assert(x);\
	}\
}

typedef TmsStruct {
	pthread_mutex_t mutex;
	char *estr;
	char hms[32];
	char first_strerror[TMS_LOG_LINE_SIZE];
	char first_error[TMS_LOG_LINE_SIZE];
	char log_buf[TMS_LOG_DEPTH][TMS_LOG_LINE_SIZE];
	char line[TMS_LOG_LINE_SIZE];
	char serrno[TMS_LOG_STRERROR_SIZE];
	char **indent;
	int first_errno;
	uint32_t cnt;
	uint32_t idx;
	uint32_t indent_cnt;
	uint8_t enable;
	uint8_t quiet;
	uint8_t error_enable;
} TmsLogT;

typedef TmsStruct {
	uint32_t req_cnt;
	uint32_t req_pend;

	uint32_t reply_cnt;
	uint32_t reply_pend;

	uint32_t free_pend;

	uint32_t msg_oom_cnt;
	uint32_t msg_err_cnt;

	uint32_t tx_tout_cnt;
	uint32_t tx_err_cnt;

	uint32_t rx_err_cnt;
	uint32_t rx_tout_cnt;
} TmsStatsT;

extern __thread TmsLogT _tmslog;
extern TmsStatsT _tms_stats;

char *TmsLogHms(char *buf, int size);
int TmsLogDump(FILE *fp);
void TmsLogClear(void);
void TmsLog(char *line, int xerrorno);
char *TmsLogStrError(int err);
void TmsLogQuietEnable(void);
void TmsLogQuietDisable(void);
void TmsLogEnable(void);
void TmsLogDisable(void);
void TmsErrorLogEnable(void);
void TmsErrorLogDisable(void);
void TmsDebugPrefix(const char *func, int line);

#endif /* TMS_LOG_H_ */
