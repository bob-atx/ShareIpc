/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */
/*
 * tms_log.c
 *
 *  Created on: Nov 1, 2015
 *      Author: bob
 */

#include "shareipc.h"
#include "shm_err.h"

static char *indent[TMS_MAX_INDENT] = {
		"",
		"    ",
		"        ",
		"            ",
		"                ",
		"                    ",
		"                        ",
		"                            ",
		"                                ",
		"                                    ",
		"                                        ",
		"                                            ",
		"                                                ",
		"                                                    ",
		"                                                        ",
		"                                                            "
};

__thread TmsLogT _tmslog = {
	.enable = 1,
	.error_enable = 1,
	.indent_cnt = 0,
	.indent = indent,
	.idx = 0,
	.cnt = 0,
	.quiet = 0,
	.mutex = PTHREAD_MUTEX_INITIALIZER
};

TmsStatsT _tms_stats = {0};

char *TmsLogStrError(int err)
#if (_POSIX_C_SOURCE >= 200112L) && !defined(_GNU_SOURCE)
{
	strerror_r(err, _tmslog.serrno, sizeof(_tmslog.serrno));
	return _tmslog.serrno;
}
#else
{
	char tmp[sizeof(_tmslog.serrno)];
	char *s;
	s = strerror_r(err, tmp, sizeof(tmp));
	snprintf(_tmslog.serrno, sizeof(_tmslog.serrno), "%s", s);
	return _tmslog.serrno;
}
#endif

char *TmsLogHms(char *buf, int size)
{
	struct timespec ts;
	struct tm tinfo;
	char tmp1[16];
	time_t junk;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	junk = time(NULL);
	localtime_r(&junk, &tinfo);
	strftime(tmp1, sizeof(tmp1), "%H:%M:%S", &tinfo);
	snprintf(buf, size, "%s.%03ld", tmp1, ts.tv_nsec / 1000000);
	return buf;
}

void TmsLogQuietEnable(void)
{
	_tmslog.quiet = 1;
}

void TmsLogQuietDisable(void)
{
	_tmslog.quiet = 0;
}

void TmsLogEnable(void)
{
	_tmslog.enable = 1;
}

void TmsLogDisable(void)
{
	_tmslog.enable = 0;
}

void TmsErrorLogEnable(void)
{
	_tmslog.error_enable = 1;
}

void TmsErrorLogDisable(void)
{
	_tmslog.error_enable = 0;
}

void TmsLogClear(void)
{
	_tmslog.cnt = 0;
	_tmslog.idx = 0;
	_tmslog.first_errno = 0;
	errno = 0;
}

int TmsLogDump(FILE *fp)
{
	int i, cnt, idx;

	pthread_mutex_lock(&_tmslog.mutex);
	cnt = _tmslog.cnt > TMS_LOG_DEPTH ? TMS_LOG_DEPTH : _tmslog.cnt;
	fprintf(fp, "\n================= Tms Log Dump, %d Entries %s =================\n", cnt, _tmslog.cnt > TMS_LOG_DEPTH ? "(overflow)":"");
	if (cnt){
		fprintf(fp, "First Error:\n");
		fprintf(fp, "\t%s\n", _tmslog.first_strerror);

		fprintf(fp, "\nError Stack:\n");
		idx = _tmslog.idx == 0 ? TMS_LOG_DEPTH-1 : _tmslog.idx-1;
		for (i=0; i<cnt; i++){
			fprintf(fp, "\t%2d: %s", idx, _tmslog.log_buf[idx]);
			idx = idx == 0 ? TMS_LOG_DEPTH-1 : idx-1;
		}
		fprintf(fp, "================= Log has been cleared. =================\n\n");
	}
	fflush(fp);
	TmsLogClear();
	pthread_mutex_unlock(&_tmslog.mutex);
	return 0;
}

void TmsLog(char *line, int xerrno)
{
	if (!line){
		return;
	}
	pthread_mutex_lock(&_tmslog.mutex);
	if (!_tmslog.quiet){
		fputs(line, stdout);fflush(stdout);
	}
	if (!_tmslog.cnt){
		snprintf(_tmslog.first_error, TMS_LOG_LINE_SIZE, "%s", line);
	}
	if (xerrno && !_tmslog.first_errno){
		snprintf(_tmslog.first_strerror, TMS_LOG_LINE_SIZE, "%s", line);
		_tmslog.first_errno = xerrno;
	}
	snprintf(_tmslog.log_buf[_tmslog.idx], TMS_LOG_LINE_SIZE, "%s", line);
	_tmslog.idx = _tmslog.idx == TMS_LOG_DEPTH-1 ? 0 : _tmslog.idx + 1;
	_tmslog.cnt++;
	pthread_mutex_unlock(&_tmslog.mutex);
}

void TmsDebugPrefix(const char *func, int line)
{
	snprintf(_tmslog.line, TMS_LOG_LINE_SIZE, "DEBUG %s %d:%s:%d ",
		TMS_LOG_TIME,
		(int)syscall(SYS_gettid),
		func,
		line
	);
}

#if 0
void TmsLogTrace(void)
{
  void *array[50];
  size_t size;

  size = backtrace(array, 50);
  fprintf(_tmslog_.fd, "Obtained %zd stack frames.\n", size);
  backtrace_symbols_fd(array, size, fileno(_tmslog_.fd));
}
#endif
