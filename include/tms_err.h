/*
 *
 * tms_err.h
 *  Created on: Nov 24, 2016
 *      Author: bob
 */

#ifndef TMS_INTERNALS_TMS_ERR_H_
#define TMS_INTERNALS_TMS_ERR_H_

#define error_if(x) if (x) {TMS_ERROR(#x "\n");}
#define error(fmt, ...) TMS_ERROR(fmt, ##__VA_ARGS__)

#define CatchAndRelease TmsTryBitsT tms_prog=TMS_TRY_NONE
#define tms_errno(x) if (!errno){errno = (x);}
#define catch_if(x) if ((x)) {tms_errno(EINVAL); goto catch;}
#define try(x) if (!(x)) {tms_errno(EINVAL); TMS_ERROR(#x "\n"); goto catch;}
#define try_no_log(x) if (!(x)) {tms_errno(EINVAL); goto catch;}
#define throw(err, fmt, ...) {errno=(err); TMS_ERROR(fmt, ##__VA_ARGS__); goto catch;}
#define throw_errno(err) {errno=(err); goto catch;}
#define try_set(x, y) {if (!(y)) {tms_errno(EINVAL); TMS_ERROR(#y "\n"); goto catch;} release_set(x);}
#define try_clr(x, y) {release_clr(x); if (!(y)) {tms_errno(EINVAL); TMS_ERROR(#y "\n"); goto catch;}}
#define release(prog, x) if (TMS_TRY_##prog & tms_prog){int err=errno; x; errno=err;}
#define release_set(x) (tms_prog |= TMS_TRY_##x)
#define release_clr(x) (tms_prog &= ~TMS_TRY_##x)
#define tms_is_set(x) (tms_prog & TMS_TRY_##x)
#define tms_set(x, y) {y; release_set(x);}
#define tms_clr(x, y) {y; release_clr(x);}
#define tms_set_if(x, y) {if (y){release_set(x);}}

typedef TmsEnum {
	TMS_TRY_NONE		 	= 0x0,
	TMS_TRY_INIT1		 	= 0x1,
	TMS_TRY_INIT2			= 0x2,
	TMS_TRY_INIT3			= 0x4,
	TMS_TRY_INIT4			= 0x8,
	TMS_TRY_CREATE1			= 0x10,
	TMS_TRY_CREATE2		 	= 0x20,
	TMS_TRY_CREATE3			= 0x40,
	TMS_TRY_CREATE4		 	= 0x80,
	TMS_TRY_ALLOC1		 	= 0x100,
	TMS_TRY_ALLOC2		 	= 0x200,
	TMS_TRY_ALLOC3		 	= 0x400,
	TMS_TRY_ALLOC4		 	= 0x800,
	TMS_TRY_OPEN1			= 0x1000,
	TMS_TRY_OPEN2		 	= 0x2000,
	TMS_TRY_OPEN3		 	= 0x4000,
	TMS_TRY_OPEN4			= 0x8000,
	TMS_TRY_LOCK1			= 0x10000,
	TMS_TRY_LOCK2		 	= 0x20000,
	TMS_TRY_LOCK3		 	= 0x40000,
	TMS_TRY_LOCK4		 	= 0x80000,
	TMS_TRY_FLAG1			= 0x100000,
	TMS_TRY_FLAG2			= 0x200000,
	TMS_TRY_FLAG3			= 0x400000,
	TMS_TRY_FLAG4			= 0x800000
} TmsTryBitsT;

#endif /* TMS_INTERNALS_TMS_ERR_H_ */
