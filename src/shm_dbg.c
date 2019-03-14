/*
 * tms_dbg.c

 *
 *  Created on: Sep 20, 2018
 *      Author: bob
 */


#include "shm_include.h"
#include "shm_err.h"
#include "shm_dbg.h"

#ifndef __GNUC__
#define __GNUC__
#endif

int shm_check(void *ptr)
{
	TmsShmT *shm;
	TmsObjDataT *data;
	uint8_t *p1;
	ptrdiff_t diff;

	TMS_ASSERT (ptr > (void *) TMS_SHM_NODE_SIZE);

	data = (TmsObjDataT *) ((uint8_t *) ptr - sizeof(TmsObjDataT));
	shm = (TmsShmT *) ((uint8_t *) ptr - data->offset);

	p1 = (uint8_t *) ptr + shm->usrSize;
	diff = p1 - (uint8_t *) shm;

	TMS_DEBUG("\nshm: %p/%zx\n"
			"ptr: %p/%zx\n"
			"guard: %p/%zx: %x\n",
			shm, shm->usrSize,
			ptr, (uint8_t *)ptr - (uint8_t *)shm,
			p1, diff, *(int *) p1);


	// make sure valid object
	TMS_ASSERT (TMS_OBJ_PASS(shm, TMS_OBJ_SHM));

	// make sure we didn't overrun
	TMS_ASSERT (*((TmsGuardT *) ((uint8_t *) ptr + shm->usrSize)) == TMS_MEM_GUARD);

	return 0;
}

int tmsd_obj_check(void *ptr, TmsObjT obj)
{
	TmsMemT *node = (TmsMemT *) ((uint8_t *) ptr - TMS_MEM_NODE_SIZE);
	return !TMS_OBJ_PASS(node, obj);
}

void tmsd_node_dump(void *ptr)
{
	TmsMemT *node = (TmsMemT *) ((uint8_t *) ptr - TMS_MEM_NODE_SIZE);

	TMS_DEBUG("---------------------------\n");
	TMS_DEBUG("node: %p\n", node);
	TMS_DEBUG("guard: 0x%x\n", node->guard);
	TMS_DEBUG("user size: %zd\n", node->usrSize);
	TMS_DEBUG("obj: %zx\n", node->data.obj);
	TMS_DEBUG("next: %zx\n", node->data.next);
	TMS_DEBUG("prev: %zx\n", node->data.prev);
	TMS_DEBUG("---------------------------\n");
}

#if 0
void tmsd_link_dump(TmsLinkT *link)
{
	int i;

	TMS_DEBUG("---------------------------\n");

	for (i=0; i<link->cnt; i++) {

	}

	TMS_DEBUG("---------------------------\n");
	TMS_DEBUG("node: %p\n", node);
	TMS_DEBUG("guard: 0x%x\n", node->guard);
	TMS_DEBUG("user size: %zd\n", node->usrSize);
	TMS_DEBUG("obj: %zx\n", node->data.obj);
	TMS_DEBUG("next: %zx\n", node->data.next);
	TMS_DEBUG("prev: %zx\n", node->data.prev);
	TMS_DEBUG("---------------------------\n");
}

void tmsd_ring_dump(TmsListCtlT *list)
{
	int i;
	char *s, buf[2048];
	uint8_t *ringbuf;
	int pri;
	TmsLinkT *link;
	TmsRingPubT *ring;
	TmsMemT *tnode, *hnode;
	TmsPoolT *pool;

	pool = (TmsPoolT *) ((uint8_t *) list + list->pool);

	s = buf;
	ringbuf = (uint8_t *) ((uint8_t *) list + list->ring_buf);
	TmsRwRdLock(&list->header.lock.rwlock);

	s += sprintf(s, "\n\nlist %p, %d ring nodes\n", list->self, list->num_elem);
	for (i=0; i<list->num_elem; i++){
		pri = ringbuf[i];
		link = &list->pri[pri];
		hnode = (TmsMemT *) ((uint8_t *) pool + link->head);
		tnode = (TmsMemT *) ((uint8_t *) pool + link->tail);
		s += sprintf(s, "idx %d, pri %d, hnode %zx/%zx, tnode %zx/%zx %s\n",
				i, pri, link->head, hnode->data.obj, link->tail, tnode->data.obj, i == list->seq_num ? "seq num" : "");
	}

	s += sprintf(s, "\nring, pool %p, seq %d, qcnt %d\n", pool->self, list->seq_num, list->qcnt);
	for (i=0; i<list->num_elem; i++){
		pri = ringbuf[i];
		link = &list->pri[pri];
		ring = &list->ring_pub[pri];
		s += sprintf(s, "%d, pri %d, cnt %d, head %zx, tail %zx,  |  pub %"PRIx64", del %"PRIx64"\n",
				i, pri, link->cnt, link->head, link->tail, ring->add_cnt, ring->del_cnt);
	}

	s += sprintf(s, "\npri list\n");
	for (i=0; i<10; i++){
		pri = i;
		link = &list->pri[pri];
		s += sprintf(s, "pri %d, cnt %d, head %zx, tail %zx\n", pri, link->cnt, link->head, link->tail);
	}
	s += sprintf(s, "\n");

	TMS_DEBUG("%s", buf);
	TmsRwUnlock(&list->header.lock.rwlock);
}

#endif

