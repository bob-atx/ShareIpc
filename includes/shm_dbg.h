/*
 * tms_dbg.h
 *
 *  Created on: Sep 20, 2018
 *      Author: bob
 */

#ifndef TMS_INTERNALS_TMS_DBG_H_
#define TMS_INTERNALS_TMS_DBG_H_

// 0x1990
#define _xd(ptr, offset){\
	TmsPoolT *_pool = &lista->zpool;\
	TmsMemT *_node = (TmsMemT *) ((uint8_t *) _pool + offset);\
	if (!_node){\
		TMS_DEBUG("ZZZZZZZZZZZ ptr %p, pool %p, NULL NODE!!!!\n", ptr->self, _pool->self);\
	}\
	else if (!_node->data.obj) {\
		TMS_DEBUG("ZZZZZZZZZZ ptr %p, pool %p, node %p, NULL OBJ !!!!!!\n", ptr->self, _pool->self, _node);\
	}\
	else {\
		TMS_DEBUG("ZZZZZZZZZZZZZ ptr %p, pool %p, node %p, obj %zx\n", ptr->self, _pool->self, _node, _node->data.obj);\
	}\
}
#define xe _xd(list, 0x1990);

extern TmsListCtlT *lista;



int shm_check(void *_shm);
void tmsd_ring_dump(TmsListCtlT *list);
int tmsd_obj_check(void *ptr, TmsObjT obj);
void tmsd_node_dump(void *ptr);
void tmsd_link_dump(void *ptr);

#endif /* TMS_INTERNALS_TMS_DBG_H_ */
