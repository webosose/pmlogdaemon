// Copyright (c) 2014-2018 LG Electronics, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

#include "heavy_operation_routine.h"

#include <string.h>

typedef struct
{
	HeavyOperation *op;
	HeavyOperationRoutine *self;

} RoutineOpaque;

static gboolean HeavyOperationFunc(gpointer user_data)
{
	RoutineOpaque* opaque = (RoutineOpaque*)user_data;

	HeavyOperation* op = opaque->op;
	HeavyOperationRoutine* self = opaque->self;

	g_mutex_lock(&self->mutex);
	if (self->last_operation[op->type] == op)
	{
		self->last_operation[op->type] = NULL;
	}
	g_mutex_unlock(&self->mutex);

	op->routine_func(op->opaque);

	g_free(op);
	g_free(opaque);

	return FALSE;
}

gboolean HeavyOperationRoutineConstruct(HeavyOperationRoutine *self)
{
	if (!WorkerRoutineConstruct(&self->routine, "heav_operation_routine"))
		return FALSE;

	g_mutex_init(&self->mutex);
	memset(self->last_operation, 0, sizeof(self->last_operation));

	return TRUE;
}

void HeavyOperationRoutineDestruct(HeavyOperationRoutine* self)
{
	WorkerRoutineDestruct(&self->routine);

	memset(self->last_operation, 0, sizeof(self->last_operation));
	g_mutex_clear(&self->mutex);
}

gboolean
HeavyOperationRoutineRun(HeavyOperationRoutine* self)
{
	return WorkerRoutineRun(&self->routine);
}

void HeavyOperationRoutineAdd(HeavyOperationRoutine* self,
							  GSourceFunc op_routine,
							  gpointer op_opaque,
							  HeavyOperationType op_type,
							  HeavyOperationMergeFunc op_merge_func)
{
	g_mutex_lock(&self->mutex);

	do
	{
		if (op_merge_func)
		{
			HeavyOperation *op = self->last_operation[op_type];
			if (op != NULL && op_merge_func(op_opaque, op->opaque))
			{
				break;
			}
		}

		HeavyOperation *op =g_new(HeavyOperation, 1);
		if (op != NULL) {
			op->type         = op_type;
			op->opaque       = op_opaque;
			op->routine_func = op_routine;
		}


		if (op_merge_func)
		{
			self->last_operation[(unsigned)op_type] = op;
		}

		RoutineOpaque *opaque = g_new(RoutineOpaque, 1);
		if (opaque != NULL) {
			opaque->op = op;
			opaque->self = self;
		}

		WorkerRoutineAddTimerEvent(&self->routine, 0, HeavyOperationFunc, opaque);
	} while (FALSE);

	g_mutex_unlock(&self->mutex);
}
