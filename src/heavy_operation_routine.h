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

#ifndef _HEAVY_OPERATION_ROUTINE_H_
#define _HEAVY_OPERATION_ROUTINE_H_

#include <glib.h>

#include "worker_routine.h"
#include "heavy_operation.h"

typedef struct
{
	GMutex mutex;
	WorkerRoutine routine;

	HeavyOperation* last_operation[HeavyOperationTypeLast];

} HeavyOperationRoutine;

gboolean
HeavyOperationRoutineConstruct(HeavyOperationRoutine *self);

void
HeavyOperationRoutineDestruct(HeavyOperationRoutine* self);

gboolean
HeavyOperationRoutineRun(HeavyOperationRoutine* self);

/**
 * @brief HeavyOperationRoutineAdd
 *
 * If merge function doesn't specifyed or merge function return false
 * operation will be added to queue. Function doesn't carry about opaque
 * memory managment.
 *
 * @param Self pointer
 * @param Operation routine
 * @param Operation routine opaque.
 * @param Operation type
 * @param Operation merge function or NULL
 *
*/

void
HeavyOperationRoutineAdd(HeavyOperationRoutine* self,
						 GSourceFunc op_routine,
						 gpointer op_opaque,
						 HeavyOperationType op_type,
						 HeavyOperationMergeFunc op_merge_func);

#endif // _HEAVY_OPERATION_ROUTINE_H_
