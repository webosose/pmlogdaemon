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

#ifndef _HEAVY_OPERATION_TYPE_H_
#define _HEAVY_OPERATION_TYPE_H_

#include <glib.h>

typedef enum
{
	CompressFileType,
	FreeDiskSpaceType,
	CreateRdxReportType,
	DoNotifySubscribersType,
        LunaRegistration,
        MonitorFile,
        HeavyOperationTypeLast
} HeavyOperationType;

typedef struct
{
	gpointer            opaque;
	GSourceFunc         routine_func;
	HeavyOperationType  type;

} HeavyOperation;

/**
 * @brief HeavyOperationMergeFunc
 *
 * Function pointer to merge logic.
 *
 * @param Pointer to context that sould be merged
 * @param Pointer to context where merge is applyed
 *
 * @return true if merge was done, otherwise false
*/

typedef gboolean(*HeavyOperationMergeFunc)(gpointer, gpointer);

gboolean
CompressFileMergeFuncDefault(gpointer from, gpointer to);

gboolean
FreeDiskSpaceMergeFuncDefault(gpointer from, gpointer to);

#endif //_HEAVY_OPERATION_TYPE_H_
