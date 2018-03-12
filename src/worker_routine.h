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

#ifndef _WORKER_ROUTINE_H_
#define _WORKER_ROUTINE_H_

#include <glib.h>

typedef struct
{
	gchar        *name;
	GThread      *thrd;
	GMainLoop    *loop;
	GMainContext *context;
} WorkerRoutine;

gboolean
WorkerRoutineConstruct(WorkerRoutine* self, const gchar *name);

void
WorkerRoutineDestruct(WorkerRoutine *self);

gboolean
WorkerRoutineRun(WorkerRoutine *self);

void
WorkerRoutineAddTimerEvent(WorkerRoutine *self, guint timeout, GSourceFunc func, gpointer opaque);

#endif //_WORKER_ROUTINE_H_

