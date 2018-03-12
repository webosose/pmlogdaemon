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

#include "worker_routine.h"

static gpointer ThreadFunc(gpointer user_data)
{
	WorkerRoutine *wr = (WorkerRoutine*)user_data;
	g_main_loop_run(wr->loop);
	return 0;
}

gboolean WorkerRoutineConstruct(WorkerRoutine* self, const gchar *name)
{
	do
	{
		if (!(self->context = g_main_context_new()))
			break;

		if (!(self->loop = g_main_loop_new(self->context, FALSE)))
			break;

		if (!(self->name = g_strdup(name)))
			break;

		return TRUE;
	} while (FALSE);

	WorkerRoutineDestruct(self);
	return FALSE;
}

void WorkerRoutineDestruct(WorkerRoutine *self)
{
	if (self->name)
	{
		g_free(self->name);
		self->name = NULL;
	}

	if (self->loop)
	{
		g_main_loop_quit(self->loop);
	}

	if (self->thrd)
	{
		g_thread_join(self->thrd);
		g_thread_unref(self->thrd);
		self->thrd = NULL;
	}

	if (self->loop)
	{
		g_main_loop_unref(self->loop);
		self->loop = NULL;
	}

	if (self->context)
	{
		g_main_context_unref(self->context);
		self->context = NULL;
	}
}

gboolean
WorkerRoutineRun(WorkerRoutine *self)
{
	return (self->thrd = g_thread_try_new(self->name, ThreadFunc, self, NULL)) != NULL;
}

void
WorkerRoutineAddTimerEvent(WorkerRoutine *self, guint timeout, GSourceFunc func, gpointer opaque)
{
	GSource *gsrc = g_timeout_source_new_seconds(timeout);

	g_source_set_callback(gsrc, func, opaque, NULL);
	g_source_attach(gsrc, self->context);
	g_source_unref(gsrc);
}
