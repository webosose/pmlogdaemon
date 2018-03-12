// Copyright (c) 2007-2018 LG Electronics, Inc.
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

/**
 *************************************************************************
 * @file ring.c
 *
 * @brief This file contains implementation of ring buffer related functions.
 *
 *************************************************************************
 */

#include "ring.h"

#include <string.h>

#include "print.h"

static const int RBMinBufferSize = 2048; /* Minimum is 2K */

static void RBClear(PmLogRingBuffer_t *rb)
{
	if (rb)
	{
		rb->isEmpty = true;
		rb->nextWritePos = rb->buff;
		g_assert(rb->buff);
		g_assert(rb->bufferSize >= RBMinBufferSize);
		memset(rb->buff, 0, (size_t)rb->bufferSize);
	}
}


/**
 * @brief RBNew
 *
 * Constructor for a new Ring Buffer object
 *
 * @param bufferSize
 * @param flushLevel
 *
 * @return
 */
PmLogRingBuffer_t *RBNew(int bufferSize, int flushLevel)
{
	DbgPrint("%s: called with bs %d fl %d\n", __FUNCTION__, bufferSize, flushLevel);
	PmLogRingBuffer_t *ret = NULL;

	if ((bufferSize <= 0) && (flushLevel <= 0))
	{
		/* no need to create RB */
	}
	else
	{
		ret = g_new0(PmLogRingBuffer_t, 1);

		if (ret)
		{
			if (bufferSize < RBMinBufferSize)
			{
				ret->bufferSize = RBMinBufferSize;
				DbgPrint("%s: bufferSize must be at least %d bytes.\n", __FUNCTION__,
				         RBMinBufferSize);
			}
			else
			{
				ret->bufferSize = bufferSize;
			}

			ret->flushLevel = flushLevel;
			ret->buff = NULL;
			ret->isEmpty = true;
		}
	}

	return ret;
}

static inline bool RBValidPos(PmLogRingBuffer_t *rb, const char *p)
{
	g_assert(rb);
	g_assert(rb->bufferSize > 0);
	g_assert(rb->isEmpty || rb->buff);
	const char *rbEnd = rb->buff + rb->bufferSize;
	return ((p < rbEnd) && (p >= rb->buff));
}

/**
 * @brief RBValid
 *
 * Checks if the RB is valid
 *
 * @param rb
 *
 * @return true if the RB is valid
 */
static bool RBValid(PmLogRingBuffer_t *rb)
{
	if (rb == NULL)
	{
		DbgPrint("%s: null ring buffer\n", __FUNCTION__);
		return false;
	}

	if (rb->bufferSize < RBMinBufferSize)
	{
		DbgPrint("%s: bufferSize must be at least %d bytes.\n", __FUNCTION__,
		         RBMinBufferSize);
		return false;
	}

	if (!rb->isEmpty && !(rb->buff))
	{
		DbgPrint("%s: buff is missing.\n", __FUNCTION__);
		return false;
	}

	if (!RBValidPos(rb, rb->nextWritePos))
	{
		DbgPrint("%s: end nextWritePos out of range/n", __FUNCTION__);
		return false;
	}

	return true;
}

static char *RBStep(const PmLogRingBuffer_t *rb, char *p)
{
	p++;

	if (p >= (rb->buff + rb->bufferSize))
	{
		p = rb->buff;
	}

	return p;
}

/**
 * @brief RBAllocBuff
 *
 * Allocate memory for buff in rb
 *
 * @param rb pointer to the RB object
 *
 */
void RBAllocBuff(PmLogRingBuffer_t *rb)
{
	/* Lazy allocation for buffer, only when actual write happens */
	if (!rb->buff)
	{
		rb->buff = (char *) g_malloc((gsize)rb->bufferSize);
		RBClear(rb);
	}
}

/**
 * @brief RBWrite
 *
 * Add a new entry to the ring buffer
 *
 * @param rb pointer to the RB object
 * @param buffMsg  message to add to the RB
 * @param numBytes length of message
 */
void RBWrite(PmLogRingBuffer_t *rb, const char *buffMsg, int numBytes)
{
	DbgPrint("%s: called with buffMsg %s\n", __FUNCTION__, buffMsg);

	if (!rb->buff)
	{
		RBAllocBuff(rb);
	}

	g_assert(RBValid(rb));
	g_assert(numBytes <= (strlen(buffMsg) + 1));

	char *n = rb->nextWritePos;
	char *b = rb->buff;
	const int buffSize = rb->bufferSize;
	const char *rbEnd = b + (buffSize - 1);
	const int tailLen = (int)(rbEnd - n + 1);

	/* write, depending on wether we wrap or not */
	if (numBytes > tailLen)
	{
		memcpy(n, buffMsg, (size_t)tailLen);
		int remain = numBytes - tailLen;
		memcpy(b, buffMsg + tailLen, (size_t)remain);
		n = b + remain;
	}
	else
	{
		memcpy(n, buffMsg, (size_t)numBytes);
		n = RBStep(rb, n + (numBytes - 1));
	}

	rb->isEmpty = false;
	rb->nextWritePos = n;
}


/**
 * @brief RBFlush
 *
 * Flush
 *
 * @param rb The ring buffer to flush
 * @param flushMsgFunc
 * @param data
 *
 * @return true if we flushed
 */
bool RBFlush(PmLogRingBuffer_t *rb, RBTraversalFunc flushMsgFunc,
             gpointer data)
{
	DbgPrint("%s flush called on rb with bs %d and fl %d\n", __FUNCTION__,
	         rb->bufferSize, rb->flushLevel);

	if (!rb->buff)
	{
		RBAllocBuff(rb);
	}

	g_assert(RBValid(rb));

	/* have RB, need to flush */
	char msg[rb->bufferSize];
	int j = 0;
	int i = 0;
	char *n = rb->nextWritePos;
	int buffSize = rb->bufferSize;

	for (i = 0; i < buffSize; i++)
	{
		msg[j] = *n;
		n = RBStep(rb, n);

		if (msg[j] == '\0')
		{
			if (j != 0)
			{
				flushMsgFunc(msg, data);
			}

			j = 0;
		}
		else
		{
			j++;
		}

		if (n == rb->nextWritePos)
		{
			break;
		}
	}

	RBClear(rb);
	return true;
}
