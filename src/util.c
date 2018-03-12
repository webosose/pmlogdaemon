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
 ***********************************************************************
 * @file util.c
 *
 * @brief This file contains generic utility functions.
 *
 ***********************************************************************
 */

#include "main.h"

#include <stdlib.h>
#include <string.h>

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <PmLogLib.h>

#include "print.h"

typedef struct
{
	char    path[ PATH_MAX ];
	int     fd;
}
LockFile;

static LockFile g_processLock;


/**
 * @brief LockProcess
 *
 * Acquire the process lock (by getting an file lock on our pid file).
 *
 * @param component
 *
 * @return true on success, false if failed.
 */
bool LockProcess(const char *component)
{
	const char *locksDirPath = WEBOS_INSTALL_LOCALSTATEDIR "/run";

	LockFile   *lock;
	pid_t       pid;
	int         fd;
	int         result;
	char        pidStr[ 16 ];
	int         pidStrLen;
	int         err;

	lock = &g_processLock;
	pid = getpid();

	/* create the locks directory if necessary */
	(void) mkdir(locksDirPath, 0777);

	snprintf(lock->path, sizeof(lock->path), "%s/%s.pid", locksDirPath,
	         component);

	/* open or create the lock file */
	fd = open(lock->path, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);

	if (fd < 0)
	{
		err = errno;
		DbgPrint("Failed to open lock file (err %d, %s), exiting.\n",
		         err, strerror(err));
		return false;
	}

	/* use a POSIX advisory file lock as a mutex */
	result = lockf(fd, F_TLOCK, 0);

	if (result < 0)
	{
		err = errno;

		if ((err == EDEADLK) || (err == EAGAIN))
		{
			DbgPrint("Failed to acquire lock, exiting.\n");
		}
		else
		{
			DbgPrint("Failed to acquire lock (err %d, %s), exiting.\n",
			         err, strerror(err));
		}

		close(fd);
		return false;
	}

	/* remove the old pid number data */
	result = ftruncate(fd, 0);

	if (result < 0)
	{
		err = errno;
		DbgPrint("Failed truncating lock file (err %d, %s).\n",
		         err, strerror(err));
	}

	/* write the pid to the file to aid debugging */
	snprintf(pidStr, sizeof(pidStr), "%d\n", pid);
	pidStrLen = (int) strlen(pidStr);
	result = (int)write(fd, pidStr, (size_t)pidStrLen);

	if (result < pidStrLen)
	{
		err = errno;
		DbgPrint("Failed writing lock file (err %d, %s).\n",
		         err, strerror(err));
	}

	lock->fd = fd;
	return true;
}


/**
 * @brief UnlockProcess
 *
 * Release the lock on the pid file as previously acquired by
 * LockProcess.
 */
void UnlockProcess(void)
{
	LockFile   *lock;

	lock = &g_processLock;
	close(lock->fd);
	(void) unlink(lock->path);
}


/**
 * @brief TrimSuffixCaseInsensitive
 *
 * @param s
 * @param suffix
 *
 * @return
 */
bool TrimSuffixCaseInsensitive(char *s, const char *suffix)
{
	size_t  sLen;
	size_t  suffixLen;
	char   *sSuffix;

	sLen = strlen(s);
	suffixLen = strlen(suffix);

	if (sLen < suffixLen)
	{
		return false;
	}

	sSuffix = s + sLen - suffixLen;

	if (strcasecmp(sSuffix, suffix) != 0)
	{
		return false;
	}

	*sSuffix = 0;
	return true;
}


/**
 * @brief ParseLevel
 *
 * "none" => -1 (kPmLogLevel_None)
 * "err"  => LOG_ERR (kPmLogLevel_Error),
 * etc.
 *
 * @param s
 * @param levelP
 *
 * @return true if parsed OK, else false.
 */
bool ParseLevel(const char *s, int *levelP)
{
	const int *nP;

	nP = PmLogStringToLevel(s);

	if (nP != NULL)
	{
		*levelP = *nP;
		return true;
	}

	*levelP = -1;
	return false;
}


/**
 * @brief ParseKeyValue
 *
 * If the given string is of the form "KEY=VALUE" copy the given
 * key and value strings into the specified buffers and return true,
 * otherwise return false.
 * Key may not be empty string, but value may be.
 *
 * @param arg
 * @param keyBuff
 * @param keyBuffSize
 * @param valBuff
 * @param valBuffSize
 *
 * @return
 */
bool ParseKeyValue(const char *arg, char *keyBuff, size_t keyBuffSize,
                   char *valBuff, size_t valBuffSize)
{
	const char *sepStr;
	size_t      keyLen;
	const char *valStr;
	size_t      valLen;

	sepStr = strchr(arg, '=');

	if ((sepStr == NULL) || (sepStr <= arg))
	{
		return false;
	}

	keyLen = (size_t)(sepStr - arg);

	if (keyLen >= keyBuffSize)
	{
		return false;
	}

	memcpy(keyBuff, arg, keyLen);
	keyBuff[keyLen] = 0;

	valStr = sepStr + 1;
	valLen = strlen(valStr);

	if (valLen >= valBuffSize)
	{
		return false;
	}

	memcpy(valBuff, valStr, valLen);
	valBuff[valLen] = 0;

	return true;
}
