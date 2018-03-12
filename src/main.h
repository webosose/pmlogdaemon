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
 **********************************************************************
 * @file main.h
 *
 * @brief This file contains implementation definitions used by PmLogDaemon.
 *
 **********************************************************************
 */

#ifndef PMLOGDAEMON_H
#define PMLOGDAEMON_H

#include <stdbool.h>

#include <glib.h>

#include "ring.h"

#define CONFIG_DIR WEBOS_INSTALL_SYSCONFDIR "/pmlog.d"

#define PMLOGD_NAME     "PmLogDaemon"
#define PMLOGD_CONTEXT  "pmlogdaemon"
#define PMLOGD_APP_ID   "com.webos.pmlogd"

#define LEVEL_WARNING   (LOG_SYSLOG | LOG_WARNING)
#define LEVEL_ERROR     (LOG_SYSLOG | LOG_ERR)
#define LEVEL_INFO      (LOG_SYSLOG | LOG_INFO)
#define LEVEL_DEBUG     (LOG_SYSLOG | LOG_DEBUG)

bool ParseLevel(const char *s, int *levelP);

bool TrimSuffixCaseInsensitive(char *s, const char *suffix);


/**
 * @brief ParseKeyValue
 *
 * If the given string is of the form "KEY=VALUE" copy the given
 * key and value strings into the specified buffers and return true,
 * otherwise return false.
 * Key may not be empty string, but value may be.
 */
bool ParseKeyValue(const char *arg, char *keyBuff, size_t keyBuffSize,
                   char *valBuff, size_t valBuffSize);


/**
 * @brief LockProcess
 *
 * Acquire the process lock (by getting an file lock on our pid file).
 * Return true on success, false if failed.
 */
bool LockProcess(const char *component);


/**
 * @brief UnlockProcess
 *
 * Release the lock on the pid file as previously acquired by
 * LockProcess.
 */
void UnlockProcess(void);


/*
 * PmLogDaemon build configuration and implementation
 * We don't support forwarding messages to a remote socket.
 * Not difficult, but we don't have a need.
 */

//#define PMLOGDAEMON_FEATURE_REMOTE_LOG

/* default path for stdlog */
#define DEFAULT_LOG_FILE_PATH           WEBOS_INSTALL_LOGDIR "/messages"

/* reasonable small defaults */
#define PMLOG_DEFAULT_LOG_SIZE          (200 * 1024)
#define PMLOG_DEFAULT_LOG_ROTATIONS         1

/*
 * min & max allowed log sizes - note that the /var/log partition is currently only
 * about 24MB, so 64MB is only usable if you specify a different filesystem
 */
#define PMLOG_MIN_LOG_SIZE (4 * 1024)
#define PMLOG_MAX_LOG_SIZE (64 * 1024 * 1024)

/* arbitrary maximum number of outputs */
#define PMLOG_MAX_NUM_OUTPUTS           128

/* maximum number of rotations allowed */
#define PMLOG_MIN_NUM_ROTATIONS         1
#define PMLOG_MAX_NUM_ROTATIONS         20

/* arbitrary maximum string length */
#define PMLOG_OUTPUT_MAX_NAME_LENGTH    31

/* required first output definition */
#define PMLOG_OUTPUT_STDLOG             "stdlog"

#define CONF_INT_UNINIT_VALUE   -1

/* arbitrary maximum name length */
#define PMLOG_PROGRAM_MAX_NAME_LENGTH   31

/* arbitrary value */
#define PMLOG_CONTEXT_MAX_NUM_RULES     16

typedef struct
{
	/* -1 = all or specific value e.g. LOG_KERN */
	int         facility;

	/* -1 = all or specific value e.g. LOG_ERR */
	int         level;
	bool        levelInvert;

	/* NULL = all or specific value */
	gchar *program;

	/* index of output target */
	int         outputIndex;

	/* false to include, true to omit */
	bool        omitOutput;
}
PmLogRule_t;


typedef struct
{
	const char *outputName;

	/* path of log file, e.g. /var/log/messages */
	const char *path;

	/* maximum size of log file in bytes */
	int         maxSize;

	/* number of rotations 1..10 */
	int         rotations;
}
PmLogFile_t;


typedef struct
{
	gchar  *contextName;
	PmLogRingBuffer_t *rb;
	int         numRules;
	PmLogRule_t rules[ PMLOG_CONTEXT_MAX_NUM_RULES ];
}
PmLogContextConf_t;


/* global configuration settings */

extern int          g_numOutputs;
extern PmLogFile_t  g_outputConfs[ PMLOG_MAX_NUM_OUTPUTS ];

extern int          g_numContexts;
extern GTree        *g_contextConfs;

/**
 * @brief ParseRuleFacility
 *
 * "*" => -1, "user" => LOG_USER, etc.
 * Return true if parsed OK, else false.
 */
bool ParseRuleFacility(const char *s, int *facilityP);

/**
 * ParseRuleLevel
 *
 * "*" => -1, "err" => LOG_ERR, etc.
 * Return true if parsed OK, else false.
 */
bool ParseRuleLevel(const char *s, int *levelP);

bool ParseJsonOutputs(const char *file_name);

bool ParseJsonContexts(const char *file_name);

void SetDefaultConf(void);

gint char_array_comp_func(gconstpointer a, gconstpointer b, gpointer user_data);

#endif /* PMLOGDAEMON_H */
