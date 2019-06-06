// Copyright (c) 2007-2019 LG Electronics, Inc.
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
 * @file main.c
 *
 * @brief This file contains the Open webOS logging daemon implementation.
 * The syslogd implementation is per RFC 3164.
 * Reference http://www.faqs.org/rfcs/rfc3164.html.
 * Reference http://tools.ietf.org/wg/syslog/draft-ietf-syslog-protocol/
 * e.g. http://tools.ietf.org/html/draft-ietf-syslog-protocol-23.
 *
 * This implementation is a subset of functionality, intended to
 * efficiently address the needs for the Open webOS embedded device.
 *  - it does not support remote logging (not needed)
 *  - it only supports the standard datagram socket on port 514
 *  - it does not support /etc/syslog.conf or standard filtering/redirection
 *
 * Features that may be added:
 *  - support for RFC 3339-style timestamps
 *  - support for advanced file buffering + rotation configuration
 *  - support for custom filtering/redirection
 *
 ***********************************************************************
 */

#include "main.h"

#include <ctype.h>
#include <errno.h>
#include <linux/inotify.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/syslog.h>
#include <sys/time.h>
#include <sys/un.h>

#include <zlib.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <rdx.h>

#include <pbnjson.h>
#include <PmLogLibPrv.h>
#include <luna-service2/lunaservice.h>

#include "print.h"
#include "heavy_operation_routine.h"

/***********************************************************************
 * status codes
 ***********************************************************************/
enum
{
    RESULT_OK,
    RESULT_RUN_ERR,
    RESULT_PARAM_ERR,
    RESULT_HELP
};


/***********************************************************************
 * constants
 ***********************************************************************/

/* maximum line length that can be handled, per RFC 3164 */
#define MAXLINE         1024
#define MAX_MSGID_LEN   32

#define PMLODAEMON_CONTEXT "pmlogdaemon"
#define EVENT_SIZE  ( sizeof (struct inotify_event) )
#define EVENT_BUF_LEN     ( 4 * ( EVENT_SIZE + NAME_MAX + 1 ) )
#define MAX_MSG_LEN 256
/*
 * see the comments in PmKLogDaemon regarding the issue that glibc
 * does not allow a user-space client to mark a message with kernel
 * facility (LOG_KERN) as needed.  To support passing that through we
 * use a pseudo-facility value and re-map it back.
 */
#define PMLOGDAEMON_LOG_KERN    (LOG_NFACILITIES<<3)

#define PMLOGDAEMON_FILE_ROTATION_PATTERN "%s.%d.gz"

#define ROTATION_SUBSCRIPTION_KEY "rotation"

/* Inotify Watch Path */
#define INOTIFY_WATCH_PATH "/tmp/pmlogdaemon"

/* file in path indicates PmLogDaemon and ls-hubd is Ready */
#define HUBD_READY_FILE "/tmp/pmlogdaemon/hub-ready"

/* flag file which tells first boot */
#define FIRST_BOOT_STATUS_FILE "/var/luna/preferences/ran-firstuse"
/***********************************************************************
 * globals settings
 ***********************************************************************/
static int          g_showStartInfo;

/* 0 for regular timestamps, 1 for full = RFC 3339 format timestamps */
static int          g_useFullTimeStamps;

/* 0 for no fractional seconds, 1 for 1 digit precision, etc. */
static int          g_timeStampFracSecDigits;

/* 0 for no monotonic seconds, 1 to include monotonic seconds */
static int          g_timeStampMonotonic;

#ifdef PMLOGDAEMON_FEATURE_REMOTE_LOG
/* UDP socket port number, i.e. 514 */
static int          g_port;
#endif

/* path to the unix domain socket = _PATH_LOG = /dev/log */
static char         g_pathLog[ PATH_MAX ];

/***********************************************************************
 * globals
 ***********************************************************************/

/* counter for rotation subscriptions. Subscriber manage rotated log file
 * by himself, so we allow ony 1 or none subscribers. */
static int          g_haveRotSubscription;

static PmLogFile_t  g_logFiles[ PMLOG_MAX_NUM_OUTPUTS ];
static GHashTable          *whitelist_table = NULL;
static bool g_collectDevLogs =
//! This macro can be defined to restrict logging
//! to whitelist logs
#ifdef ENABLE_WHITELIST
    false
#else
	true
#endif
	;

PmLogContext g_context;
static HeavyOperationRoutine heavy_routine;

/**********************************************************************
 *  Function declarations
 **********************************************************************/
static LSHandle *g_lsServiceHandle = NULL;
static LSError g_lsError;

/**
 * @brief _SysLogMessage
 * Wrapper around the LogMessage command to provide
 * formated arguments.
 * Note this must be called with printf type arguments
 *
 * @param level the log level
 * @param fmt the format string
 * @param ... optional additional arguments
 */
static void _SysLogMessage(const int level, const char *fmt, ...)
__attribute__((format(printf, 2, 3))) __attribute__((used));

/* Insert process name, context name, and message ID */
#define SysLogMessage(level, msgID, ...) \
        _SysLogMessage(level, PMLOGD_NAME ":" " " PMLOG_IDENTIFIER " [] " PMLOGD_CONTEXT " " msgID " " __VA_ARGS__);

#define ROTATED_LOG_FILE_PATH           WEBOS_INSTALL_LOGDIR "/messages.0"

/**
 * @brief ParseRuleFacility
 *
 * "*" => -1, "user" => LOG_USER, etc.
 *
 * @param facilityStr
 * @param facilityP
 *
 * @return true if parsed OK, else false.
 */
bool ParseRuleFacility(const char *facilityStr, int *facilityP)
{
	const int  *nP;

	if (strcmp(facilityStr, "*") == 0)
	{
		*facilityP = -1;
		return true;
	}

	nP = PmLogStringToFacility(facilityStr);

	if (nP != NULL)
	{
		*facilityP = *nP;
		return true;
	}

	*facilityP = -1;
	return false;
}


/**
 * @brief ParseRuleLevel
 *
 * "*" => -1, "err" => LOG_ERR, etc.
 *
 * @param levelStr
 * @param levelP
 *
 * @return true if parsed OK, else false.
 */
bool ParseRuleLevel(const char *levelStr, int *levelP)
{
	const int  *nP;

	if (strcmp(levelStr, "*") == 0)
	{
		*levelP = -1;
		return true;
	}

	nP = PmLogStringToLevel(levelStr);

	if (nP != NULL)
	{
		*levelP = *nP;
		return true;
	}

	*levelP = -1;
	return false;
}


/**
 * @brief GetRuleFacilityStr
 *
 * @param fac
 *
 * @return NULL if not recognized.
 */
static const char *GetRuleFacilityStr(int fac)
{
	const char *s;

	if (fac == -1)
	{
		return "*";
	}

	s = PmLogFacilityToString(fac);
	return s;
}


/**
 * @brief GetRuleLevelStr
 *
 * -1 => "*", LOG_ERR => "err", etc.
 *
 * @param level
 *
 * @return NULL if not recognized.
 */
static const char *GetRuleLevelStr(int level)
{
	const char *s;

	if (level == -1)
	{
		return "*";
	}

	s = PmLogLevelToString(level);
	return s;
}


/**
 * @brief FormatPri
 *
 * @param pri
 * @param str
 * @param size
 */
static void FormatPri(int pri, char *str, size_t size)
{
	const char *facStr;
	const char *lvlStr;

	facStr = GetRuleFacilityStr(pri & LOG_FACMASK);
	lvlStr = GetRuleLevelStr(pri & LOG_PRIMASK);

	if ((facStr != NULL) && (lvlStr != NULL))
	{
		snprintf(str, size, "%s.%s", facStr, lvlStr);
	}
	else
	{
		snprintf(str, size, "<%d>", pri);
	}
}

/**
 * @brief myremove
 *
 * wrapper around the remove function to provide some error logging
 *
 * @param filename
 *
 * @return
 */
static int myremove(const char *filename)
{
	int result;
	int err = 0;
	result = remove(filename);

	if (result < 0)
	{
		err = errno;

		if (errno != ENOENT)
		{
			PmLogError(g_context, "REMOVE_FILE", 1, PMLOGKS("ErrorText", strerror(err)),
			           "");
		}
	}

	return err;
}

/**
 * @brief CompressFile
 *
 * compress the given file (using zlib).  The file will be replaced
 * with the compressed file (having the same filename appended with .gz)
 * similarly to how the gzip command works
 *
 * @param infilename
 *
 * @return true if succeeded, else false
 */
static gboolean CompressFile(gpointer userdata)
{
	gchar *infilename = (gchar*)userdata;
	char *outfilename = g_strconcat(infilename, ".gz", NULL);
	char inbuffer[128];
	size_t num_read = 0;
	int num_written = 0;
	unsigned long total_read = 0;
	unsigned long total_written = 0;
	int err = 0;
	gzFile outfile = NULL;
	FILE *infile = NULL;
	gboolean result = false;

	if (!outfilename)
	{
		err = EIO;
		PmLogError(g_context, "COMPRESS_FILE", 1, PMLOGKS("ErrorText", strerror(err)),
		           "Failed to construct compressed filename.");
		goto Error;
	}

	infile = fopen(infilename, "rb");

	if (!infile)
	{
		err = EIO;
		PmLogError(g_context, "COMPRESS_FILE", 1, PMLOGKS("ErrorText", strerror(err)),
		           "Failed to open input file");
		goto Error;
	}

	outfile = gzopen(outfilename, "wb");
	if (outfile == Z_NULL)
	{
		err = EIO;
		PmLogError(g_context, "COMPRESS_FILE", 1, PMLOGKS("ErrorText", strerror(err)),
		           "Failed to create compressed file");
		outfile = NULL;
		goto Error;
	}

	while ((num_read = fread(inbuffer, (size_t)1, sizeof(inbuffer), infile)) > 0)
	{
		total_read += num_read;
		num_written = gzwrite(outfile, inbuffer, (unsigned)num_read);

		if (num_written != num_read)
		{
			PmLogError(g_context, "COMPRESS_FILE", 1, PMLOGKS("ErrorText", gzerror(outfile,
			           &err)), "gzwrite error");
			goto Error;
		}

		total_written += num_read;
	}

	/* delete old file */
	err = myremove(infilename);
	if (err != 0)
	{
		PmLogError(g_context, "CMP_RM_FILE", 1,
		           PMLOGKS("ErrorText", strerror(err)),
		           "Failed to remove source file after compression");
	}
	if (0 != total_read)
	{
		PmLogDebug(g_context,
			"CompressFile: Read %lu bytes, Wrote %lu bytes, Compression factor %4.2f%%\n",
			total_read, total_written,
			(1.0 - (double)total_written / (double)total_read) * 100.0);
	}
	result = true;
Error:
	g_free(infilename);

	if (outfilename)
	{
		free(outfilename);
	}

	if (infile)
	{
		fclose(infile);
	}

	if (outfile)
	{
		gzclose(outfile);
	}

	return result;
}

/**
 * @brief DoNotifySubscribers
 *
 * Notify rotation subscribers with log 'filename' in payload.
 *
 * @param userdata
 *
 * @return true if succeeded, else false
 */

static gboolean DoNotifySubscribers(gpointer userdata)
{
	gboolean result = true;
	gchar *newPath = (gchar*)userdata;

	LSError lserror;
	LSErrorInit(&lserror);

	gchar *payload = g_strdup_printf("{\"filepath\":\"%s\"}", newPath);

	if (!LSSubscriptionReply(g_lsServiceHandle, ROTATION_SUBSCRIPTION_KEY,
	                         payload, &lserror))
	{

		LSErrorLog(g_context, "LSSUBREPLY_ERROR", &lserror);
		LSErrorFree(&lserror);
		result = false;
	}

	g_free(payload);
	g_free(newPath);

	return result;
}

/**
 * @brief DoRotateLogFile
 *
 * Rotate the specified log set.  It should already have been verified
 * that the base log exists. If startTaskInNewThread is true, add a new
 * task for heavy operation thread, to prevent syslog locking.
 *
 * @param logFileP
 * @param startTaskInNewThread
 *
 * @return 1 if the rotation was performed, else 0.
 */
static int DoRotateLogFile(PmLogFile_t *logFileP, bool startTaskInNewThread)
{
	int             result;
	char            oldPath[ PATH_MAX ];
	char            newPath[ PATH_MAX ];

	/* If daemon has no rotation subscribers, just compress
	 * the file, else notify subscribers and let them manage
	 * rotated log file if not collecting dev logs.
	 */
	if (g_atomic_int_get(&g_haveRotSubscription) == 0 || g_collectDevLogs)
	{
		if (logFileP->rotations <= 0)
		{
			/* we require rotations >= 1 */
			ErrPrint("ROTATE_LOG ROTATION %d invalid number of rotations",logFileP->rotations);
			return 0;
		}

		/* rotate the log file set
		   rotations = 1 then { log, log.0.gz }
		   rotations = 2 then { log, log.0.gz, log.1.gz }
		   ... */
		for (int i = logFileP->rotations - 1; i > 0; i--)
		{
			snprintf(oldPath, sizeof(oldPath), PMLOGDAEMON_FILE_ROTATION_PATTERN,
			         logFileP->path, i - 1);
			snprintf(newPath, sizeof(newPath), PMLOGDAEMON_FILE_ROTATION_PATTERN,
			         logFileP->path, i);
			/* note that rename will replace the old file if present */
			result = rename(oldPath, newPath);

			if (result < 0)
			{
				if (errno != ENOENT)
				{
					ErrPrint("RotateLogFile: rename error: %s\n", strerror(errno));
				}
			}
		}

		/* the assumption is that the current file is flushed by the rename */
		snprintf(newPath, sizeof(newPath), "%s.%d", logFileP->path, 0);
		result = rename(logFileP->path, newPath);

		if (result < 0)
		{
			ErrPrint("RotateLogFile: rename error: %s\n", strerror(errno));
		}

		if (startTaskInNewThread)
		{
			HeavyOperationRoutineAdd(&heavy_routine,
								   CompressFile,
								   g_strdup(newPath),
								   CompressFileType,
								   CompressFileMergeFuncDefault);
		}
		else
		{
			CompressFile(g_strdup(newPath));
		}
	}
	/* Else we have rotation subscribers, i.e. g_rotSubCount > 0 */
	else
	{
		snprintf(newPath, sizeof(newPath), "%s.XXXXXX", logFileP->path);
                umask(0022);

		int tmp_fd = mkstemp(newPath);
		if (tmp_fd == -1)
		{
			ErrPrint("RotateLogFile: tmp file creation error: %s\n", strerror(errno));
		}
		else
		{
			if (close(tmp_fd) == -1)
			{
				ErrPrint("RotateLogFile: failed to close tmp file: %s\n", strerror(errno));
			}
			result = rename(logFileP->path, newPath);

			if (result < 0)
			{
				ErrPrint("RotateLogFile: rename error: %s\n", strerror(errno));
			}
			else
			{
				if (startTaskInNewThread)
				{
					HeavyOperationRoutineAdd(&heavy_routine,
										   DoNotifySubscribers,
										   g_strdup(newPath),
										   DoNotifySubscribersType,
										   NULL);
				}
				else
				{
					DoNotifySubscribers(g_strdup(newPath));
				}
			}
		}
	}

	return 1;
}

/**
 * @brief RotateLogFile
 *
 * If the specified file is too big to add the specified amount of data
 * according to the maximum size limit, then rotate the file set.
 *
 * @param logFileP
 * @param fd
 * @param numToWrite
 *
 * @return 1 if the rotation was performed, else 0.
 */
static int RotateLogFile(PmLogFile_t *logFileP, int fd, size_t numToWrite)
{
	int             result;
	struct stat     fdStat;
	size_t          fileLen;

	if (logFileP->rotations <= 0)
	{
		/* we require rotations >= 1 */
		DbgPrint("RotateLogFile: invalid number of rotations: %d\n",
		         logFileP->rotations);
		return 0;
	}

	result = fstat(fd, &fdStat);

	if (result != 0)
	{
		DbgPrint("RotateLogFile: fstat error: %s\n", strerror(errno));
		return 0;
	}

	if (!S_ISREG(fdStat.st_mode))
	{
		DbgPrint("RotateLogFile: not regular file\n");
		return 0;
	}

	fileLen = (size_t) fdStat.st_size;

	if (fileLen + numToWrite <= logFileP->maxSize)
	{
		return 0;
	}

	result = DoRotateLogFile(logFileP, true);

	return result;
}

/**
 * @brief WriteToLogFile
 *
 * @param logFileP
 * @param p
 * @param n
 *
 * @return 0 on success else err code.
 */
static int WriteToLogFile(PmLogFile_t *logFileP, const char *p, size_t n)
{
	int             fd;
	int             err;
	struct flock    fl;
	int             result;
	int             nWritten;
	int             writeErr;
	int             didRotate;

	if ((p == NULL) || (n <= 0))
	{
		/* shouldn't happen, but check anyway */
		ErrPrint("%s: invalid parameter", __FUNCTION__);
		return 0;
	}

	didRotate = 0;

Retry:

	fd = open(logFileP->path, O_WRONLY | O_CREAT | O_NOCTTY |
	          O_APPEND | O_NONBLOCK, 0644);

	if (fd < 0)
	{
		err = errno;
		ErrPrint("OPEN_FILE ErrorText %s open error", strerror(err));
		return err;
	}

	/* get advisory file lock (write => exclusive lock) */
	memset(&fl, 0, sizeof(fl));
	fl.l_type = F_WRLCK;
	result = fcntl(fd, F_SETLKW, &fl);

	if (result != 0)
	{
		err = errno;
		ErrPrint("GET_FILE_ADVISORY ErrorText %s fcntl F_SETLKW F_WRLCK error", strerror(err));
	}

	if (didRotate)
	{
		didRotate = 0;
	}
	else
	{
		didRotate = RotateLogFile(logFileP, fd, n);
	}

	writeErr = 0;

	if (!didRotate)
	{
		errno = 0;
		nWritten = (int)write(fd, p, n);

		if (nWritten != n)
		{
			err = errno;

			if (err)
			{
				ErrPrint("WRITE_FILE ErrorText %s write error", strerror(err));
				writeErr = err;
			}
			else
			{
				ErrPrint("WRITE_FILE LogFilePath %s write did not complete", logFileP->path);
			}
		}
	}

	/* release advisory file lock */
	memset(&fl, 0, sizeof(fl));
	fl.l_type = F_UNLCK;
	result = fcntl(fd, F_SETLKW, &fl);

	if (result != 0)
	{
		err = errno;
		ErrPrint("WRITE_FILE ErrorText %s fcntl F_SETLKW F_UNLCK error",strerror(err));
	}

	/* close the file, which will sync (flush) it */
	close(fd);

	if (didRotate)
	{
		goto Retry;
	}

	return writeErr;
}


/**
 * @brief ForceRotateLogFile
 *
 * @param logFileP
 * @param startTaskInNewThread
 *
 * @return 0 on success else err code.
 */
static int ForceRotateLogFile(PmLogFile_t *logFileP, bool startTaskInNewThread)
{
	int             result;
	struct stat     fileStat;

	result = stat(logFileP->path, &fileStat);

	if (result != 0)
	{
		ErrPrint("ForceRotateLogFile: stat error for the path %s: %s\n", logFileP->path, strerror(errno));
		return 0;
	}

	if (!S_ISREG(fileStat.st_mode))
	{
		ErrPrint("ForceRotateLogFile: not regular file\n");
		return 0;
	}

	result = DoRotateLogFile(logFileP, startTaskInNewThread);

	return result;
}


/**
 * @brief MatchOutputRule
 *
 * @param ruleP
 * @param pri
 * @param programName
 *
 * @return true if the specified message attributes match the specified
 * rule.
 */
static bool MatchOutputRule(const PmLogRule_t *ruleP, int pri,
                            const char *programName)
{
	int     fac;
	int     lvl;

	fac = pri & LOG_FACMASK;
	lvl = pri & LOG_PRIMASK;

	if (ruleP->facility != -1)
	{
		if (ruleP->facility != fac)
		{
			return false;
		}
	}

	if (ruleP->level == -1)
	{
		if (ruleP->levelInvert)
		{
			return false;
		}
	}
	else
	{
		if (ruleP->levelInvert)
		{
			if (ruleP->level >= lvl)
			{
				return false;
			}
		}
		else
		{
			/*
			 * If the rule specified a level, it means match
			 * that level or higher priority. But remember that
			 * higher priority means lower numeric value.
			 */
			if (ruleP->level < lvl)
			{
				return false;
			}
		}
	}

	if (ruleP->program != NULL)
	{
		if (programName == NULL)
		{
			return false;
		}

		if (strcmp(ruleP->program, programName) != 0)
		{
			return false;
		}
	}

	return true;
}

/* Forward Declaration */
static void LogFileKillRotations(PmLogFile_t *logFileP, int start);


static gboolean FreeDiskSpace(gpointer userdata)
{
	(void)userdata;

	bool ret = true;

	GError *gerr = NULL;
	gchar *usage_out = NULL;

	if (!g_spawn_command_line_sync(WEBOS_INSTALL_DATADIR "/PmLogDaemon/show_disk_usage.sh "
	                               WEBOS_INSTALL_LOGDIR"/", &usage_out, NULL, NULL, &gerr))
	{
		ErrPrint("SPAWN_FAILED ErrorText %s", gerr->message);
		g_error_free(gerr);
	}

	/* clear some space */
	for (int i = 0; i < g_numOutputs; ++i)
	{
		LogFileKillRotations(&g_logFiles[i], 0);
	}

	if (usage_out)
	{
		RdxReportMetadata md = create_rdx_report_metadata();
		rdx_report_metadata_set_component(md, "syslog");
		rdx_report_metadata_set_cause(md, WEBOS_INSTALL_LOGDIR " full");
		rdx_report_metadata_set_detail(md, WEBOS_INSTALL_LOGDIR " full");

		if (!rdx_make_report(md, usage_out))
		{
			/* more aggressive cleanup */
			PmLogDebug(g_context, "%s: couldn't create low disk space report after clearing logs.. Kill 'em all!\n",
			           __func__);
			system("/bin/rm -rf " WEBOS_INSTALL_LOGDIR "/* " WEBOS_INSTALL_LOGDIR "/.*");
			system("/usr/bin/pkill -SIGHUP rdxd"); /* restart rdxd */

			if (!rdx_make_report(md, usage_out))
			{
				PmLogDebug(g_context, "%s: still couldnt make report after nuking " WEBOS_INSTALL_LOGDIR "!\n",
				           __func__);
				ret = false;
			}
		}

		destroy_rdx_report_metadata(md);
		g_free(usage_out);
	}

	return ret;
}

/**
 * @brief OutputMessage
 *
 * @param contextName
 * @param pri
 * @param programName
 * @param msg
 */
static void OutputMessage(
    const PmLogContextConf_t *contextConfP, int pri,
    const char *programName, const char *msg)
{
	bool                        wantOutput[ g_numOutputs ];
	const PmLogRule_t          *ruleP;
	PmLogFile_t                *logFileP;

	if (contextConfP == NULL)
	{
		ErrPrint("INVALID_PARAMETER. ErrorText contextConfP is null");
		return;
	}

	for (int i = 0; i < g_numOutputs; i++)
	{
		wantOutput[ i ] = false;
	}

	/* determine which outputs to target based on the context rules */
	for (int i = 0; i < contextConfP->numRules; i++)
	{
		ruleP = &contextConfP->rules[ i ];

		if (MatchOutputRule(ruleP, pri, programName))
		{
			g_assert(ruleP->outputIndex >= 0);
			g_assert(ruleP->outputIndex < g_numOutputs);

			if (ruleP->omitOutput)
			{
				wantOutput[ ruleP->outputIndex ] = false;
			}
			else
			{
				wantOutput[ ruleP->outputIndex ] = true;
			}
		}
	}

	/* output to the specified targets */
	for (int i = 0; i < g_numOutputs; i++)
	{
		logFileP = &g_logFiles[ i ];

		if (wantOutput[ i ])
		{
			int err_code = WriteToLogFile(logFileP, msg, strlen(msg));
			if (err_code == ENOSPC)
			{
				/* out of space.. clear it and report it */
				ErrPrint("OUTOFSPACE ErrorCode %d", err_code);
				HeavyOperationRoutineAdd(&heavy_routine,
				                         FreeDiskSpace,
				                         NULL,
				                         FreeDiskSpaceType,
				                         FreeDiskSpaceMergeFuncDefault);
			}
		}
	}
}


/**
 * @brief ParseMsgProgram
 *
 * If the message came from a syslog call, it should be of the form:
 *  <progname>: [ '[' <pid> ']' ] ' '
 *
 * If this is matched, return the address of the character past the ' ',
 * else return NULL.
 *
 * @param msg the message to parse
 * @param programFull
 * @param programFullBuffSize
 * @param nameLenP
 * @param programName
 * @param programNameBuffSize
 *
 * @return if a match was made, the program name is returned in programName,
 * otherwise it should be left empty.
 */
static const char *ParseMsgProgram(const char *msg,
                                   char *programFull, size_t programFullBuffSize, size_t *nameLenP,
                                   char *programName, size_t programNameBuffSize)
{
	const char *s;
	size_t      nameLen;
	size_t      fullLen;
	int         index_colon = -1;
	int         index_first_space = -1;

	programFull[ 0 ] = '\0';
	programName[ 0 ] = '\0';
	*nameLenP = 0;

	s = msg;

	/* span characters not including ':' and whitespace */
	nameLen = 0;

	while ((*s != 0) && (*s != ':'))
	{
		// Case of long process name which includes parameter
		// e.g. "chrome --in-render-process ... : [pid:tid]"
		if (isspace(*s) && index_first_space == -1)
		{
			index_first_space = (int)(s - msg);
		}
		nameLen++;
		s++;
	}

	if (nameLen == 0)
	{
		return NULL;
	}

	if (*s != ':')
	{
		return NULL;
	}
	else
	{
		// Remember index of colon to remove the colon
		index_colon = (int)(s - msg);
	}

	s++;

	if (*s != ' ')
	{
		return NULL;
	}

	s++;

	//
	if (index_first_space > -1)
	{
		nameLen = (size_t)index_first_space;
		index_colon = index_first_space;
	}

	fullLen = (size_t)(s - msg);

	if (fullLen >= programFullBuffSize)
	{
		/* overflow */
		fullLen = programFullBuffSize - 1;
	}

	memcpy(programFull, msg, fullLen);

	if (index_colon > -1)
	{
		programFull[ index_colon ] = ' ';  // Remove the colon and replace with space
		programFull[ index_colon + 1 ] = '\0'; // Replace with next of the colon with NUL
	}

	programFull[ fullLen ] = '\0';

	*nameLenP = nameLen;

	if (nameLen >= programNameBuffSize)
	{
		/* name buff overflow! */
		nameLen = programNameBuffSize - 1;
	}

	memcpy(programName, msg, nameLen);
	programName[ nameLen ] = 0;

	return s;
}


/**
 * @brief ParseMsgPidTid
 *
 * If PmLogLib is set to log process/thread IDs, it should be of the form:
 *  '[' <pid> [ ':' <tid> ] ']' ' '
 *
 * @param msg the message to parse
 *
 * @return if this is matched, return the address of the character past the ' ',
 * else return NULL.
 */
static const char *ParseMsgPidTid(const char *msg)
{
	const char *s;

	s = msg;

	if (*s != '[')
	{
		return NULL;
	}

	s++;

	if (']' == *s)  // If "[Pid:Tid]" is empty, it will come as "[]".
	{
		if (*++s != ' ')
		{
			return NULL;
		}

		return ++s;
	}

	if (!isdigit(*s))
	{
		return NULL;
	}

	s++;

	while (isdigit(*s))
	{
		s++;
	}

	if (*s == ':')
	{
		s++;

		if (!isdigit(*s))
		{
			return NULL;
		}

		s++;

		while (isdigit(*s))
		{
			s++;
		}
	}

	if (*s != ']')
	{
		return NULL;
	}

	s++;

	if (*s != ' ')
	{
		return NULL;
	}

	s++;

	return s;
}


/**
 * @brief ParseMsgContext
 *
 * If the message came from a PmLogLib call that specified a context,
 * it should be of the form:
 *  contextName msgid
 *
 * If a match was made, the context name is returned in contextName,
 * otherwise it should be left empty.
 *
 * @param msg the message
 * @param contextName  the context name to write
 * @param contextNameBuffSize  the size of the context name buffer
 *
 * @return the address of the character past the ' ' if this is matched, otherwise return NULL.
 */
static const char *ParseMsgContext(const char *msg, char *contextName,
                                   size_t contextNameBuffSize)
{
	const char *s;
	size_t      i;

	contextName[ 0 ] = 0;

	s = msg;

	/* span characters that are allowed for context names
	 * see PmLogLib for definition */
	i = 0;

	while (!isspace(*s))
	{
		i++;
		s++;
	}

	if (i == 0)
	{
		return NULL;
	}

	if (i >= contextNameBuffSize)
	{
		/* context buff overflow! */
		i = contextNameBuffSize - 1;
	}

	memcpy(contextName, msg, i);
	contextName[ i ] = 0;

	return s;
}

static __attribute__((__used__))
const char *ParseMsgID(const char *msg, char *msgid, size_t msgIDSize)
{
        const char *s;
        size_t      i;

        msgid[ 0 ] = 0;

        s = msg;

        /* span characters that are allowed for context names
         * see PmLogLib for definition */
        i = 0;

	DbgPrint("In %s, msg is %s\n", __func__, msg);
        while (!isspace(*s))
        {
                i++;
                s++;
        }

        if (i == 0)
        {
		DbgPrint("In %s, returning NULL\n", __func__);
                return NULL;
        }

        if (i >= msgIDSize)
        {
                /* context buff overflow! */
                i = msgIDSize - 1;
        }

        memcpy(msgid, msg, i);
        msgid[ i ] = 0;

	DbgPrint("In %s, msgid is %s\n", __func__, msgid);
        return s;
}

/**
 * @brief HandleLogCommand
 * A command handler used to handle internal log commands (like rotate and dump).
 *
 * @param msg the message
 *
 * @return true iff the message was a command and it was handled.
 */
static bool HandleLogCommand(const char *msg)
{
	const char  *kLogCmdPrefix    = "!log ";
	const size_t kLogCmdPrefixLen = 5;
	PmLogFile_t *logFileP;

	if (strncmp(msg, kLogCmdPrefix, kLogCmdPrefixLen) != 0)
	{
		return false;
	}

	msg += kLogCmdPrefixLen;

	if (strcmp(msg, "rotate") == 0)
	{
		DbgPrint("HandleLogCommand: forcing rotation of main log\n");
		logFileP = &g_logFiles[ 0 ];
		(void) ForceRotateLogFile(logFileP, true);
		return true;
	}

	return false;
}

/**
 * @brief getMonotonicTime
 *
 * Get the current monotonic time in seconds
 *
 * @return -1 on error, 0 otherwise
 */
static int getMonotonicTime(struct timespec *ts)
{
	int result = 0;
	long ms = 0;
	result = clock_gettime(CLOCK_MONOTONIC, ts);

	if (result != 0)
	{
		DbgPrint("%s: Problem reading time", __FUNCTION__);
		return -1;
	}

	return 0;
}

/**
 * @brief FlushMessage
 *
 * Flush the given message.  This just calls OutputMessage
 *
 * @param msg The message to flush
 * @param data the context to flush under
 */
void FlushMessage(const char *msg, gpointer data)
{
	DbgPrint("%s: called with msg=%s\n", __FUNCTION__, msg);
	const PmLogContextConf_t   *contextConfP = data;
	gchar **tokens      = g_strsplit(msg, "/", 3);

	/* TODO: report corrupted buff msg, or print err msg */
	if (tokens == NULL)
	{
		/* no buffer message */
		DbgPrint("%s: No buffer message\n", __FUNCTION__);
	}
	else if (tokens[0] && tokens[1] && tokens[2])
	{
		/* TODO: check size of tokens */
		char *p;
		errno = 0;
		int pri = (int)strtol(tokens[0], &p, 10);

		if ((errno != 0) || ((*p) != '\0'))
		{
			DbgPrint("%s: parse error on pri token\n", __FUNCTION__);
			goto error;
		}

		gchar *programName  = tokens[1];
		gchar *outMsg       = tokens[2];

		OutputMessage(contextConfP, pri, programName, outMsg);
	}
	else
	{
		/* corrupted buffer message */
		DbgPrint("%s: Corrupted buffer message\n", __FUNCTION__);
	}

error:

	if (tokens)
	{
		g_strfreev(tokens);
	}

}

/**
 * @brief MakeMessageTimestamp
 *
 * Creates the timestamp string that is the prefix to output messages.
 *
 * @return pointer to new gchar* containing timestamp
 */
static gchar *MakeMessageTimestamp()
{

	struct timeval  nowTv;
	time_t          now;
	struct tm       nowTm;
	struct timespec ts;
	char            fracSecStr[ 16 ];
	GString        *timeStamp = NULL;
	int 			res = -1;

	memset(&nowTv, 0, sizeof(nowTv));
	(void) gettimeofday(&nowTv, NULL);
	now = nowTv.tv_sec;

	if (g_useFullTimeStamps)
	{
		/*  Generate the timestamp => "1985-04-12T23:20:50.52Z" */
		memset(&nowTm, 0, sizeof(nowTm));
		(void) gmtime_r(&now, &nowTm);

		fracSecStr[ 0 ] = 0;

		if (g_timeStampFracSecDigits > 0)
		{
			snprintf(fracSecStr, sizeof(fracSecStr),
			         ".%06ld", nowTv.tv_usec);
			fracSecStr[ 1 + g_timeStampFracSecDigits ] = 0;
		}


		timeStamp = g_string_sized_new(50);
		g_string_printf(timeStamp,
		                "%04d-%02d-%02dT%02d:%02d:%02d%sZ",
		                1900 + nowTm.tm_year, 1 + nowTm.tm_mon, nowTm.tm_mday,
		                nowTm.tm_hour, nowTm.tm_min, nowTm.tm_sec, fracSecStr);
	}
	else
	{
		/*
		 * Generate the timestamp. ctime => "Wed Jun 30 21:49:08 1993\n"
		 * Note: glibc uses strftime "%h %e %T" using C locale
		 */
		timeStamp = g_string_new_len(ctime(&now) + 4, 15);
	}

	/* append the monotonic time */
	if (g_timeStampMonotonic)
	{
		memset(&ts, 0, sizeof(ts));
		res = getMonotonicTime(&ts);

		if (res != -1)
		{
			g_string_append_printf(timeStamp, " [%ld.%09ld]", ts.tv_sec, ts.tv_nsec);
		}
	}

	return g_string_free(timeStamp, FALSE);
}

/**
 * @brief FlushNotMe
 *
 * This flushes the RB if the context is not me.  The point of this
 * is that it is called on every contexts when a flush is to be done.
 * We exclude "me" since it will be done last.
 *
 * @param value pointer to a context that may be flushed
 * @param data pointer to the context that is not to be flushed, aka "me"
 * @param key unused
 *
 * @return
 */
gboolean FlushNotMe(gpointer key, gpointer value, gpointer data)
{
	PmLogContextConf_t *keyContextP = value;
	const PmLogContextConf_t   *me = data;

	if (keyContextP == me)
	{
		/* Don't flush me. It will be done last so I show up recently in log */
		DbgPrint("%s: %s will be flushing last, skipping", __FUNCTION__, keyContextP->contextName);
	}
	else if (keyContextP->rb)
	{
		/* have RB, need to flush */
		DbgPrint("%s: %s is now flushing...", __FUNCTION__, keyContextP->contextName);

		if (!(keyContextP->rb->isEmpty))
		{

			gchar *timeStamp = MakeMessageTimestamp();
			char            priStr[ 20 ];
			/* look up facility + priority name from pri */
			FormatPri(LOG_SYSLOG | LOG_INFO, priStr, sizeof(priStr));
			gchar *outMsg =
			    g_strdup_printf("%s %s pmsyslogd: {%s}: ------ Flushing ring buffer for context %s ------\n",
			                    timeStamp,
			                    priStr,
			                    keyContextP->contextName,
			                    me->contextName);

			g_free(timeStamp);
			OutputMessage(keyContextP, LOG_SYSLOG | LOG_INFO, "pmsyslogd", outMsg);
			g_free(outMsg);

			RBFlush(keyContextP->rb, FlushMessage, keyContextP);

			timeStamp = MakeMessageTimestamp();
			outMsg = g_strdup_printf("%s %s pmsyslogd: {%s}: ------ Done flushing ------\n",
			                         timeStamp,
			                         priStr,
			                         keyContextP->contextName);
			OutputMessage(keyContextP, LOG_SYSLOG | LOG_INFO, "pmsyslogd", outMsg);

			g_free(timeStamp);
			g_free(outMsg);
		}
	}
	else
	{
		/* no RB, keep going */
		DbgPrint("%s: %s doesnt have ring buffer, not flushing", __FUNCTION__, keyContextP->contextName);
	}

	return FALSE;
}

/**
 * @brief ParseMsgTag
 * Parse identifier which indicates whether current log
 * is from pmloglib.
 *
 * @param msg message to parse
 */
static
const char *ParseMsgTag(const char *msg)
{
	size_t tagLength = strlen(PMLOG_IDENTIFIER) + 1; // tag + space

	if ((strlen(msg) < tagLength)  ||
	        (strncmp(msg, PMLOG_IDENTIFIER " ", tagLength) != 0))
	{
		return NULL;    // Does not start with tag
	}

	return msg + tagLength;
}

typedef struct _RdxReportTask
{
	int pri;
	gchar *programName;
	gchar *msg;
} RdxReportTask;

RdxReportTask *CreateRdxReportTask(int pri, const char *programName, const char *msg)
{
	RdxReportTask *ret = g_new0(RdxReportTask, 1);
	ret->pri = pri;
	ret->programName = g_strdup(programName);
	ret->msg = g_strdup(msg);
	return ret;
}

void DeleteRdxReportTask(RdxReportTask *task)
{
	g_free(task->programName);
	task->programName = NULL;

	g_free(task->msg);
	task->msg = NULL;

	g_free(task);
}

gboolean RdxLogReport(gpointer userdata)
{
	RdxReportTask *task = (RdxReportTask *)userdata;

	RdxReportMetadata md = create_rdx_report_metadata();
	rdx_report_metadata_set_component(md, "syslog");
	const char *cause;

	switch ((task->pri & LOG_PRIMASK))
	{
		case LOG_EMERG:
			cause = "LOG_EMERG";
			break;

		case LOG_ALERT:
			cause = "LOG_ALERT";
			break;

		case LOG_CRIT:
			cause = "LOG_CRIT";
			break;

		case LOG_ERR:
			cause = "LOG_ERR";
			break;

		case LOG_WARNING:
			cause = "LOG_WARNING";
			break;

		case LOG_NOTICE:
			cause = "LOG_NOTICE";
			break;

		case LOG_INFO:
			cause = "LOG_INFO";
			break;

		case LOG_DEBUG:
			cause = "LOG_DEBUG";
			break;

		default:
			cause = "UNKNOWN";
	}

	rdx_report_metadata_set_cause(md, cause);
	rdx_report_metadata_set_detail(md, task->programName);
	rdx_make_report(md, task->msg);
	destroy_rdx_report_metadata(md);

	DeleteRdxReportTask(task);

	return FALSE;
}

/**
 * @brief LogMessage
 * Log the message
 *
 * @param pri priority
 * @param msg message to log
 */
static void LogMessage(int pri, const char *msg)
{
	size_t          msgLen;
	gchar          *timeStamp = NULL;
	char            priStr[ 20 ];
	GString        *outMsg = g_string_sized_new(MAXLINE + 1);
	char            msgProgram[ MAX_MSG_LEN ];
	char            programName[ PMLOG_PROGRAM_MAX_NAME_LENGTH + 1 ];
	char            contextName[ PMLOG_MAX_CONTEXT_NAME_LEN + 1 ];
	const char     *msgLeft;
	const char     *msgCurr;
	const char     *msgNext;
	size_t          msgProgramNameLen;
	size_t          size;

	timeStamp = MakeMessageTimestamp();

	/*
	 * Remove timestamp prefix if present. Local messages should have this, remote may not.
	 * Check for RFC 3164 timestamp  0123456789ABCDEF0 "Mmm dd hh:mm:ss " and remove it
	 */
	msgLen = strlen(msg);

	if ((msgLen >= 16) &&
	        (msg[ 3 ] == ' ') &&
	        isdigit(msg[ 5 ]) &&
	        (msg[ 6 ] == ' ') &&
	        isdigit(msg[ 8 ]) &&
	        (msg[ 9 ] == ':') &&
	        isdigit(msg[ 10 ]) &&
	        isdigit(msg[ 11 ]) &&
	        (msg[ 12 ] == ':') &&
	        isdigit(msg[ 13 ]) &&
	        isdigit(msg[ 14 ]) &&
	        (msg[ 15 ] == ' '))
	{
		msg += 16;
		msgLen -= 16;
	}

	/* look up facility + priority name from pri */
	FormatPri(pri, priStr, sizeof(priStr));

	g_string_printf(outMsg, "%s %s ", timeStamp, priStr);

	g_free(timeStamp);

	msgProgram[ 0 ] = 0;
	programName[ 0 ] = 0;
	contextName[ 0 ] = 0;

	/*
	 * msgLeft is what will actually be written to the file (possibly
	 * after stripping some stuff off from msg prefix)
	 */
	msgLeft = msg; // eg "progName contextName rest_of_msg..."

	/* parse off program identifier prefix */
	msgNext = ParseMsgProgram(msgLeft, msgProgram, sizeof(msgProgram),
	                          &msgProgramNameLen, programName, sizeof(programName));

	if (msgNext != NULL)
	{
		msgLeft = msgNext; /* eg "contextName rest_of_msg..." */
	}

	/* msgCurr is where we're at in parsing */
	msgCurr = msgLeft;

	/* parse off PmLogLib pid/tid prefix */
	msgNext = ParseMsgPidTid(msgCurr);

	if (msgNext != NULL)
	{
		/* integrate into msgProgram */
		snprintf(msgProgram + msgProgramNameLen + 1,
			sizeof(msgProgram) - (msgProgramNameLen + 1), "%.*s",
			(int)(msgNext - msgCurr), msgCurr);

		msgLeft = msgNext;
		msgCurr = msgNext;
	}

	/* Recognization for PMLOG_IDENTIFIER*/
	msgNext = ParseMsgTag(msgCurr);

	if (!msgNext)
	{
		// not from pmloglib
		strncpy(contextName, LEGACY_LOG, sizeof(contextName) );
	}
	else
	{
		// from pmloglib
		msgCurr = msgNext;
		msgLeft = msgNext;
		/* parse off PmLogLib context identifier prefix (if present) */
		msgNext = ParseMsgContext(msgCurr, contextName, sizeof(contextName));

		if (msgNext != NULL)
		{
			msgCurr = msgNext;
		}
	}

	if (HandleLogCommand(msgCurr))
	{
		g_string_free(outMsg, true);
		return;
	}

	outMsg = g_string_append(outMsg, msgProgram); /* e.g "uploadd \0" */
	outMsg = g_string_append(outMsg, msgLeft); /* "context msgid kvpair message" */
	outMsg = g_string_append(outMsg, "\n");
	/* e.g "2008-12-08T12:17:12.824279Z [1824] user.info uploadd uploadd msgid kvpairs msg... \n" */

	PmLogContextConf_t *contextConfP = NULL;

	/* look up the specified context */
	if ((contextName[ 0 ] != 0))
	{
		contextConfP = g_tree_lookup(g_contextConfs, contextName);
	}

	/* default to default context */
	if (contextConfP == NULL)
	{
		contextConfP = g_tree_lookup(g_contextConfs, kPmLogDefaultContextName);

		if (contextConfP == NULL)
		{
			DbgPrint("%s, default context not found!\n", __FUNCTION__);
			g_string_free(outMsg, true);
			return;
		}
	}

	bool allowedToLog;
	if (g_collectDevLogs)
	{
		allowedToLog = true; // log everything when collecting dev logs
	}
	else
	{
		char msgid[ MAX_MSGID_LEN + 1];
		msgNext = ParseMsgID(++msgCurr, msgid, sizeof(msgid));

		assert(strlen(contextName) + strlen(msgid) + 2 <= MAXLINE);

		char context_msgid_pair[MAXLINE];
		(void) snprintf(context_msgid_pair, sizeof(context_msgid_pair),
		                "%s/%s", contextName, msgid);

		allowedToLog = (g_hash_table_lookup(whitelist_table, context_msgid_pair) != NULL);
		if (allowedToLog)
		{
			DbgPrint("Whitelisted: This message can be logged %s\n", context_msgid_pair);
		}
		else
		{
			DbgPrint("Blacklisted: Restrict logging this message %s\n", context_msgid_pair);
		}
	}

	if (allowedToLog)
	{
		/* Has ring buffer */
		if (contextConfP->rb)
		{
			DbgPrint("%s: %s has RB\n", __FUNCTION__, contextConfP->contextName);
			int lvl = pri & LOG_PRIMASK;

			if (lvl <= contextConfP->rb->flushLevel)
			{
				DbgPrint("%s: %s Flushing!\n", __FUNCTION__, contextConfP->contextName);
				g_tree_foreach(g_contextConfs, FlushNotMe, contextConfP);

				timeStamp = MakeMessageTimestamp();
				char priStr2[20];
				FormatPri(LOG_SYSLOG | LOG_INFO, priStr2, sizeof(priStr2));
				gchar *flushMsg =
					g_strdup_printf("%s %s pmsyslogd: {%s}: ------ Flushing ring buffer for %s message ------\n",
						timeStamp,
						priStr2,
						contextConfP->contextName,
						priStr);
				g_free(timeStamp);
				OutputMessage(contextConfP, pri, "pmsyslogd", flushMsg);

				/* Flush */
				RBFlush(contextConfP->rb, FlushMessage, contextConfP);
				OutputMessage(contextConfP, pri, programName, outMsg->str);
				g_free(flushMsg);

				timeStamp = MakeMessageTimestamp();
				flushMsg =
					g_strdup_printf("%s %s pmsyslogd: {%s}: ------ Done flushing ------\n",
						timeStamp,
						priStr2,
						contextConfP->contextName);
				OutputMessage(contextConfP, pri, "pmsyslogd", flushMsg);
				g_free(timeStamp);
				g_free(flushMsg);

			}
			else
			{
				DbgPrint("%s: %s buffering!\n", __FUNCTION__, contextConfP->contextName);
				/* buffer */
				char buffMsg[contextConfP->rb->bufferSize];
				snprintf(buffMsg, sizeof(buffMsg) - 1, "%d/%s/%s", pri, programName,
				         outMsg->str);
				buffMsg[sizeof(buffMsg) - 1 ] = '\0';
				RBWrite(contextConfP->rb, buffMsg, (int)strlen(buffMsg) + 1);
			}
		}
		else
		{
			OutputMessage(contextConfP, pri, programName, outMsg->str);
		}
	}

	g_string_free(outMsg, true);

#ifdef RDX_LOG_REPORTING
	/* RDX report */
	if ((pri & LOG_PRIMASK) <= LOG_CRIT)
	{
		const char *black_list[] = { "rdxd", "uploadd", "pmsyslogd", "upstart", NULL };

		for (int i = 0; black_list[i] != NULL; i++)
		{
			if (strcmp(black_list[i], programName) == 0)
			{
				return;
			}
		}

		HeavyOperationRoutineAdd(&heavy_routine,
		                         RdxLogReport,
		                         CreateRdxReportTask(pri, programName, msg),
		                         CreateRdxReportType,
		                         NULL);
	}

#endif
}

/**
 * @brief ProcessMessage
 *
 * Message processor, this is called on each message read
 * off of the /dev/log socket; it will actually parse the
 * message to calculate the priority and recreate the log
 * body to contain with printable characters.  Afterwhich
 * it will log the message.
 *
 * @param buff the message
 * @param buffLen the length of the message
 */
static void ProcessMessage(const char *buff, int buffLen)
{
	int             pri;
	const char     *in;
	char            line[ MAXLINE + 1 ];
	char           *out;
	unsigned char   c;

	/*
	 * As we are using a datagram socket, we know that buff is a
	 * complete message that is a null-terminated string.
	 * The caller has already verified that, so we can ignore
	 * the specified length here and just look for the terminator.
	 * Note: If there were embedded NUL characters in
	 * the data that will cause the message to be truncated.
	 */
	(void) &buffLen;

	pri = LOG_USER | LOG_NOTICE;

	in = buff;

	/* If string starts with "<ddd>" parse the priority */
	if (*in == '<')
	{
		in++;
		pri = 0;

		while (isdigit(*in))
		{
			pri = pri * 10 + *in - '0';
			in++;
		}

		if (*in == '>')
		{
			in++;
		}
	}

	if ((pri & LOG_FACMASK) == PMLOGDAEMON_LOG_KERN)
	{
		pri = (pri & (~LOG_FACMASK)) | LOG_KERN;
	}

	if (pri & ~(LOG_FACMASK | LOG_PRIMASK))
	{
		pri = LOG_USER | LOG_NOTICE;
	}

	out = line;

	while ((c = (unsigned char)*in++) != 0)
	{
		if (out >= &line[ sizeof(line) - 1 ])
		{
			break;
		}

		if ((c == '\n') || (c == 127))
		{
			*out++ = ' ';
		}
		else if (c < 0x20)
		{
			if (out + 1 >= &line[ sizeof(line) - 1 ])
			{
				break;
			}

			/*
			 * escape control characters as printable
			 * 0x07 => ^G, 0x08 => ^H, 0x09 => ^I, etc
			 */
			*out++ = '^';
			*out++ = (char)(c ^ 0x40);
		}
		else
		{
			*out++ = (char)c;
		}
	}

	*out = 0;
	LogMessage(pri, line);
}

static void _SysLogMessage(const int level, const char *fmt, ...)
{
	va_list     args;
	char        msg[ 512 ];

	va_start(args, fmt);

	(void) vsnprintf(msg, sizeof(msg), fmt, args);

	va_end(args);

	LogMessage(level, msg);
}

static GMainLoop *mainLoop = NULL;

/**
 * @brief QuitSysLogD
 * Flush all log buffers and quit.  This method is intended to be called
 * as a signal handler
 *
 * @param sig the signal to handle
 */
static void QuitSysLogD(int sig)
{
	/* exit based on external signal */
	DbgPrint("PROC_EXIT");
	g_main_loop_quit(mainLoop);
}


/**
 * @brief LogConfig
 *
 * Used to log the configuration for debugging purposes.
 *
 * This is a GTraverseFunc (see glib's Balanced Binary Trees), it is passed the key and value
 * of each node, together with user_data parameter passed to g_tree_traverse().  If the function
 * returns TRUE, the traversal is stopped;  Currently it will never stop.
 *
 * @param key a key of a GTree node
 * @param value the value corresponding to the key
 * @param data user data passed to g_tree_traversal
 *
 * @return TRUE to stop the traversal; currently it always returns FALSE
 */
static gboolean LogConfig(gpointer key, gpointer value, gpointer data)
{
	const PmLogContextConf_t   *contextP = value;
	gchar *name = (gchar *)key;

	char filter[32] = {0,};
	char output[32] = {0,};

	PmLogInfo(g_context, "CFG_CTX", 1, PMLOGKS("Name", name), "");

	for (int i = 0; i < contextP->numRules; i++)
	{
		const PmLogRule_t *ruleP = &contextP->rules[i];
		const PmLogFile_t *outputP = &g_outputConfs[ruleP->outputIndex];

		snprintf(filter, sizeof(filter), "%s.%s%s.%s",
		         GetRuleFacilityStr(ruleP->facility),
		         ruleP->levelInvert ? "!" : "",
		         GetRuleLevelStr(ruleP->level),
		         (ruleP->program == NULL) ? "*" : ruleP->program);

		snprintf(output, sizeof(output), "%s%s",
		         ruleP->omitOutput ? "-" : "",
		         outputP->outputName);

		PmLogInfo(g_context, "CFG_RULE", 2, PMLOGKS("Filter", filter), PMLOGKS("Output",
		          output), "");
	}

	/* return true to stop the traversal */
	return FALSE;

}

/**
 * @brief LogConfigInfo
 *
 * For status reporting purposes, log out configuration information.
 * It accomplishes this by calling LogConfig on every node in the configuration
 * tree.
 *
 * @see LogConfig
 */
static void LogConfigInfo(void)
{
	for (int i = 0; i < g_numOutputs; i++)
	{
		const PmLogFile_t *outputP = &g_outputConfs[i];

		PmLogInfo(g_context, "CFG_OUTPUT", 4,
		          PMLOGKS("Name", outputP->outputName),
		          PMLOGKS("Path", outputP->path),
		          PMLOGKFV("Size", "%d", outputP->maxSize),
		          PMLOGKFV("Rotations", "%d", outputP->rotations),
		          "");
	}

	g_tree_foreach(g_contextConfs, LogConfig, NULL);
}

/**
 * @brief LogFileKillRotations
 *
 * delete the rotation files at and after the given index
 *
 * e.g
 * messages          index: 0
 * messages.0.gz     index: 1
 * messages.1.gz     index: 2
 * messages.2.gz     index: 3
 * messages.3.gz     index: 4
 * messages.4.gz     index: 5
 *
 * @param logFileP
 * @param start starting index to delete, see example above
 */
static void
LogFileKillRotations(PmLogFile_t *logFileP, int start)
{
	for (int r = start; r < PMLOG_MAX_NUM_ROTATIONS; r++)
	{
		gchar *rotation_file = r ?
		                       g_strdup_printf(PMLOGDAEMON_FILE_ROTATION_PATTERN, logFileP->path, r - 1) :
		                       g_strdup(logFileP->path);

		g_remove(rotation_file);
		g_free(rotation_file);
	}
}


/**
 * @brief LogFileInit
 * Constructor for the logFileP; copy variables from confP and initialize
 *
 * @param logFileP logfile to initialize
 * @param confP source of initial data to copy from.
 */
static void LogFileInit(PmLogFile_t *logFileP, const PmLogFile_t *confP)
{
	/* copy the fields to this struct for convenience */
	logFileP->outputName    = confP->outputName;
	logFileP->path          = confP->path;
	logFileP->maxSize       = confP->maxSize;
	logFileP->rotations     = confP->rotations;

	/* make sure there are not stale rotation files around */
	LogFileKillRotations(logFileP, logFileP->rotations + 1);
}


/**
 * @brief HandleNewLog
 *
 * Called by Glib's mainloop when there is data in the channel
 * to read.  In  this case this is called when someone has written
 * to the unix domain socket /dev/log
 *
 * @param source the channel (/dev/log) that has data to read
 * @param condition
 * @param data
 *
 * @return
 */
gboolean HandleNewLog(GIOChannel *source, GIOCondition condition,
                      gpointer data)
{
	char buff[MAXLINE + 1];
	ssize_t bytes;
	int sock_fd = g_io_channel_unix_get_fd(source);

	if ((condition & G_IO_IN) || (condition & G_IO_PRI))
	{
		bytes = recv(sock_fd, buff, sizeof(buff) - 1, 0);

		if (bytes <= 0)
		{
			DbgPrint("%s: recv returned %d", __FUNCTION__, bytes);
			goto error;
		}

		if (bytes)
		{
			buff[bytes] = '\0';
			#ifdef PMLOGDAEMON_ENABLE_LOGGING
			ProcessMessage(buff, (int)bytes);
			#endif
		}
	}
	else
	{
		DbgPrint("%s: unexpected watch event condition: %d\n", __FUNCTION__, condition);
	}

error:
	/* TODO: should this ever return FALSE, to close the channel? */
	return TRUE;
}

/////////////////////////////////////////////////////////////////
//                                                             //
//            Start of API documentation comment block         //
//                                                             //
/////////////////////////////////////////////////////////////////
/**
@page com_webos_pmlogd com.webos.pmlogd
@{
@section com_webos_pmlogd_backuplogs backuplogs

make tarball which includes all files in /var/log to
/mnt/lg/cmn_data/var/log

@par Returns

Name | Required | Type | Description
-----|--------|------|----------
returnValue | yes | Boolean | True on success, false otherwise
@}
*/
/////////////////////////////////////////////////////////////////
//                                                             //
//            End of API documentation comment block           //
//                                                             //
/////////////////////////////////////////////////////////////////
static bool backup_logs_ls(LSHandle *lsHandle, LSMessage *lsMessage, void *wd)
{
	LSMessageRef(lsMessage);

	bool          ret_val = true;
	const char    *tarball = WEBOS_INSTALL_LOCALSTATEDIR "/spool/rdxd/previous_boot_logs.tar.gz";
	const char    *src_path = WEBOS_INSTALL_LOCALSTATEDIR;
	const char    *log_files = "`find log/ -type f -maxdepth 1`";
	const char    *tar_options = "--absolute-names";
	jvalue_ref    reply = NULL;
	jschema_ref   response_schema = NULL;

	reply = jobject_create();

	gchar *tar_cmd = g_strdup_printf("cd %s; tar -czf %s %s %s", src_path, tarball, log_files, tar_options);

	PmLogDebug(g_context, "tar_cmd : %s", tar_cmd);

	system(tar_cmd); // Result value cannot be used as a validation. ls-method is not a synchronous.
	if (g_file_test(tarball, G_FILE_TEST_EXISTS))
	{
		jobject_put(reply, J_CSTR_TO_JVAL("returnValue"), jboolean_create(true));
	}
	else
	{
		jobject_put(reply, J_CSTR_TO_JVAL("returnValue"), jboolean_create(false));
	}

    response_schema = jschema_parse(j_cstr_to_buffer("{}"), DOMOPT_NOOPT, NULL);
    if (NULL == response_schema)
        goto END;

	ret_val = LSMessageReply(lsHandle, lsMessage, jvalue_tostring(reply,
	                         response_schema), &g_lsError);
	if (!ret_val)
	{
		PmLogWarning(g_context, "LSREPLY_ERROR", 1, PMLOGKS("ErrorText",
		             g_lsError.message), "");
	}
END :
	LSMessageUnref(lsMessage);
	j_release(&reply);
	LSErrorFree(&g_lsError);
	g_free(tar_cmd);
    if(response_schema)
    {
        jschema_release(&response_schema);
    }
    return ret_val;
}

/////////////////////////////////////////////////////////////////
//                                                             //
//            Start of API documentation comment block         //
//                                                             //
/////////////////////////////////////////////////////////////////
/**
@page com_webos_pmlogd com.webos.pmlogd
@{
@section com_webos_pmlogd_forcerotate forcerotate

Force rotates to mainstream file. /var/log/messages

@par Returns

Name | Required | Type | Description
-----|--------|------|----------
returnValue | yes | Boolean | True on success, false otherwise
errorText | no | String | Error text
@}
*/
/////////////////////////////////////////////////////////////////
//                                                             //
//            End of API documentation comment block           //
//                                                             //
/////////////////////////////////////////////////////////////////
static bool force_rotate_ls(LSHandle *lsHandle, LSMessage *lsMessage, void *wd)
{

	bool          ret_val = true;
	PmLogFile_t  *logFileP;
	jvalue_ref    reply = NULL;
	jschema_ref   response_schema = NULL;

	LSMessageRef(lsMessage);

	reply = jobject_create();

	logFileP = &g_logFiles[ 0 ];

	if (ForceRotateLogFile(logFileP, false))
	{
		jobject_put(reply, J_CSTR_TO_JVAL("returnValue"), jboolean_create(true));
	}
	else
	{
		jobject_put(reply, J_CSTR_TO_JVAL("returnValue"), jboolean_create(false));
		jobject_put(reply, J_CSTR_TO_JVAL("errorText"),
		            jstring_create("Log rotation failed"));
	}

    response_schema = jschema_parse(j_cstr_to_buffer("{}"), DOMOPT_NOOPT, NULL);
    if (NULL == response_schema)
        goto END;

	ret_val = LSMessageReply(lsHandle, lsMessage, jvalue_tostring(reply,
	                         response_schema), &g_lsError);

	if (!ret_val)
	{
		PmLogError(g_context, "LSREPLY_ERROR", 1, PMLOGKS("ErrorText",
		           g_lsError.message), "");
	}

END :
	LSMessageUnref(lsMessage);
	j_release(&reply);
	LSErrorFree(&g_lsError);
    if(response_schema)
    {
        jschema_release(&response_schema);
    }
    return ret_val;
}

/////////////////////////////////////////////////////////////////
//                                                             //
//            Start of API documentation comment block         //
//                                                             //
/////////////////////////////////////////////////////////////////
/**
@page com_webos_pmlogd com.webos.pmlogd
@{
@section com_webos_pmlogd_subscribe_on_rotations subscribeOnRotations

Add client to rotation subscription list

@par Returns

Name | Required | Type | Description
-----|--------|------|----------
returnValue | yes | Boolean | True on success, false otherwise
errorText | no | String | Error text
@}
*/
/////////////////////////////////////////////////////////////////
//                                                             //
//            End of API documentation comment block           //
//                                                             //
/////////////////////////////////////////////////////////////////
static bool subscribe_on_rotations_ls(LSHandle *lsHandle, LSMessage *lsMessage, void *wd)
{
	bool result = true;
	jvalue_ref reply = jobject_create();

	LSError lserror;
	LSErrorInit(&lserror);

	if (g_atomic_int_get(&g_haveRotSubscription) != 0)
	{
		jobject_put(reply, J_CSTR_TO_JVAL("returnValue"), jboolean_create(false));
		jobject_put(reply, J_CSTR_TO_JVAL("subscribed"), jboolean_create(false));
		jobject_put(reply, J_CSTR_TO_JVAL("errorText"),
		            jstring_create("Already have a subscriber. Can't add another one."));
	}
	else if (!LSSubscriptionAdd(lsHandle, ROTATION_SUBSCRIPTION_KEY, lsMessage, &lserror))
	{
		jobject_put(reply, J_CSTR_TO_JVAL("returnValue"), jboolean_create(false));
		jobject_put(reply, J_CSTR_TO_JVAL("subscribed"), jboolean_create(false));
		jobject_put(reply, J_CSTR_TO_JVAL("errorText"),
		            jstring_create("Internal error. Can't add subscription"));

		LSErrorLog(g_context, "LSSUBADD_ERROR", &lserror);
		LSErrorFree(&lserror);

		result = false;
	}
	else
	{
		g_atomic_int_inc(&g_haveRotSubscription);

		jobject_put(reply, J_CSTR_TO_JVAL("returnValue"), jboolean_create(true));
		jobject_put(reply, J_CSTR_TO_JVAL("subscribed"), jboolean_create(true));
	}

	if (!LSMessageReply(lsHandle, lsMessage,
	                    jvalue_tostring_simple(reply),
	                    &lserror))

	{
		LSErrorLog(g_context, "LSSUBREPLY_ERROR", &lserror);
		LSErrorFree(&lserror);

		result = false;
	}

	DbgPrint("%s called\n", __FUNCTION__);

	j_release(&reply);
	return result;
}

static bool sub_cancel_func(LSHandle *sh, LSMessage *reply, void *ctx)
{
	g_atomic_int_dec_and_test(&g_haveRotSubscription);

	DbgPrint("%s called\n", __FUNCTION__);

	return true;
}

static bool handle_configd_reply(LSHandle *handle, LSMessage *reply, void *ctx)
{
	// that this callback is running within the same thread where we read logs

	(void) handle;
	(void) ctx;

	// by default flag isn't changed
	bool collectDevLogs = g_collectDevLogs;

	jerror *error = NULL;
	jvalue_ref root = jdom_create(j_cstr_to_buffer(LSMessageGetPayload(reply)), jschema_all(), &error);
	if (error != NULL)
	{
		int errorLen = jerror_to_string(error, NULL, 0);
		char errorStr[errorLen+1];
		(void) jerror_to_string(error, errorStr, sizeof(errorStr));
		// PmLogError(g_context, "CONFIGD_REPLY", 0, "Can't handle reply from configd: %s", errorStr);
		ErrPrint("Can't handle reply from configd: %s\n", errorStr);
		jerror_free(error);
	}
	else
	{
		jvalue_ref value = jobject_get_nested(root, "configs", "system.collectDevLogs", NULL);

		if (jboolean_get(value, &collectDevLogs) != CONV_OK)
		{
			// PmLogError(g_context, "CONFIGD_REPLY", 0, "Can't parse reply: %s", LSMessageGetPayload(reply));
			ErrPrint("Can't handle reply from configd: %s\n", LSMessageGetPayload(reply));
			collectDevLogs = g_collectDevLogs;
		}
	}
	j_release(&root);

	if (collectDevLogs != g_collectDevLogs)
	{
		/*
		PmLogInfo(g_context, "DEVLOGS", 1,
		          PMLOGKFV("collectDevLogs", "%d", collectDevLogs),
		          "Switching collectDevLogs %s", collectDevLogs ? "on" : "off");
		*/
		DbgPrint("Switching collectDevLogs %s", collectDevLogs ? "on" : "off");
                PmLogSetDevMode(collectDevLogs);

		if (collectDevLogs)
		{
			// rotate and maybe send out non-dev logs first
			for (int i = 0; i < g_numOutputs; i++)
			{
				PmLogFile_t *logFileP = &g_logFiles[ i ];
				DbgPrint("Retating logs for %s\n", logFileP->path);
				DoRotateLogFile(logFileP, false); // rotate synchronously
			}
			g_collectDevLogs = true;
		}
		else
		{
			// first of all turn on filtering
			g_collectDevLogs = collectDevLogs;

			// now kill all logs including active one
			for (int i = 0; i < g_numOutputs; i++)
			{
				PmLogFile_t *logFileP = &g_logFiles[ i ];
				DbgPrint("Removing logs for %s\n", logFileP->path);
				(void) g_remove(logFileP->path);
				// whole log folder might be collected and sent out by
				// bugreporter so kill rotations also
				LogFileKillRotations(logFileP, 0);
			}
		}
	}
	return true;
}

static LSMethod g_lsMethods[] =
{
	{ "forcerotate", force_rotate_ls },
	{ "backuplogs", backup_logs_ls },
	{ "subscribeOnRotations", subscribe_on_rotations_ls },
	{},
};

static bool register_luna_service(GMainLoop *mainLoop)
{

	bool result;
	LSErrorInit(&g_lsError);

	result = LSRegister(PMLOGD_APP_ID, &g_lsServiceHandle, &g_lsError);
	if (!result)
	{
		LSErrorLog(g_context, "LSREGISTER_ERROR", &g_lsError);
		return false;
	}

	result = LSRegisterCategory(g_lsServiceHandle, "/", g_lsMethods, NULL, NULL,
	                            &g_lsError);
	if (!result)
	{
		LSErrorLog(g_context, "LSREGCAT_ERROR", &g_lsError);
		return false;
	}

	result = LSSubscriptionSetCancelFunction(g_lsServiceHandle, &sub_cancel_func,
	                                         NULL, &g_lsError);
	if (!result)
	{
		LSErrorLog(g_context, "LSSUBCANCFUN_ERROR", &g_lsError);
		return false;
	}

	result = LSGmainAttach(g_lsServiceHandle, mainLoop, &g_lsError);
	if (!result)
	{
		LSErrorLog(g_context, "LSATTACH_ERROR", &g_lsError);
		return false;
	}

	return true;
}

static gboolean registration(gpointer userdata) {
    int lsResult = register_luna_service(heavy_routine.routine.loop);
    PmLogDebug(g_context, "LSREGISTER_SERVICE result : %s", lsResult ? "true" : "false");

    // subscribe for system.collectDevLogs in configd
    {
        LSError lserror;
        LSErrorInit(&lserror);
        if (!LSCall(g_lsServiceHandle,
                    "luna://com.webos.service.config/getConfigs",
                    "{\"configNames\":[\"system.collectDevLogs\"],\"subscribe\":true}",
                    handle_configd_reply, NULL, NULL, &lserror))
        {
            /* Can cause deadlock:
            * LSErrorLog(g_context, "LSCALL_ERROR", &lserror);
            */
            ErrPrint("Failed to call configd: %s\n", lserror.message);
            LSErrorFree(&lserror);
            return false;
        }
    }
    return true;
}

static gboolean InitializeHubStatusReader(gpointer userdata)
{
    int fd;
    int wd;
    ssize_t length;
    size_t i = 0;
    char buffer[EVENT_BUF_LEN];
    struct stat     fdStat;
    bool retVal = TRUE;

    int result = stat(HUBD_READY_FILE, &fdStat);

    if (result == 0)
    {
        HeavyOperationRoutineAdd(&heavy_routine,
                                         registration,
                                         NULL,
                                         LunaRegistration,
                                         NULL);
        return retVal;
    }

    fd = inotify_init();

    if (fd < 0)
    {
        DbgPrint("error while inotify_init");
        return FALSE;
    }

    wd = inotify_add_watch( fd, INOTIFY_WATCH_PATH, IN_CREATE );

    if (wd == -1)
    {
        DbgPrint("error while inotify_add_watch");
        close(fd);
        return FALSE;
    }

    memset(buffer, 0, sizeof(buffer));

    length = read( fd, buffer, EVENT_BUF_LEN );

    if (length <= 0)
    {
        DbgPrint("error while reading");
        retVal = FALSE;
    }
    else
    {
        while (i < length)
        {
            if (((i + EVENT_SIZE-1) >= length) || ((i + EVENT_SIZE-1) >= EVENT_BUF_LEN)) {
                retVal = FALSE;
                break;
            }

            struct inotify_event *event = ( struct inotify_event * ) &buffer[ i ];
            if ((event->len) && (event->mask & IN_CREATE))
            {
                HeavyOperationRoutineAdd(&heavy_routine,
                                         registration,
                                         NULL,
                                         LunaRegistration,
                                         NULL);
            }

            i += EVENT_SIZE + event->len;
        }
    }
    inotify_rm_watch(fd, wd);
    close(fd);

    return retVal;
}

gboolean InitializeSysLogReader(gpointer user_data)
{
    struct sockaddr_un  sunx;
    int                 sock_fd;
    int                 result;
    GIOChannel         *gioch;
    GMainLoop          *mainLoop = (GMainLoop *)user_data;

    /* create socket listener */
    memset(&sunx, 0, sizeof(sunx));
    sunx.sun_family = AF_UNIX;
    (void) strncpy(sunx.sun_path, g_pathLog, sizeof(sunx.sun_path) - 1);

    sock_fd = socket(AF_UNIX, SOCK_DGRAM, 0);

    if (sock_fd < 0)
    {
        DbgPrint("RunSysLogD: socket error: %s\n", strerror(errno));
        g_main_loop_quit(mainLoop);
        return FALSE;
    }

    result = bind(sock_fd, (struct sockaddr *) &sunx,
                    (socklen_t)(sizeof(sunx.sun_family) + strlen(sunx.sun_path)));

    if (result < 0)
    {
        DbgPrint("InitializeSysLogReader: bind error: %s\n", strerror(errno));
        close(sock_fd);
        g_main_loop_quit(mainLoop);
        return FALSE;
    }

    result = chmod(g_pathLog, 0666);

    if (result < 0)
    {
        DbgPrint("RunSysLogD: chmod error: %s\n", strerror(errno));
        close(sock_fd);
        g_main_loop_quit(mainLoop);
        return FALSE;
    }

    gioch = g_io_channel_unix_new(sock_fd);

    if (gioch == NULL)
    {
        DbgPrint("%s: channel error using fd: %d\n", __FUNCTION__, sock_fd);
        close(sock_fd);
        g_main_loop_quit(mainLoop);
        return FALSE;
    }

    g_io_add_watch(gioch, G_IO_IN, HandleNewLog, NULL);
    g_io_channel_unref(gioch);

    return FALSE;
}

/**
 * @brief RunSysLogD
 * Run the actual syslogdaemon as a daemon; Register a listener on the
 * /dev/log unix domain socket for locally generated log
 * messages.
 *
 * @return RESULT_OK if we were able to listen on the socket, error code otherwise
 */
static int RunSysLogD(void)
{
	PmLogFile_t        *logFileP;

	(void) signal(SIGINT, QuitSysLogD);
	(void) signal(SIGTERM, QuitSysLogD);
	(void) signal(SIGQUIT, QuitSysLogD);

	(void) signal(SIGHUP, SIG_IGN);
	(void) signal(SIGCHLD, SIG_IGN);

	for (int i = 0; i < g_numOutputs; i++)
	{
		logFileP = &g_logFiles[ i ];
		LogFileInit(logFileP, &g_outputConfs[ i ]);
	}

	/* clean up before start */
	(void) unlink(g_pathLog);

	if (!HeavyOperationRoutineConstruct(&heavy_routine))
	{
		ErrPrint("Failed to create heavy operation routine");
		goto error;
	}


    if (!HeavyOperationRoutineRun(&heavy_routine))
    {
        ErrPrint("Failed to run heavy operation routine");
        goto error;
    }

	mainLoop = g_main_loop_new(NULL, FALSE);

	if (mainLoop == NULL)
	{
		goto error;
	}

	/* Run the main loop */
	PmLogDebug(g_context, "PROC_START");

	if (g_showStartInfo)
	{
		LogConfigInfo();
	}

	g_timeout_add(0, InitializeSysLogReader, mainLoop);
	HeavyOperationRoutineAdd(&heavy_routine, InitializeHubStatusReader, NULL, MonitorFile, NULL);

	g_main_loop_run(mainLoop);
	g_main_loop_unref(mainLoop);

error:
	HeavyOperationRoutineDestruct(&heavy_routine);

	(void) unlink(g_pathLog);

	/* Clean up our pid file.  Not necessary, but nice to have */
	UnlockProcess();

	exit(EXIT_SUCCESS);

	return RESULT_OK;
}


/**
 * @brief InitSettings
 * Initialize the settings of this configuration
 */
static void InitSettings(void)
{
	g_showStartInfo = 0;
	g_useFullTimeStamps = 0;
	g_timeStampFracSecDigits = 0;

	strncpy(g_pathLog, _PATH_LOG, sizeof(g_pathLog));

	g_numOutputs = 0;
	g_numContexts = 0;
}


/**
 * @brief ParseParams
 * Parse the command line parameters.
 *
 * @param argc number of arguments
 * @param argv array of arguements
 *
 * @return Return result code.
 */
static int ParseParams(int argc, char *argv[])
{
	int ret = RESULT_OK;
	GOptionEntry entries[] =
	{
		{
			"fractional", 'f', 0, G_OPTION_ARG_INT, &g_timeStampFracSecDigits,
			"Specify timestamp seconds decimal precision (0..6)", "N"
		},
		{
			"verbose", 'v', 0, G_OPTION_ARG_NONE, &g_showStartInfo,
			"Be verbose", NULL
		},
		{
			"longtime", 'z', 0, G_OPTION_ARG_NONE, &g_useFullTimeStamps,
			"Use full RFC 3339 format timestamps", NULL
		},
		{
			"monotonic", 'm', 0, G_OPTION_ARG_NONE, &g_timeStampMonotonic,
			"Include monotonic seconds in timestamp", NULL
		},
		{ NULL }
	};
	GError *error = NULL;
	GOptionContext *context;

	context = g_option_context_new("- implements syslogd");
	g_option_context_add_main_entries(context, entries, NULL);

	if (!g_option_context_parse(context, &argc, &argv, &error))
	{
		if (error)
		{
			DbgPrint("%s: option parsing failed: %s\n", __FUNCTION__, error->message);
			g_error_free(error);
		}

		ret = RESULT_PARAM_ERR;
	}

	g_option_context_free(context);
	return ret;
}

gint char_array_comp_func(gconstpointer a, gconstpointer b, gpointer user_data)
{
	const gchar *ga = a;
	const gchar *gb = b;
	return strcmp(ga, gb);
}

/**
 * @brief InitConfig
 * Initial setup of configuration
 */
static void InitConfig(void)
{
	g_numOutputs = 0;
	g_numContexts = 0;

	memset(&g_outputConfs, 0, sizeof(g_outputConfs));
	g_contextConfs = g_tree_new_full(char_array_comp_func, NULL, g_free, free);

	/* TODO : Validation for result of PmLogReadConfigs() */
	PmLogPrvReadConfigs(ParseJsonOutputs);
	PmLogPrvReadConfigs(ParseJsonContexts);
}

/**
 * @brief InitConfig
 * Initial setup of whitelist table
 */
static gboolean LoadWhitelist(const char *filename, GError **error)
{
    gboolean result = TRUE;
    gchar *rawwhitelist = NULL;
    gchar **wlentry = NULL;
    gchar **whitelist_buffer = NULL;

    whitelist_table = g_hash_table_new(g_str_hash, g_str_equal);
    g_assert(whitelist_table != NULL);

    DbgPrint("Loading whitelist file\n");
    if (g_file_get_contents(filename, &rawwhitelist, NULL, error))
    {
        g_assert(rawwhitelist != NULL);
        whitelist_buffer = g_strsplit(rawwhitelist, "\n", 0);
        g_assert(whitelist_buffer != NULL);

        for (wlentry = whitelist_buffer; *wlentry != NULL; wlentry++)
        {
            if (strlen(*wlentry) != 0)
            {
                g_strstrip(*wlentry); // Remove leading and trailing white space

                gchar *sep = NULL;
                for (sep = *wlentry; *sep != '\0'; ++sep)
                {
                    if (*sep == ' ' || *sep == '\t')
                    {
                        *sep++ = '/';       // ensure it's a space
                        g_strchug(sep);     // remove any extra whitespace
                        break;
                    }
                }

                if (*sep == '\0')
                    continue;

                // Now the entry matches "<context> <msg_id>" with no leading or
                // trailing white space, and a single space between them
                if (strlen(*wlentry) != 0)
                    g_hash_table_add(whitelist_table, *wlentry);
            }
        }
        g_free(rawwhitelist);
        g_strfreev(whitelist_buffer);
    }
    else
    {
        result = FALSE;
    }

    return result;
}


/**
 * @brief main
 *
 * @param argc
 * @param argv
 *
 * @return
 */
int main(int argc, char *argv[])
{
	int           result;

	PmLogGetContext(PMLODAEMON_CONTEXT, &g_context);

	InitSettings();

	result = ParseParams(argc, argv);

	if (result != RESULT_OK)
	{
		exit(EXIT_FAILURE);
	}

	DbgPrint("PmLogDaemon running...\n");

	InitConfig();

	GError *error = NULL;
	if (!LoadWhitelist(WEBOS_INSTALL_SYSCONFDIR "/PmLogDaemon/whitelist.txt", &error))
	{
		if (error != NULL)
		{
			DbgPrint("Failed to load whitelist file: %s\n", error->message);
			g_error_free(error);
		}
		else
		{
			DbgPrint("Failed for unknown reason\n");
		}
	}

	/* make sure we aren't already running */
	if (!LockProcess("PmLogDaemon"))
	{
		exit(EXIT_FAILURE);
	}

	/* service the syslog socket */
	result = RunSysLogD();

	if (result != RESULT_OK)
	{
		exit(EXIT_FAILURE);
	}

	exit(EXIT_SUCCESS);
}
