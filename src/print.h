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
 * @file print.h
 *
 * @brief This file contains debugging/error reporting utilities.
 *
 **********************************************************************
 */


#ifndef PMLOGDAEMON_PRINT_H
#define PMLOGDAEMON_PRINT_H

#include <stdio.h>

/*
 * Note that we don't output to syslog.  As this module is implementing
 * the syslog socket reader, if we make a call to the syslog API from
 * the same thread it may deadlock on the write, so it's easier to just
 * avoid it completely.
 */

/* uncomment to debug. */
//#define PMLOGDAEMON_DEBUG

#define COMPONENT_PREFIX    "PmLogDaemon: "


/* DbgPrint */
#ifdef PMLOGDAEMON_DEBUG
#define DbgPrint(...) \
 {                                                       \
     fprintf(stdout, COMPONENT_PREFIX __VA_ARGS__);      \
 }
#define ErrPrint(...) \
 {                                                       \
     fprintf(stderr, COMPONENT_PREFIX __VA_ARGS__);      \
 }
#else
#define DbgPrint(...)
#define ErrPrint(...)
#endif

#endif /* PMLOGDAEMON_PRINT_H */
