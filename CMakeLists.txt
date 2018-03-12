# Copyright (c) 2011-2018 LG Electronics, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

#
# PmLogDaemon/CMakeLists.txt
#

cmake_minimum_required(VERSION 2.8.7)

project(PmLogDaemon C)

include(webOS/webOS)
webos_modules_init(1 0 0 QUALIFIER RC4)
webos_component(3 1 0)

include(FindPkgConfig)

# Check that we have glib-2.0
pkg_check_modules(GLIB2 REQUIRED glib-2.0)
include_directories(${GLIB2_INCLUDE_DIRS})
webos_add_compiler_flags(ALL ${GLIB2_CFLAGS_OTHER})

# Check that we have PmLogLib
pkg_check_modules(PMLOGLIB REQUIRED PmLogLib)
include_directories(${PMLOGLIB_INCLUDE_DIRS})
webos_add_compiler_flags(ALL ${PMLOGLIB_CFLAGS_OTHER})

# Check that we have PmLogLib-private
pkg_check_modules(PMLOGLIB_PRV REQUIRED PmLogLib-private)
include_directories(${PMLOGLIB_PRV_INCLUDE_DIRS})
webos_add_compiler_flags(ALL ${PMLOGLIB_PRV_CFLAGS_OTHER})

# Check that we have librdx
pkg_check_modules(LIBRDX REQUIRED rdx)
include_directories(${LIBRDX_INCLUDE_DIRS})
webos_add_compiler_flags(ALL ${LIBRDX_CFLAGS_OTHER})

# Check that we have libpbnjson
pkg_check_modules(PBNJSON_C REQUIRED pbnjson_c>=2.11.0)
include_directories(${PBNJSON_C_INCLUDE_DIRS})
webos_add_compiler_flags(ALL ${PBNJSON_C_CFLAGS_OTHER})

# Check that we have luna-service2
pkg_check_modules(LUNASERVICE2 REQUIRED luna-service2)
include_directories(${LUNASERVICE2_INCLUDE_DIRS})
webos_add_compiler_flags(ALL ${LUNASERVICE2_CFLAGS_OTHER})

# Get the zlib library
include(FindZLIB)
if(NOT ZLIB_FOUND)
        message(FATAL_ERROR "ZLIB not found!")
endif()

webos_include_install_paths()

include_directories(src)
webos_add_compiler_flags(ALL -std=gnu99 -Wall -Wconversion -Wno-unused-result)

set(ENABLE_LOGGING TRUE CACHE BOOL "Enable logging")

if(ENABLE_LOGGING)
        webos_add_compiler_flags(ALL -DPMLOGDAEMON_ENABLE_LOGGING)
endif()

set(PMLOGDAEMON_DEBUG FALSE CACHE BOOL
    "Turn on internal logging to stdout/stderr for debugging purposes")
if(PMLOGDAEMON_DEBUG)
    webos_add_compiler_flags(ALL -DPMLOGDAEMON_DEBUG)
endif()

set(SOURCE_FILES
    src/main.c
    src/ring.c
    src/config.c
    src/util.c
    src/worker_routine.c
    src/heavy_operation.c
    src/heavy_operation_routine.c
    )

# Build the PmLogDaemon executable
add_executable(PmLogDaemon ${SOURCE_FILES})
target_link_libraries(PmLogDaemon
                     ${GLIB2_LDFLAGS}
                     ${PMLOGLIB_LDFLAGS}
                     ${PMLOGLIB_PRV_LDFLAGS}
                     ${LIBRDX_LDFLAGS}
                     ${PBNJSON_C_LDFLAGS}
                     ${ZLIB_LIBRARIES}
                     ${LUNASERVICE2_LDFLAGS}
                     -lrt)

webos_build_daemon()
webos_build_system_bus_files()
webos_build_configured_file(files/launch/PmLogDaemon-ready.conf SYSCONFDIR init)
install(PROGRAMS scripts/public/show_disk_usage.sh DESTINATION @WEBOS_INSTALL_DATADIR@/PmLogDaemon)
install(FILES files/whitelist.txt DESTINATION @WEBOS_INSTALL_SYSCONFDIR@/PmLogDaemon/)

webos_config_build_doxygen(doc Doxyfile)
