PmLogDaemon
===========

Summary
-------
The Open webOS logging daemon implementation

Description
-----------
The syslogd implementation is per RFC 3164. This implementation is a subset of
that functionality, intended to efficiently address the needs for Open webOS
embedded devices.

    - it does not support remote logging (not needed)
    - it only supports the standard datagram socket on port 514
    - it does not support /etc/syslog.conf or standard filtering/redirection

Additional features are:
    - support for RFC 3339-style timestamps
    - support for advanced file buffering + rotation configuration
    - support for custom filtering/redirection

Dependencies
============

Below are the tools (and their minimum versions) required to build PmLogDaemon:

- cmake (version required by webosose/cmake-modules-webos)
- gcc 4.6.3
- glib-2.0 2.32.1
- make (any version)
- webosose/cmake-modules-webos 1.0.0 RC2
- webosose/PmLogLib 3.0.0
- webosose/PmLogLib-private 3.0.0
- webosose/librdx-stub 1.0.0
- webosose/libpbnjson 2.11.0
- webosose/luna-service2 3.21.2
- pkg-config 0.26
- zlib 1.2.3

How to Build on Linux
=====================

## Building

Once you have downloaded the source, enter the following to build it (after
changing into the directory under which it was downloaded):

    $ mkdir BUILD
    $ cd BUILD
    $ cmake ..
    $ make
    $ sudo make install

The directory under which the files are installed defaults to <tt>/usr/local/webos</tt>.
You can install them elsewhere by supplying a value for <tt>WEBOS\_INSTALL\_ROOT</tt>
when invoking <tt>cmake</tt>. For example:

    $ cmake -D WEBOS_INSTALL_ROOT:PATH=$HOME/projects/webosose ..
    $ make
    $ make install

will install the files in subdirectories of <tt>$HOME/projects/webosose</tt>.

Specifying <tt>WEBOS\_INSTALL\_ROOT</tt> also causes <tt>pkg-config</tt> to look
in that tree first before searching the standard locations. You can specify
additional directories to be searched prior to this one by setting the
<tt>PKG\_CONFIG\_PATH</tt> environment variable.

If not specified, <tt>WEBOS\_INSTALL\_ROOT</tt> defaults to <tt>/usr/local/webos</tt>.

To configure for a debug build, enter:

    $ cmake -D CMAKE_BUILD_TYPE:STRING=Debug ..

To see a list of the make targets that <tt>cmake</tt> has generated, enter:

    $ make help

## Uninstalling

From the directory where you originally ran <tt>make install<tt>, enter:

    $ [sudo] make uninstall

You will need to use <tt>sudo</tt> if you did not specify <tt>WEBOS\_INSTALL\_ROOT</tt>.


## Generating Documentation

The tools required to generate the documentation are:

- doxygen 1.7.6.1
- graphviz 2.26.3

Once you have run `cmake`, enter the following to generate the documentation:

    $ make docs

To view the generated HTML documentation, point your browser to
`Documentation/PmLogDaemon/html/index.html`

To install the generated documentation, enter:

    $ [sudo] make install-docs

The documentation will be installed to `usr/share/doc/PmLogDaemon/html` under
the tree defined by the value of `WEBOS_INSTALL_ROOT` (or its default).

You will need to use `sudo` if you did not specify `WEBOS_INSTALL_ROOT`.


## Copyright and License Information

All content, including all source code files and documentation files in this repository are:

Copyright (c) 2007-2018 LG Electronics, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this content except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

SPDX-License-Identifier: Apache-2.0
