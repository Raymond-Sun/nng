#
# Copyright 2017 Garrett D'Amore <garrett@damore.org>
# Copyright 2017 Capitar IT Group BV <info@capitar.com>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

# TLS transport

# This requires the mbedTLS library be installed somewhere.  You can
# point this at a suitable installation of mbedTLS by setting
# MBEDTLS_ROOT_DIR to point at the root of the installation (prefix).

# It is possible to minimize the mbedTLS library quite a bit.  We do
# not require legacy algorithms, the net_sockets layer, as well as
# various other tidbits.  (Look for a sample config.h in this directory,
# if you want to build a minimized version just for nng.)


if (NNG_TRANSPORT_TLS)
    Find_Package(mbedTLS REQUIRED)

    # If it isn't already in the link list, add the TLS libraries
    # there.  We might have pulled it in elsewhere (e.g. for websockets
    # or something, so we take care not to duplicate it).
    list(FIND NNG_REQUIRED_LIBRARIES ${MBEDTLS_TLS_LIBRARY} _index)
    if (_index EQUAL -1)
        set(NNG_REQUIRED_LIBRARIES ${NNG_REQUIRED_LIBRARIES} ${MBEDTLS_LIBRARIES})
        set(NNG_REQUIRED_LIBRARIES ${NNG_REQUIRED_LIBRARIES} PARENT_SCOPE)
    endif()

    # Likewise for the inclue search path.
    list(FIND NNG_REQUIRED_INCLUDES ${MBEDTLS_INCLUDE_DIR} _index)
    if (_index EQUAL -1)
        set(NNG_REQUIRED_INCLUDES ${NNG_REQUIRED_INCLUDES} ${MBEDTLS_INCLUDE_DIR})
        set(NNG_REQUIRED_INCLUDES ${NNG_REQUIRED_INCLUDES} PARENT_SCOPE)
    endif()

    set(TLS_SOURCES transport/tls/tls.c transport/tls/tls.h)
    install(FILES tls.h DESTINATION include/nng/transport/tls)
    
endif()

set(NNG_SOURCES ${NNG_SOURCES} ${TLS_SOURCES} PARENT_SCOPE)
