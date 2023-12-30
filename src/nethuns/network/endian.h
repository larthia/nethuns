#pragma once

#if defined(__APPLE__)
#  include <sys/types.h>
#  include <netinet/in.h>
#  if (BYTE_ORDER == LITTLE_ENDIAN)
#       define NETHUNS_LITTLE_ENDIAN  1
#  elif (BYTE_ORDER == BIG_ENDIAN)
#       define NETHUNS_BIG_ENDIAN     1
#  else
#  error "nethuns: endianess platform error"
#  endif
#elif defined(BSD)
#  include <sys/endian.h>
#  include <netinet/in.h>
#  if (_BYTE_ORDER == _LITTLE_ENDIAN)
#  define NETHUNS_LITTLE_ENDIAN      1
#  elif (_BYTE_ORDER == _BIG_ENDIAN)
#  define NETHUNS_BIG_ENDIAN         1
#  else
#  error "nethuns: endianess platform error"
#  endif
#elif defined(_WIN32)
#  include <winsock2.h>
#  define NETHUNS_LITTLE_ENDIAN      1
#else
#  include <endian.h>
#  include <netinet/in.h>
#  if (__BYTE_ORDER == __LITTLE_ENDIAN)
#       define NETHUNS_LITTLE_ENDIAN 1
#  elif (__BYTE_ORDER == __BIG_ENDIAN)
#       define NETHUNS_BIG_ENDIAN    1
#  else
#  error "nethuns: endianess platform error"
#  endif
#endif