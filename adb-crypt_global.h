#ifndef ADBCRYPT_GLOBAL_H
#define ADBCRYPT_GLOBAL_H

#include <QtCore/qglobal.h>

#if defined(ADBCRYPT_LIBRARY)
#  define ADBCRYPT_EXPORT Q_DECL_EXPORT
#else
#  define ADBCRYPT_EXPORT Q_DECL_IMPORT
#endif

#endif // ADBCRYPT_GLOBAL_H
