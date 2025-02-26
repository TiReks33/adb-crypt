#ifndef ADBCRYPT_GLOBAL_H
#define ADBCRYPT_GLOBAL_H

#include <QtCore/qglobal.h>

#include "iqtplugins.h"

#include <QLineEdit>

#if defined(ADBCRYPT_LIBRARY)
#  define ADBCRYPT_EXPORT Q_DECL_EXPORT
#else
#  define ADBCRYPT_EXPORT Q_DECL_IMPORT
#endif

// get adb-crypt plugin object; 'LOGIN' AND 'PASSWORD' FORMS OBJECTS MUSTN'T NULL(nullptr)!!
extern "C" ADBCRYPT_EXPORT ICryptoPlugin* CCreateCryptoModuleObj
(
    QLineEdit * const &loginFormObjRef__, //!=nullptr
    QLineEdit * const &passwFormObjRef__, //!=nullptr
    QLineEdit * const & hostFormObjRef__, // if nullptr, host form simply not used in encrypt
    const QString &directoryPath__,       // if NULL or empty, standard path will used
    int const credLim__,
    int const hostEntriesLimit__
);


#endif // ADBCRYPT_GLOBAL_H


