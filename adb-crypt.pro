QT += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TEMPLATE = lib
DEFINES += ADBCRYPT_LIBRARY

CONFIG += c++11

# You can make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += \
    adbcrypt.cpp \
    simplecrypt.cpp \
    textstreamwlinecount.cpp

HEADERS += \
    adb-crypt_global.h \
    adbcrypt.h \
    onetimestring.h \
    simplecrypt.h \
    textstreamwlinecount.h

# Default rules for deployment.
unix {
    target.path = /usr/lib
}
!isEmpty(target.path): INSTALLS += target

DISTFILES += \
    CopyrightNoticeOfUsedSources
