#ifndef ADBCRYPT_H
#define ADBCRYPT_H

#include "adb-crypt_global.h"
#include "simplecrypt.h"
#include "onetimestring.h"
//#include "textstreamwlinecount.h"

#include <QFile>
#include <QTextStream>
#include <QDebug>
#include <QLineEdit>
#include <QDir>
#include <QStringListModel>
#include <QBuffer>
#include <QCompleter>
#include <QStringLiteral>

#include <QRandomGenerator>
#include <QRandomGenerator64>


enum fileCreateStatus{
    Failed,
    Success,
    AlreadyExist
};

namespace AdbCryptUtility {

    extern OneTimeString<QString> __passPhrase;

    extern QString const __standardPath;

    int createFile(QString const& fullFilePath, QString const& fileLogDescr = "file");

    bool deleteFile(QString const& fullFilePath, QString const& fileLogDescr = "file");

}



class ADBCRYPT_EXPORT AdbCrypt
{

private:
    QLineEdit * const & loginForm_ = nullptr;
    QLineEdit * const & passwForm_ = nullptr;

    SimpleCrypt crypto_binf_;
    SimpleCrypt crypto_passw_;

    QString const dirPath_;
    QString const cryptoFileFullPath_;
    QString const dataFileFullPath_;

    QStringListModel completerModel;
    QStringList wordList;
    QCompleter *completer = nullptr;

    int credLim_ = 0;

public:    


    static AdbCrypt* data
    (
          QLineEdit * const & loginFormObjRef
        , QLineEdit * const & passwFormObjRef
        , QString const & directoryPath = AdbCryptUtility::__standardPath
        , int credentialsLimit = 25
    );


    bool decryptCredentials4romFile(QMap<QString, QString> &settingsMap);

    bool encryptCredentials2File();

    void completerActivated(const QString& curText);

    void reCreate();//void clearSavedUserData();

    void getSavedLogins();

private:

    void initObj();

    void generateNewKey2bin();

    bool getKey4romBin();

    void removeDuplicateCredentialsEntrie(QString * decryptedFormattedFileContent, QString const & dupLogin);

    void parseCredentials2Map(QString * decryptedFormattedFileContentFrom, QMap<QString,QString> * settingsMapWherePut);

    QString getPassword(QString *decryptedFormattedFileContentFrom,QString const& login);

    QString getLogin4romEntrie(QString *lineEntrie);

    QString getLineEntrie(QString *decryptedFormattedFileContentFrom,QString const& login);

    void cutLines2lim(QString & str2cut,int linesLimit);

    explicit AdbCrypt
    (
          QLineEdit * const & loginFormObjRef
        , QLineEdit * const & passwFormObjRef
        , QString const & directoryPath /*= AdbCryptUtility::__standardPath*/
        , int credentialsLimit
    );

    AdbCrypt() = delete;

    AdbCrypt(AdbCrypt const&) = delete;
    AdbCrypt& operator=(AdbCrypt const&) = delete;

};



#endif // ADBCRYPT_H
