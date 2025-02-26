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
#include <QPointer>

#include <QRandomGenerator>
#include <QRandomGenerator64>

#include "iqtplugins.h"

enum fileCreateStatus{
    Failed,
    Success,
    AlreadyExist
};

namespace AdbCryptUtility {

    extern QString const __standardPath;

    int createFile(QString const& fullFilePath, QString const& fileLogDescr = "file");

    bool deleteFile(QString const& fullFilePath, QString const& fileLogDescr = "file");

    void cutStr2linesLim(QString & strRef,int linesLimit);

    bool removeDuplicateLine4romStr(QString & strRef, QString const & line2remove);
}


class /*ADBCRYPT_EXPORT*/ AdbCrypt : public ICryptoPlugin
{

private:
    QLineEdit * const /*&*/ loginForm_ = nullptr;
    QLineEdit * const /*&*/ passwForm_ = nullptr;
    //
    QLineEdit * const /*&*/ hostForm_ = nullptr;
    //

    OneTimeString<QString> passPhrase_;

    SimpleCrypt crypto_binf_;
    SimpleCrypt crypto_passw_;

    QString dirPath_;
    QString cryptoFileFullPath_;
    QString dataFileFullPath_;

    QStringListModel completerModel;
    QStringList wordList;
    QCompleter *completer = nullptr;

    int const credLim_ = 0;

    // 'Host' form members
    QString conHostsFileFullPath_ ;
    int const conHostEntrLim_ = 0;
    QStringList conHostsList_;
    QStringListModel conHostsListModel_;
    QCompleter conHostsCompleter_;
    //

public:    

    static ICryptoPlugin* getInst
    (
          QLineEdit * const & loginFormObjRef
        , QLineEdit * const & passwFormObjRef
        //
        , QLineEdit * const & hostFormObjRef/* = nullptr*/
        //
        , QString const & directoryPath/* = AdbCryptUtility::__standardPath*/
        , int const credentialsLimit/* = 25*/
        //
        , int const hostEntriesLimit/* = 5*/
        //
    );

//    static ICryptoPlugin* getInst(std::nullptr_t, std::nullptr_t,QLineEdit* const &, QString const &, int const, int const) = delete;
//    static ICryptoPlugin* getInst(std::nullptr_t, QLineEdit * const &,QLineEdit* const &, QString const &, int const, int const) = delete;
//    static ICryptoPlugin* getInst(QLineEdit * const &, std::nullptr_t,QLineEdit* const &, QString const &, int const, int const) = delete;


    virtual bool encryptCredentials2File() override;

    virtual void /*reCreate*/reGenKey() override;

    void getSavedLogins() override;

    virtual QString decryptSomeBinF(QString const& fNameWpath) override;
    virtual void encryptSomeInfoToSomeBinF(QString const& info,QString const& fNameWpath,int linesLim, bool removeDuplicates = false) override;

    virtual void encryptCurHost() override;


    virtual void getSavedHosts() override;

    virtual ~AdbCrypt();

    virtual QString pluginName() override;


private:

    void setHostCompleter();

    void setLoginCompleter();

    void decrSavedConHosts();

    bool decryptCredentials4romFile(QMap<QString, QString> &settingsMap);

    void completerActivated(const QString& curText);


    void setupObj();

    void generateNewKey2bin();

    bool getKey4romBin();

    void removeDuplicateCredentialsEntrie(QString * decryptedFormattedFileContent, QString const & dupLogin);

    void parseCredentials2Map(QString * decryptedFormattedFileContentFrom, QMap<QString,QString> * settingsMapWherePut);

    QString getPassword(QString *decryptedFormattedFileContentFrom,QString const& login);

    QString getLogin4romEntrie(QString *lineEntrie);

    QString getLineEntrie(QString *decryptedFormattedFileContentFrom,QString const& login);

    void cutCredentialsEntries2linesLim(QString & decryptedCredFileContent2cut,int linesLimit);

    explicit AdbCrypt
    (
          QLineEdit * const & loginFormObjRef
        , QLineEdit * const & passwFormObjRef
        , QString const & directoryPath /*= AdbCryptUtility::__standardPath*/
        , int credentialsLimit
        //
        , QLineEdit * const & hostFormObjRef
        , int const hostEntriesLimit
        //
    );

    AdbCrypt() = delete;

    AdbCrypt(AdbCrypt const&) = delete;
    AdbCrypt& operator=(AdbCrypt const&) = delete;

};



#endif // ADBCRYPT_H
