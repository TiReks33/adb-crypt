#include "adbcrypt.h"

#include <QKeyEvent>

#define __SU "::[SUCCESS]::"
#define __FA "::[FAIL]::"
#define __WA "::[WARNING]::"
#define __ER "::[ERROR]::"


QString const AdbCryptUtility::__standardPath = QDir::homePath()+"/.adbCrypt";


AdbCrypt::AdbCrypt
(
    QLineEdit * const &loginFormObjRef__,
    QLineEdit * const &passwFormObjRef__,
    const QString &directoryPath__,
    int const credLim__,
    QLineEdit * const &hostFormObjRef__,
    int const hostEntriesLim__
)
    : loginForm_{loginFormObjRef__}
    , passwForm_{passwFormObjRef__}
    //
    , hostForm_{hostFormObjRef__}
    //
    , passPhrase_{
          #include "test.dat"
          }

    , crypto_binf_(passPhrase_.getStr().toUInt())

//    , dirPath_{directoryPath__}
//    , cryptoFileFullPath_{dirPath_+"/.cr.bin"}
//    , dataFileFullPath_{dirPath_+"/.usdata.bin"}

    , completer{new QCompleter{}}

    , credLim_{credLim__}

    //
//    , conHostsFileFullPath_{dirPath_+"/.ushosts.bin"}
    , conHostEntrLim_{hostEntriesLim__}
    //
{
    if(!loginForm_ || !passwForm_)
    {
        auto __ERR_STR = __ER"ADBCRYPT MODULE'S 'LOGIN' AND 'PASSWD' FORMS OBJECTS ARGUMENTS MUST BE PROPERLY INITIALIZED (MUSTN'T BE NULL). ABORTING.";
        qDebug() << __ERR_STR;
        std::cout << __ERR_STR << std::endl;
        std::abort();
    }

    if(!(directoryPath__.isNull() || directoryPath__.isEmpty()))
        dirPath_ = directoryPath__;
    else
        dirPath_ = AdbCryptUtility::__standardPath;

    cryptoFileFullPath_ = dirPath_+"/.cr.bin";
    dataFileFullPath_ = dirPath_+"/.usdata.bin";
    conHostsFileFullPath_ = dirPath_+"/.ushosts.bin";

    setupObj();


}


void AdbCrypt::setupObj()
{
    QDir dir(dirPath_);

    QMap <QString, QString> __settingsMap;

    do{

        if(!dir.exists()){

            dir.mkpath(".");
        }

        if(!QFile(cryptoFileFullPath_).exists()){

            generateNewKey2bin();
            getKey4romBin();
            break;

        } else{

            if(!getKey4romBin()){
                generateNewKey2bin();
                getKey4romBin();
                break;
            }
        }


        if(QFile(dataFileFullPath_).exists()){

            if(decryptCredentials4romFile(__settingsMap)){

                wordList << __settingsMap.keys();
            }
        }

    }while(false);



    setLoginCompleter();


    QObject::connect(completer,static_cast<void (QCompleter::*)(QString const&)> (&QCompleter::activated),[=](QString const& selectedStr__){

        completerActivated(selectedStr__);
    });

    if(QFile(conHostsFileFullPath_).exists()){

        decrSavedConHosts();
    }

    setHostCompleter();

}


void AdbCrypt::generateNewKey2bin()
{
    QString const __fileLogDescr = "crypto file";
    int __fileCreateStatus = AdbCryptUtility::createFile(cryptoFileFullPath_,__fileLogDescr);
    if(__fileCreateStatus){

        if(__fileCreateStatus==fileCreateStatus::AlreadyExist){
            AdbCryptUtility::deleteFile(cryptoFileFullPath_,__fileLogDescr);
            AdbCryptUtility::createFile(cryptoFileFullPath_,__fileLogDescr);
        }

        QFile myBinaryFile(cryptoFileFullPath_);
        if(!myBinaryFile.open(QIODevice::ReadWrite)){
            qDebug() << __WA"crypto file not opened. Check permissions.";
            return;
        }

        QDataStream binaryDataStream(&myBinaryFile);
        binaryDataStream.setVersion(QDataStream::Qt_4_7); //set QDataStream version for your Qt version if you need both forward and backward compatibility

        quint64 value = QRandomGenerator64::global()->generate() & std::numeric_limits<quint64>::max();



        QByteArray cyphertextBefore;

        cyphertextBefore = QString::number(value).toUtf8();



        QByteArray cyphertextAfter = crypto_binf_.encryptToByteArray(cyphertextBefore);



        if (crypto_binf_.lastError() != SimpleCrypt::ErrorNoError) {


            qDebug() << __FA"Key gen error. Error while encryption. Data integrity may be corrupted. ";

        }

        binaryDataStream << cyphertextAfter;

        myBinaryFile.flush();
        myBinaryFile.close();


    } else{

        qDebug() << __FA"Key gen error. File unavailable.";
    }

}


bool AdbCrypt::getKey4romBin()
{
    QFile file(cryptoFileFullPath_);
    file.open(QIODevice::ReadOnly);
    QDataStream in(&file);
    QByteArray cyphertext;
    in >> cyphertext;


    bool __checkNumb;

    crypto_passw_.setKey(QString::fromUtf8(crypto_binf_.decryptToByteArray(cyphertext)).toULongLong(&__checkNumb));

    return __checkNumb;
}

ICryptoPlugin* CCreateCryptoModuleObj(QLineEdit * const &loginFormObjRef__,
                             QLineEdit * const &passwFormObjRef__,
                             QLineEdit * const & hostFormObjRef__,
                             const QString &directoryPath__,
                             int const credLim__,
                             int const hostEntrLim__)
{

    return AdbCrypt::getInst(loginFormObjRef__,passwFormObjRef__, hostFormObjRef__, directoryPath__,credLim__,hostEntrLim__);
}


ICryptoPlugin* AdbCrypt::getInst(QLineEdit * const &loginFormObjRef__, QLineEdit * const &passwFormObjRef__, QLineEdit * const & hostFormObjRef__, const QString &directoryPath__, int const credLim__, int const hostEntrLim__)
{
    return new (std::nothrow) AdbCrypt(loginFormObjRef__,passwFormObjRef__,directoryPath__,credLim__,hostFormObjRef__,hostEntrLim__);
}

bool AdbCrypt::decryptCredentials4romFile(QMap<QString, QString> &settingsMap__)
{
    QDataStream IODataStream={};

    // open file with user credentials
    QFile file(dataFileFullPath_);

    if(!file.open(QIODevice::ReadOnly)){

        qDebug() << __FA"Decrypt::Unable to open data file for decrypt.";
        return false;
    }

    // read encrypted data from file and copy to raw bytes structure
    /*QDataStream in*/IODataStream.setDevice(&file);
    QByteArray cypherText="";
    IODataStream >> cypherText;

    file.close();



    // 'unzip' credentials (with encrtypted pass)
    QByteArray decryptedFileRawBytes = crypto_binf_.decryptToByteArray(cypherText);



    if ((crypto_binf_.lastError() != SimpleCrypt::ErrorNoError)) {
        qDebug() << __FA"Decrypt::Error while decoding binary file. Reason::"<< crypto_binf_.lastError();
        return false;
    }

    // open
    QBuffer buffer(&decryptedFileRawBytes);
    buffer.open(QIODevice::ReadOnly);
    /*QDataStream s*/IODataStream.setDevice(&buffer);
    IODataStream.setVersion(QDataStream::Qt_4_7);

    QString decryptedFormattedString;
    IODataStream >> decryptedFormattedString; //stream in a string

    buffer.close();


    parseCredentials2Map(&decryptedFormattedString, &settingsMap__);


    return true;
}


bool AdbCrypt::encryptCredentials2File()
{
    QByteArray decryptedFileRawBytes{""};
    QBuffer buffer{};
    //QDataStream decryptedFileDataStream{};
    QString decryptedFormattedString{""};
    QDataStream IODataStream={};

    QFile file(dataFileFullPath_);

    if(file.exists()){

        if(file.open(QIODevice::ReadOnly)){

            /*QDataStream in*/IODataStream.setDevice(&file);    // read the data serialized from the file

            QByteArray cyphertext;
            IODataStream >> cyphertext;           // extract "the answer is" and 42

            file.close();

            /*QByteArray*/ decryptedFileRawBytes = crypto_binf_.decryptToByteArray(cyphertext);

            if ((crypto_binf_.lastError() != SimpleCrypt::ErrorNoError)) {

                qDebug() << __FA"Encrypt::Error while decoding binary file. Reason::"<< crypto_binf_.lastError();

            } else{

                buffer.setData(decryptedFileRawBytes);

                if(buffer.open(QIODevice::ReadOnly)){

                    IODataStream.setDevice(&buffer);
                    IODataStream.setVersion(QDataStream::Qt_4_7);

                    IODataStream >> decryptedFormattedString; //stream in a string

                    buffer.close();


                }

            }

        }

    }


    QString const login = loginForm_->text();

    if(wordList.contains(login)){

        removeDuplicateCredentialsEntrie(&decryptedFormattedString,login);

    } else {

        wordList << login;

        /*AdbCryptUtility::*/cutCredentialsEntries2linesLim(decryptedFormattedString,credLim_-1);

    }



    QString const passw = passwForm_->text();


    QString const encryptedPassw = crypto_passw_.encryptToString(passw);


    QTextStream decryptedFormattedStringIOStream(&decryptedFormattedString);


    decryptedFormattedStringIOStream << login << '=' << "\"" << encryptedPassw << "\"" << Qt::endl;


    crypto_binf_.setCompressionMode(SimpleCrypt::CompressionAlways); //always compress the data, see section below
    crypto_binf_. setIntegrityProtectionMode(SimpleCrypt::ProtectionHash);


    buffer.open(QIODevice::WriteOnly);

    QDataStream bufferDataIOStream(&buffer);

    bufferDataIOStream.setVersion(QDataStream::Qt_4_7);

    bufferDataIOStream << decryptedFormattedString;


    QByteArray myCypherText = crypto_binf_.encryptToByteArray(buffer.data());


    if ((crypto_binf_.lastError() != SimpleCrypt::ErrorNoError)) {

        qDebug() << __FA"Encrypt::Error while encoding 2 binary file. Reason::"<< crypto_binf_.lastError();

    } else {


        file.open(QIODevice::WriteOnly);
        /*QDataStream out*/IODataStream.setDevice(&file);

        IODataStream << myCypherText;


        file.close();

    }

    buffer.close();


    setLoginCompleter();

    return true;
}


void AdbCrypt::completerActivated(const QString &curText__)
{
    QMap <QString, QString> __settingsMap;

    if(decryptCredentials4romFile(__settingsMap)){

        passwForm_->setText(crypto_passw_.decryptToString(__settingsMap[curText__]));

    }

}


/*bool*/void AdbCrypt::reGenKey()//clearSavedUserData()
{

    AdbCryptUtility::deleteFile(dataFileFullPath_,"encrypted data file");

    AdbCryptUtility::deleteFile(cryptoFileFullPath_, "key");

    wordList.clear();

    generateNewKey2bin();
    getKey4romBin();


    setLoginCompleter();

    //
    AdbCryptUtility::deleteFile(conHostsFileFullPath_, "saved hosts file");
    conHostsList_.clear();
    setHostCompleter();
    //

    return;
}

void AdbCrypt::getSavedLogins()
{
    if(loginForm_->text().isEmpty())
    {
      loginForm_->completer()->setCompletionPrefix("");
      loginForm_->completer()->complete();
    }
}

QString AdbCrypt::decryptSomeBinF(const QString &fNameWpath__)
{
    QDataStream IODataStream={};

    // open file with user credentials
    QFile file(fNameWpath__);

    if(!file.open(QIODevice::ReadOnly)){

        qDebug() << __FA"Decrypt::Unable to open data file for decrypt.";
        return "";
    }

    // read encrypted data from file and copy to raw bytes structure
    IODataStream.setDevice(&file);
    QByteArray cypherText="";
    IODataStream >> cypherText;

    file.close();


    // 'unzip' credentials (with encrtypted pass)
    QByteArray decryptedFileRawBytes = crypto_binf_.decryptToByteArray(cypherText);


    if ((crypto_binf_.lastError() != SimpleCrypt::ErrorNoError)) {
        qDebug() << __FA"Decrypt::Error while decoding binary file. Reason::"<< crypto_binf_.lastError();
        return "";
    }

    // open
    QBuffer buffer(&decryptedFileRawBytes);
    buffer.open(QIODevice::ReadOnly);
    IODataStream.setDevice(&buffer);
    IODataStream.setVersion(QDataStream::Qt_4_7);

    QString decryptedFormattedString;
    IODataStream >> decryptedFormattedString; //stream in a string

    buffer.close();

    return decryptedFormattedString;
}

void AdbCrypt::encryptSomeInfoToSomeBinF(const QString &info__, const QString &fNameWpath__, int linesLim__, bool removeDuplicates__)
{
    QByteArray decryptedFileRawBytes{""};
    QBuffer buffer{};
    //QDataStream decryptedFileDataStream{};
    QString decryptedFormattedString{""};
    QDataStream IODataStream={};

    QFile file(fNameWpath__);

    if(file.exists()){

        if(file.open(QIODevice::ReadOnly)){

            IODataStream.setDevice(&file);    // read the data serialized from the file

            QByteArray cyphertext;
            IODataStream >> cyphertext;           // extract "the answer is" and 42

            file.close();

            decryptedFileRawBytes = crypto_binf_.decryptToByteArray(cyphertext);

            if ((crypto_binf_.lastError() != SimpleCrypt::ErrorNoError)) {

                qDebug() << __FA"Encrypt::Error while decoding binary file. Reason::"<< crypto_binf_.lastError();

            } else{

                buffer.setData(decryptedFileRawBytes);

                if(buffer.open(QIODevice::ReadOnly)){

                    IODataStream.setDevice(&buffer);
                    IODataStream.setVersion(QDataStream::Qt_4_7);

                    IODataStream >> decryptedFormattedString; //stream in a string

                    buffer.close();


                }

            }

        }

    }


    if(!(removeDuplicates__ && AdbCryptUtility::removeDuplicateLine4romStr(decryptedFormattedString,info__))){

        AdbCryptUtility::cutStr2linesLim(decryptedFormattedString,linesLim__-1);
    }


    QTextStream decryptedFormattedStringIOStream(&decryptedFormattedString);


    decryptedFormattedStringIOStream << info__  << Qt::endl;



    crypto_binf_.setCompressionMode(SimpleCrypt::CompressionAlways); //always compress the data, see section below
    crypto_binf_. setIntegrityProtectionMode(SimpleCrypt::ProtectionHash);


    buffer.open(QIODevice::WriteOnly);

    QDataStream bufferDataIOStream(&buffer);

    bufferDataIOStream.setVersion(QDataStream::Qt_4_7);

    bufferDataIOStream << decryptedFormattedString;


    QByteArray myCypherText = crypto_binf_.encryptToByteArray(buffer.data());


    if ((crypto_binf_.lastError() != SimpleCrypt::ErrorNoError)) {

        qDebug() << __FA"Encrypt::Error while encoding 2 binary file. Reason::"<< crypto_binf_.lastError();

    } else {


        file.open(QIODevice::WriteOnly);
        /*QDataStream out*/IODataStream.setDevice(&file);

        IODataStream << myCypherText;


        file.close();

    }

    buffer.close();

}

void AdbCrypt::encryptCurHost()
{
    if(hostForm_){

        QString __text2Encrypt;

        QString const curHostEntry = hostForm_->text();

        if(!curHostEntry.isEmpty()){

            __text2Encrypt = curHostEntry;

        } else{

            __text2Encrypt = "localhost";
        }


        encryptSomeInfoToSomeBinF(__text2Encrypt,conHostsFileFullPath_,conHostEntrLim_, true);

    }
}

void AdbCrypt::decrSavedConHosts()
{
    if(hostForm_){

        auto decrStr = decryptSomeBinF(conHostsFileFullPath_);

        conHostsList_.clear();

        conHostsList_ = decrStr.split("\n");

        if(!conHostsList_.isEmpty())
            conHostsList_.removeLast();

        std::reverse(conHostsList_.begin(), conHostsList_.end());

        setHostCompleter();
    }
}

void AdbCrypt::getSavedHosts()
{
    if(hostForm_){

        if(hostForm_->text().isEmpty()){
            hostForm_->completer()->setCompletionPrefix("");
            hostForm_->completer()->complete();
        }
    }
}

AdbCrypt::~AdbCrypt()
{

}

QString AdbCrypt::pluginName()
{
    return "AdbCrypt";
}

void AdbCrypt::setHostCompleter()
{
    if(hostForm_){
        conHostsCompleter_.setModel(&conHostsListModel_);

        conHostsListModel_.setStringList(conHostsList_);

        hostForm_->setCompleter(&conHostsCompleter_);
    }
}

void AdbCrypt::setLoginCompleter()
{
    completer->setModel(&completerModel);

    completerModel.setStringList(wordList);

    loginForm_->setCompleter(completer);
}


bool AdbCryptUtility::deleteFile(const QString & fullFilePath__, QString const & fileLogDescr__)
{
    if(QFile::exists(fullFilePath__)){

        qDebug()<<QStringLiteral(__SU"%1 exists.").arg(fileLogDescr__);

        if(!QFile::remove(fullFilePath__)){

            qDebug()<<QStringLiteral(__FA"error while removing %1.").arg(fileLogDescr__);
            return false;
        }

        qDebug()<<QStringLiteral(__SU"%1 successfully removed.").arg(fileLogDescr__);
        return true;
    }

    qDebug()<<QStringLiteral(__SU"%1 not exists. Nothing to delete.").arg(fileLogDescr__);
    return false;
}



int AdbCryptUtility::createFile(const QString &fullFilePath__, const QString &fileLogDescr__)
{
    int __status;

    QFile __file(fullFilePath__);

    do{

        if(__file.exists()){

            qDebug() << QStringLiteral(__SU"%1 already exist.").arg(fileLogDescr__);
            __status = fileCreateStatus::AlreadyExist;
            break;
        }

        if(__file.open(QIODevice::WriteOnly)){

            qDebug() << QStringLiteral(__SU"%1 successfully created.").arg(fileLogDescr__);
            __status = fileCreateStatus::Success;

        } else{

            qDebug() << QStringLiteral(__FA"%1 create failed.").arg(fileLogDescr__);
            __status = fileCreateStatus::Failed;
        }

    }while(false);

    return __status;
}

void /*AdbCryptUtility::*/AdbCrypt::cutCredentialsEntries2linesLim(QString &str2cut__, int linesLim__)
{

    do{
        QStringList list = str2cut__.split('\n');
        int listSize = list.size()-1;

        if(linesLim__<0){
            auto warningMessage = __WA"Can't cut data with lines limit less then 0.";
            qDebug() << warningMessage;
            std::cout << warningMessage << std::endl;
            break;
        }

        if(listSize>linesLim__){


            QString loginLine="";

            QTextStream IOTextStream{&str2cut__};


            if(!IOTextStream.atEnd())
                loginLine = IOTextStream.readLine();


            QString loginWord2remove = getLogin4romEntrie(&loginLine);


            wordList.removeOne(loginWord2remove);


            int lineOneSkipIndex = str2cut__.indexOf('\n')+1;

            int lengthBefore = str2cut__.length();

            QString tmpStr = QStringRef(&str2cut__,lineOneSkipIndex,lengthBefore-lineOneSkipIndex).toString();


            str2cut__ = tmpStr;

        } else{

            break;
        }

    }while(true);
}



void AdbCrypt::removeDuplicateCredentialsEntrie(QString * decryptedFormattedFileContent, QString const & dupLogin)
{

    QString entrie2remove;

    entrie2remove = getLineEntrie(decryptedFormattedFileContent,dupLogin);

    if(!entrie2remove.isEmpty()){


        // remove line completely
        int indOfEntrieLine = decryptedFormattedFileContent->indexOf(entrie2remove);

        int indOfEndl = decryptedFormattedFileContent->indexOf('\n',indOfEntrieLine)+1;


        decryptedFormattedFileContent->remove(indOfEntrieLine,indOfEndl-indOfEntrieLine);


    } else {

        qDebug() << __WA"removeDuplicate::Entrie2Remove is empty.";
    }
}


void AdbCrypt::parseCredentials2Map(QString *decryptedFileContent__, QMap<QString, QString> *settingsMap__)
{

    QString line{""},login{""},encryptedPassw{""};

    int delimiterPosition;

    QTextStream inParse(decryptedFileContent__);

    while (!inParse.atEnd())
    {

        line = inParse.readLine();

        auto lineSize = line.size();

        delimiterPosition = line.indexOf("=");

        if(line.isEmpty() || line[0]=='#' || delimiterPosition==-1)
           continue;


        login = QStringRef(&line,0,delimiterPosition).toString().remove(' ');


        auto firstBracket = line.indexOf("\"",delimiterPosition);

        auto lastBracket = line.indexOf("\"",firstBracket+1);


        if(firstBracket!=-1&&lastBracket!=-1){

            encryptedPassw = line.remove(lastBracket+1,lineSize-1-lastBracket)
                   .remove(delimiterPosition+1,firstBracket-1-delimiterPosition)
                   .mid(delimiterPosition+1)
                   .remove("\"");

            settingsMap__->insert(login,encryptedPassw);

        }

    }

}


QString AdbCrypt::getPassword(QString *decryptedFileContent__, const QString &login__)
{
    QString line{""},login{""},encryptedPassw{""};

    int delimiterPosition;

    QTextStream inParse(decryptedFileContent__);

    while (!inParse.atEnd())
    {

        line = inParse.readLine();

        auto lineSize = line.size();

        delimiterPosition = line.indexOf("=");

        if(line.isEmpty() || line[0]=='#' || delimiterPosition==-1)
           continue;


        login = QStringRef(&line,0,delimiterPosition).toString().remove(' ');

        if(login!=login__){

            continue;

        }else{

            auto firstBracket = line.indexOf("\"",delimiterPosition);

            auto lastBracket = line.indexOf("\"",firstBracket+1);

            if(firstBracket!=-1&&lastBracket!=-1){

                encryptedPassw = line.remove(lastBracket+1,lineSize-1-lastBracket)
                       .remove(delimiterPosition+1,firstBracket-1-delimiterPosition)
                       .mid(delimiterPosition+1)
                       .remove("\"");

                return encryptedPassw;

            }

        }

    }

    return "";
}

QString AdbCrypt::getLogin4romEntrie(QString *lineEntrie__)
{
    QString line{""},login{""};

    int delimiterPosition;

    QTextStream inParse(lineEntrie__);

    while (!inParse.atEnd())
    {

        line = inParse.readLine();


        delimiterPosition = line.indexOf("=");

        if(line.isEmpty() || line[0]=='#' || delimiterPosition==-1)
           continue;


        login = QStringRef(&line,0,delimiterPosition).toString().remove(' ');

        return login;

    }

    return "";
}

QString AdbCrypt::getLineEntrie(QString *decryptedFileContent__, const QString &login__)
{
    QString line{""},login{""};

    int delimiterPosition;

    QTextStream inParse(decryptedFileContent__);

    while (!inParse.atEnd())
    {

        line = inParse.readLine();

        delimiterPosition = line.indexOf("=");

        if(line.isEmpty() || line[0]=='#' || delimiterPosition==-1)
           continue;


        login = QStringRef(&line,0,delimiterPosition).toString().remove(' ');

        if(login!=login__)
            continue;
        else
            return line;

    }

    return "";
}


void AdbCryptUtility::cutStr2linesLim(QString &str2cut__, int linesLim__)
{

    do{

        if(linesLim__<0){
            auto warningMessage = __WA"Can't cut data with lines limit less then 0.";
            qDebug() << warningMessage;
            std::cout << warningMessage << std::endl;
            break;
        }

        QStringList list = str2cut__.split('\n');
        int listSize = list.size()-1;


        if(listSize>linesLim__){


            if(!list.isEmpty()){

                list.removeFirst();

                auto tmpStr = list.join("\n");

                str2cut__ = tmpStr;

            } else{

                break;
            }

        } else{

            break;
        }

    }while(true);
}


bool AdbCryptUtility::removeDuplicateLine4romStr(QString &strRef__, const QString &line2remove__)
{
    do{

        if(!line2remove__.isEmpty()){

            int indOfEntrieLine = strRef__.indexOf(line2remove__);
            if(indOfEntrieLine == -1)
                break;

            // remove line completely
            int indOfEndl = strRef__.indexOf('\n',indOfEntrieLine)/*+1*/;

            if(indOfEndl == -1)
                break;
            else
                indOfEndl++;

            strRef__.remove(indOfEntrieLine,indOfEndl-indOfEntrieLine);

            return true;

        }

        qDebug() << __WA"removeDuplicateLine4romStr::line2remove is empty.";

    }while(false);

    return false;

}


