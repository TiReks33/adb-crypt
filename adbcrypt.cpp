#include "adbcrypt.h"

#include <QKeyEvent>

#define __SU "::[SUCCESS]::"
#define __FA "::[FAIL]::"
#define __WA "::[WARNING]::"
//#define __ER "::[ERROR]::"

OneTimeString<QString> AdbCryptUtility::__passPhrase {
    #include "test.dat"
};

QString const AdbCryptUtility::__standardPath = QDir::homePath()+"/.adbCrypt";



AdbCrypt::AdbCrypt(QLineEdit * const &loginFormObjRef__, QLineEdit * const &passwFormObjRef__, const QString &directoryPath__, int credLim__)
    : loginForm_{loginFormObjRef__}
    , passwForm_{passwFormObjRef__}

    , crypto_binf_(AdbCryptUtility::__passPhrase.getStr().toUInt())

    , dirPath_{directoryPath__}
    , cryptoFileFullPath_{dirPath_+"/.cr.bin"}
    , dataFileFullPath_{dirPath_+"/.usdata.bin"}

    , completer{new QCompleter{}}

    , credLim_{credLim__}
{

    initObj();

//    std::cout << "address of completer from crypt module" << completer << std::endl;
//    completer->setMaxVisibleItems(4);
}


void AdbCrypt::initObj()
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

//        if(!QFile(dataFileFullPath_).exists()){

//            AdbCryptUtility::createFile(dataFileFullPath_,"data file");

//        } else{

//            if(decryptCredentials4romFile(__settingsMap)){

//                wordList << __settingsMap.keys();
//            }
//        }
        if(QFile(dataFileFullPath_).exists()){

            if(decryptCredentials4romFile(__settingsMap)){

                wordList << __settingsMap.keys();
            }
        }

    }while(false);


    completer->setModel(&completerModel);

    completerModel.setStringList(wordList);

    loginForm_->setCompleter(completer);


    QObject::connect(completer,static_cast<void (QCompleter::*)(QString const&)> (&QCompleter::activated),[=](QString const& selectedStr__){

        completerActivated(selectedStr__);
    });

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

        QFile f2(cryptoFileFullPath_);
        f2.open(QIODevice::ReadWrite);

        QDataStream stream2(&f2);



        /*quint64*/QByteArray testRes;
        stream2 >> testRes;


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


AdbCrypt* AdbCrypt::data(QLineEdit * const &loginFormObjRef__,
                         QLineEdit * const &passwFormObjRef__,
                         const QString &directoryPath__,
                         int credLim__)
{
    static bool singlInstFlag = false;
    static AdbCrypt* __singlInstObjPtr = new AdbCrypt(loginFormObjRef__,passwFormObjRef__,directoryPath__,credLim__);

    if(singlInstFlag){

        qDebug() << __WA"Crypto Module object already initialized. New parameters will be ignored.";

    }else {

        singlInstFlag=true;
    }

    return __singlInstObjPtr;
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


        /*AdbCryptUtility::*/cutLines2lim(decryptedFormattedString,credLim_);

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

    completer->setModel(&completerModel);

    completerModel.setStringList(wordList);

    loginForm_->setCompleter(completer);

    return true;
}


void AdbCrypt::completerActivated(const QString &curText__)
{
    QMap <QString, QString> __settingsMap;

    if(decryptCredentials4romFile(__settingsMap)){


        passwForm_->setText(crypto_passw_.decryptToString(__settingsMap[curText__]));

    }

}


/*bool*/void AdbCrypt::reCreate()//clearSavedUserData()
{

    AdbCryptUtility::deleteFile(dataFileFullPath_,"encrypted data file");

    AdbCryptUtility::deleteFile(cryptoFileFullPath_, "key");

    wordList.clear();

    generateNewKey2bin();
    getKey4romBin();

    completer->setModel(&completerModel);

    completerModel.setStringList(wordList);

    loginForm_ ->setCompleter(completer);


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

void /*AdbCryptUtility::*/AdbCrypt::cutLines2lim(QString &str2cut__, int linesLim__)
{

    do{
        QStringList list = str2cut__.split('\n');
        int listSize = list.size();


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


