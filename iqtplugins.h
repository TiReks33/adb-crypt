#ifndef I_QT_PLUGINS_H
#define I_QT_PLUGINS_H

#include <QObject>
#include <QLineEdit>

class ICryptoPlugin
{
public:
    virtual ~ICryptoPlugin(){}

    virtual QString pluginName() = 0;

    virtual void getSavedLogins() = 0;

    virtual bool encryptCredentials2File() = 0;

    virtual void encryptSomeInfoToSomeBinF(QString const& info,QString const& fNameWpath,int linesLim, bool removeDuplicates = false) = 0;

    virtual QString decryptSomeBinF(QString const& fNameWpath) = 0;

    virtual void reGenKey() = 0;

    //
    virtual void encryptCurHost() = 0;

    //virtual void decrSavedConHosts() = 0;

    virtual void getSavedHosts() = 0;
    //
};

#endif //I_QT_PLUGINS_H
