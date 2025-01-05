#ifndef TEXTSTREAMWLINECOUNT_H
#define TEXTSTREAMWLINECOUNT_H

#include <QTextStream>

class TextStreamWLineCount : public QTextStream
{

private:
    int lineCount_ = 0;

public:
    explicit TextStreamWLineCount();

    using QTextStream::QTextStream;

    virtual ~TextStreamWLineCount();

    inline QString readLine(qint64 maxlen = 0){
            ++lineCount_;
            return QTextStream::readLine(maxlen);
    }

    inline int getLineCount() const { return lineCount_; }

    inline void resetLineCount() { lineCount_ = 0; }

    inline void setDevice(QIODevice *device){
        resetLineCount();
        QTextStream::setDevice(device);
    }
};

#endif // TEXTSTREAMWLINECOUNT_H
