#ifndef SRC_CONNECTIONHANDLERTHREAD_H_
#define SRC_CONNECTIONHANDLERTHREAD_H_
// Copyright 2022 RakuJa
#include <QThread>
#include <QTcpSocket>

class ConnectionHandlerThread : public QThread {
    Q_OBJECT

 public:
    explicit ConnectionHandlerThread(qintptr ID, QObject *parent = 0);

    void run();

 signals:
    void error(QTcpSocket::SocketError socketError);

 public slots:
    void readyRead();
    void disconnected();

 private:
    QTcpSocket *socket;
    qintptr socketDescriptor;
};

#endif  // SRC_CONNECTIONHANDLERTHREAD_H_
