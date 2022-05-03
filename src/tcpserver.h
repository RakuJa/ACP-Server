#ifndef SRC_TCPSERVER_H_
#define SRC_TCPSERVER_H_

#include <QObject>
#include <QTcpSocket>
#include <QTcpServer>
#include <QDebug>

// Copyright 2022 RakuJa
#include <src/connectionhandlerthread.h>


class TcpServer : public QTcpServer {
    Q_OBJECT

 public:
    explicit TcpServer(
            QObject *parent = 0,
            const QHostAddress& ip = QHostAddress("127.0.0.1"),
            const int port = 25564);
    void startServer();

 signals:

 public slots:

 protected:
    void incomingConnection(qintptr socketDescriptor);

 private:
    QHostAddress serverIp;
    int serverPort;
};

#endif  // SRC_TCPSERVER_H_
