// Copyright 2022 RakuJa
#include "src/tcpserver.h"

TcpServer::TcpServer(
        QObject *parent,
        const QHostAddress& ip,
        const int port) : QTcpServer(parent) {
    serverIp = ip;
    serverPort = port;
}


void TcpServer::startServer() {
    qDebug() << "Booting up server ...";
    qDebug() << "Ip address: " << serverIp.toString();
    qDebug() << "Port: " << serverPort;
    if (!this->listen(serverIp, serverPort)) {
        qDebug() << "Could not start server";
    } else {
        qDebug() << "Server boot up sequence success! ...";
    }
}


// This function is called by QTcpServer when a new connection is available.
void TcpServer::incomingConnection(qintptr socketDescriptor) {
    // We have a new connection
    qDebug() << socketDescriptor << " Connecting...";

    // Every new connection will be run in a newly created thread
    ConnectionHandlerThread *thread =
            new ConnectionHandlerThread(socketDescriptor, this);

    // connect signal/slot
    // once a thread is not needed, it will be beleted later
    connect(thread, SIGNAL(finished()), thread, SLOT(deleteLater()));

    thread->start();
}
