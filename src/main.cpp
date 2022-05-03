// Copyright 2022 RakuJa
#include <src/tcpserver.h>

#include <QCoreApplication>
#include <QCommandLineParser>
#include <QTcpServer>
#include <iostream>

int main(int argc, char *argv[]) {
    QCoreApplication app(argc, argv);
    QCoreApplication::setApplicationName("ACP-Server");
    QCoreApplication::setApplicationVersion("0.0.1");

    QCommandLineParser parser;
    QString desc = "Server application for AC Project UNIPI";
    parser.setApplicationDescription(desc);
    parser.addHelpOption();  // Adds help option to command line (-h)
    parser.addVersionOption();  // Adds version option (-v)
    parser.addPositionalArgument(
                "ip",
                QCoreApplication::translate(
                    "main",
                    "Ip where the server socket will listen"));
    parser.addPositionalArgument(
                "port",
                QCoreApplication::translate(
                    "main",
                    "Port where the server socket will listen"));

    parser.process(app);
    const QStringList args = parser.positionalArguments();

    QHostAddress ip = QHostAddress("127.0.0.1");
    int port = 25564;
    if (args.length() >= 2) {
        QString inputIp = args.at(0);
        // TODO(RakuJa): BETTER IP VALIDATION CHECK
        if (inputIp.count(".") == 3) {
            ip = QHostAddress(inputIp);
        }
        QString inputPort = args.at(1);
        if (inputPort.toInt() != 0) {
            port = inputPort.toInt();
        }
    }

    // SERVER INITIALIZATION
    TcpServer* server = new TcpServer(0, ip, port);
    server -> startServer();

    return app.exec();
}
