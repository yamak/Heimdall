TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += \
        ../elfhasher.cpp \
        main.cpp

HEADERS += \
    ../elfhasher.h \
    ../elfparser.h

INCLUDEPATH += ../

LIBS +=  -lcrypto



