TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lnetfilter_queue

SOURCES += \
        MurmurHash3.cpp \
        main.cpp

HEADERS += \
    MurmurHash3.h
