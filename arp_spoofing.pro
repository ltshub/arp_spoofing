TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += \
    main.c \
    packet.c

LIBS += -lpcap
LIBS += -lpthread

HEADERS += \
    arp_spoofing.h
