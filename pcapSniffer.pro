#-------------------------------------------------
#
# Project created by QtCreator 2010-03-18T21:41:33
#
#-------------------------------------------------

QT       -= core gui

TARGET = pcapSniffer
CONFIG   += console
CONFIG   -= app_bundle

TEMPLATE = app
LIBS += -lpcap
SOURCES += main.cpp
