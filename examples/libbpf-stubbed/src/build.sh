#!/bin/sh
rm -rf obj build
mkdir obj build
BUILD_STATIC_ONLY=y OBJDIR=obj DESTDIR=build make install
