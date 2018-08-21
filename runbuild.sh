#!/bin/sh

if [ -z "$JAVA_HOME" ]; then
  printf "No JAVA_HOME detected! "
  printf "Setup JAVA_HOME before build: export JAVA_HOME=/path/to/java\\n"
  exit 1
fi


EXT=so
NM_FLAGS=
TARGET_OS=`uname -s`
case "$TARGET_OS" in
  Darwin)
    EXT=dylib
    export CGO_CFLAGS="-I${JAVA_HOME}/include -I${JAVA_HOME}/include/darwin"
    ;;
  Linux)
    EXT=so
    NM_FLAGS=-D
    export CGO_CFLAGS="-I${JAVA_HOME}/include -I${JAVA_HOME}/include/linux"
    ;;
  *)
  echo "Unknown platform!" >&2
  exit 1
esac


go build -o libdcrd.${EXT} -buildmode=c-shared ./okwallet/libdcrd
[ $? -ne 0 ] && exit 1
nm ${NM_FLAGS} libdcrd.${EXT} |grep "[ _]Java_com_okcoin"
