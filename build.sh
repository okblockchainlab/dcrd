#!/bin/sh

TARGET_OS=`uname -s`
case "$TARGET_OS" in
  Darwin)
    export CGO_CFLAGS="-I${JAVA_HOME}/include -I${JAVA_HOME}/include/darwin"
    ;;
  Linux)
    export CGO_CFLAGS="-I${JAVA_HOME}/include -I${JAVA_HOME}/include/linux"
    ;;
  *)
  echo "Unknown platform!" >&2
  exit 1
esac

go get ./...
