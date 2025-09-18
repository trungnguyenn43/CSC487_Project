FROM ubuntu:latest

RUN apt update \
    && apt -y upgrade \
    && apt -y install man-db \
    && yes | unminimize \
    && apt -y install build-essential \
    && apt -y install gdb \
    && apt -y install dos2unix \
    && apt -y install nano \
    && apt -y install vim \
    && apt clean