FROM alpine:edge

MAINTAINER Andrea Ceresoni

VOLUME ["/opt/Taipan"]


RUN echo "@testing http://dl-4.alpinelinux.org/alpine/edge/testing" >> /etc/apk/repositories \
    && apk add --update mono@testing  \
    && rm -rf /var/cache/apk/* \
    && wget https://ci.appveyor.com/api/buildjobs/fww164wj4fndtqu8/artifacts/Src%2Fdeploy.zip -P /opt \
    && unzip /opt/Src%2Fdeploy.zip -d /opt \
    && unzip /opt/Taipan.1.7.1215341470.zip -d /opt \
    && rm /opt/Src%2Fdeploy.zip /opt/Taipan.1.7.1215341470.zip 
