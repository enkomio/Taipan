FROM alpine:edge

RUN echo "@testing http://dl-4.alpinelinux.org/alpine/edge/testing" >> /etc/apk/repositories \
    && apk add --update mono@testing  \
    && rm -rf /var/cache/apk/*

RUN wget https://ci.appveyor.com/api/buildjobs/fww164wj4fndtqu8/artifacts/Src%2Fdeploy.zip -P /opt
RUN unzip /opt/Src%2Fdeploy.zip -d /opt
RUN unzip /opt/Taipan.1.7.1215341470.zip -d /opt
RUN rm /opt/Src%2Fdeploy.zip /opt/Taipan.1.7.1215341470.zip

