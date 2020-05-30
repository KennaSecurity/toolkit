FROM quay.io/kennasecurity/ruby:latest
LABEL maintainer="Kenna Security"

USER root
ADD . /opt/toolkit

#VOLUME  /opt/toolkit/input  # input directory
#VOLUME  /opt/toolkit/output # output directory

WORKDIR /opt/toolkit

RUN gem install bundler
RUN bundle install

ENTRYPOINT ["./toolkit.sh" ]
