FROM registry.access.redhat.com/ubi8/ruby-26
USER root

RUN REPO_LIST="ubi-8-baseos,ubi-8-appstream,ubi-8-codeready-builder"
RUN yum update -y
RUN yum install python3 ruby ruby-devel ruby-irb ruby-libs rubygems rubygems-devel rubygem-bundler -y
RUN yum -y clean all

# Removing NodeJS from base image since it isnt needed. (JG 10/25/2020)
RUN yum remove -y nodejs 

RUN { echo 'install: --no-document'; echo 'update: --no-document'; } >> /etc/gemrc && \
    /usr/bin/gem install bundler && rm -rf /root/.gem && \
    rm -rfv /var/cache/*  /var/log/* /tmp/*

# Setup The Enviroment. 
RUN mkdir -p /opt/app/toolkit/
RUN gem install bundler:2.0.2
ENV GEM_HOME=/opt/app/bundle/
ENV BUNDLE_SILENCE_ROOT_WARNING=1 BUNDLE_APP_CONFIG="/opt/app/bundle/"
ENV PATH "/opt/app/bundle"/bin:"$PATH"
RUN mkdir -p "/opt/app/bundle/"

# Copy Files To Container.
ADD . "/opt/app/toolkit/"

# Run Bundle Install
WORKDIR "/opt/app/toolkit/"
RUN bundle install

# Set Entrypoint
ENTRYPOINT ["./scripts/entrypoint.sh"]
CMD ["help"]