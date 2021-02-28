FROM ruby:2.6
USER root


# Setup The Enviroment. 
RUN apt-get update -y && apt-get upgrade -y 
RUN mkdir -p /opt/app/toolkit/
RUN gem install bundler
ENV GEM_HOME=/opt/app/bundle/
ENV BUNDLE_SILENCE_ROOT_WARNING=1 BUNDLE_APP_CONFIG="/opt/app/bundle/"
ENV PATH "/opt/app/bundle"/bin:"$PATH"
RUN mkdir -p "/opt/app/bundle/"

# Copy Files To Container.
ADD . "/opt/app/toolkit/"

# Run Bundle Install
WORKDIR "/opt/app/toolkit/"
RUN bundle install --without development test

# Set Entrypoint
ENTRYPOINT ["./scripts/entrypoint.sh"]
CMD ["help"]