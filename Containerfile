FROM quay.io/kennasecurity/ruby:2.6.3-ubi
LABEL maintainer="Kenna Security"

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