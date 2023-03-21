FROM ruby:3.2.1
USER root

# Update the base image.
RUN apt-get update -y && apt-get upgrade -y 

# Copy Files To Container.
ADD . "/opt/app/toolkit/"

# Run Bundle Install
WORKDIR "/opt/app/toolkit/"
RUN gem install bundler -v 2.4.9
RUN bundle install

# Set Entrypoint
ENTRYPOINT ["./scripts/entrypoint.sh"]
CMD ["help"]
