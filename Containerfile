FROM ruby:2.6.6
USER root

# Update the bas image.
RUN apt-get update -y && apt-get upgrade -y 

# Copy Files To Container.
ADD . "/opt/app/toolkit/"

# Run Bundle Install
WORKDIR "/opt/app/toolkit/"
RUN bundle install --without development test

# Set Entrypoint
ENTRYPOINT ["./scripts/entrypoint.sh"]
CMD ["help"]