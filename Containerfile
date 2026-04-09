FROM ruby:3.4
HEALTHCHECK NONE

# Update the base image.
RUN apt-get update -y && apt-get upgrade -y

# Copy Files To Container.
COPY . "/opt/app/toolkit/"

# Run Bundle Install
WORKDIR "/opt/app/toolkit/"
RUN gem install bundler && \
	bundle install

# Set Entrypoint
ENTRYPOINT ["./scripts/entrypoint.sh"]
CMD ["help"]
