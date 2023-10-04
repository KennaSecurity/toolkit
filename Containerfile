FROM ruby:3.2.2
USER root

# Update the base image.
RUN apt-get update -y && apt-get upgrade -y 

# Copy Files To Container.
ADD . "/opt/app/toolkit/"

# Run Bundle Install
WORKDIR "/opt/app/toolkit/"
RUN gem install bundler

# CVE-2023-36617
RUN gem install uri -v 0.12.2
# CVE-2023-28756
RUN gem install time -v 0.2.2

RUN bundle install

# Set Entrypoint
ENTRYPOINT ["./scripts/entrypoint.sh"]
CMD ["help"]
