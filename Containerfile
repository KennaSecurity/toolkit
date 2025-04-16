FROM ruby:3.2.2
HEALTHCHECK NONE

# Update the base image.
RUN apt-get update -y && apt-get upgrade -y 

# Copy Files To Container.
COPY . "/opt/app/toolkit/"

# Run Bundle Install
WORKDIR "/opt/app/toolkit/"
RUN gem install bundler && \
	# CVE-2023-36617
	gem install uri -v 0.12.2 && \
	# CVE-2023-28756
	gem install time -v 0.2.2 && \
	bundle install

# Set Entrypoint
ENTRYPOINT ["./scripts/entrypoint.sh"]
CMD ["help"]
