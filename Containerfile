FROM quay.io/kennasecurity/ruby:2.6.3-ubi
LABEL maintainer="Kenna Security"

USER root

ENV TOOLKIT_GID=1000
ENV TOOLKIT_HOME=/opt/app/toolkit/
ENV TOOLKIT_UID=1000
ENV TOOLKIT_USER=kenna

RUN mkdir -p ${TOOLKIT_HOME}

RUN groupadd -g "${TOOLKIT_GID}" "${TOOLKIT_USER}" && \
    adduser -u "${TOOLKIT_UID}" -g "${TOOLKIT_GID}" -d "${TOOLKIT_HOME}" "${TOOLKIT_USER}"

RUN chown -R "${TOOLKIT_UID}":"${TOOLKIT_GID}" "${TOOLKIT_HOME}"

# set up gem env
ENV BUNDLER_VERSION=2.0.2
RUN gem install bundler:"${BUNDLER_VERSION}"
ENV GEM_HOME=/opt/app/bundle/
ENV BUNDLE_SILENCE_ROOT_WARNING=1 BUNDLE_APP_CONFIG="${GEM_HOME}"
ENV PATH "${GEM_HOME}"/bin:$PATH
RUN mkdir -p "${GEM_HOME}" && chown -R "${TOOLKIT_UID}":"${TOOLKIT_GID}" "${GEM_HOME}"

# add our files, ensure we can write to output
ADD . "${TOOLKIT_HOME}"
RUN chown -R "${TOOLKIT_UID}":"${TOOLKIT_GID}" "${TOOLKIT_HOME}/output"

# install deps 
WORKDIR "${TOOLKIT_HOME}"
USER "${TOOLKIT_USER}"
RUN bundle install

ENTRYPOINT ["./scripts/entrypoint.sh"]

CMD ['help']
