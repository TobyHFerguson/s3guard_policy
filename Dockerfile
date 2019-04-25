
FROM python:3.7-alpine
MAINTAINER Toby Ferguson <toby@cloudera.com>
RUN apk add --no-cache bash curl jq
# Installing awscli because it has a version requirement for pyaml that I couldnt figure out
RUN curl "https://s3.amazonaws.com/aws-cli/awscli-bundle.zip" -o "awscli-bundle.zip" && \
    unzip awscli-bundle.zip && \					      
    ./awscli-bundle/install -i /usr/local/aws -b /usr/local/bin/aws
RUN pip install altuscli
VOLUME /root/.altus
VOLUME /root/.aws
COPY ./create_s3_guard_policy.sh /
ENTRYPOINT ["/bin/bash", "/create_s3_guard_policy.sh"]
