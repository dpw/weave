FROM ubuntu
WORKDIR /home/go
RUN sh -c 'apt-get -y update && apt-get -y install --no-install-recommends build-essential git ca-certificates golang docker.io mercurial libpcap-dev curl make pkg-config gcc bison flex'
ENV GOPATH=/home/go WEAVE_REPO=https://github.com/zettio/weave.git WEAVE_BRANCH=master
CMD ["sh", "-c", "git clone -b $WEAVE_BRANCH $WEAVE_REPO /home/go/src/github.com/zettio/weave && make -C /home/go/src/github.com/zettio/weave build"]
