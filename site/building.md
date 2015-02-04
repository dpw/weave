---
title: Building Weave
layout: default
---

You only need to build weave if you want to work on the weave codebase
(or you just enjoy building software).

Apart from the `weave` shell script, weave is delivered as a set of
container images.  There is no distribution-specific packaging, so in
principle it shouldn't matter which Linux distribution you build
under.  But naturally, Docker is a prerequisite (version 1.3.0 or
later).  And it is difficult to build under Fedora because [Fedora
does not include static
libraries](http://fedoraproject.org/wiki/Packaging:Guidelines#Packaging_Static_Libraries).
So we recommend building under Ubuntu.

You can also build in a container under any system that supports
Docker.  And naturally, you can run Ubuntu in a VM and build
there.  These options are described below.

## Building directly on Ubuntu

Several prerequisites are needed to build weave:

```bash
$ sudo apt-get install build-essential git golang docker.io mercurial libpcap-dev
```

The go package name is `github.com/zettio/weave`, so the weave git
repository should be cloned into
`$GOPATH/src/`github.com/zettio/weave`, in accordance with (the go
workspace conventions)[https://golang.org/doc/code.html#Workspaces].

```bash
$ WEAVE=github.com/zettio/weave
$ git clone https://$WEAVE $GOPATH/src/$WEAVE
$ cd $GOPATH/src/$WEAVE
```

Then to actually build, simply do:

```bash
$ make
```

This will build the weave components and package them into three
Docker images (`zettio/weave`, `zettio/weavedns`, and
`zettio/weavetools`).  These are then exported (as
`/var/tmp/weave.tar`, `weavends.tar` and `weavetools.tar`).

## Building in a Docker container

As a preliminary step, we create a container image based on Ubuntu
that has all the prerequisites.  This avoids the need to download and
install them for each build.  In the `weave` directory, do:

```bash
$ docker build -t zettio/weave-build build
```

Then to actually build, do:

```bash
$ docker run -v /var/run/docker.sock:/var/run/docker.sock zettio/weave-build
```

Note the `-v` option to give the container access to the Docker daemon
on the host.  When the build completes, the resulting images are
stored in docker on the host, as when building directly under
Ubuntu. The exported images are present under `/var/tmp/` inside the
container, and can be retrieved using `docker cp` if needed.

If you are building under a Fedora or RHEL Docker host (or another
distribution that uses SELinux), and you have SELinux set to enforcing
mode, it will block attempts to access `/var/run/docker.sock` inside
the container.  See
[dpw/selinux-dockersock](https://github.com/dpw/selinux-dockersock)
for a way to work around this problem.

If you want to build weave from a forked repo or a branch other than
master, you can do it by overriding the WEAVE_REPO and WEAVE_BRANCH
container environment variables with the `-e` option to `docker run`, e.g:

```bash
$ docker run -e WEAVE_REPO=<repo URI> -e WEAVE_BRANCH=<branch name> /var/run/docker.sock:/var/run/docker.sock weave-build
```

## Building using Vagrant

If you aren't running Linux, or otherwise don't want to run the docker
daemon outside a VM, you can use
[Vagrant](https://www.vagrantup.com/downloads.html) to run a
development environment. You'll probably need to install
[VirtualBox](https://www.virtualbox.org/wiki/Downloads) too, for
Vagrant to run VMs in.

First, check out the code:

```bash
$ git clone https://github.com/zettio/weave
$ cd weave
```

The `Vagrantfile` in the top directory constructs a VM that has

 * docker installed
 * go tools installed
 * weave dependencies installed
 * $GOPATH set to ~
 * the local working directory mapped as a synced folder into the
   right place in $GOPATH

Once you are in the working directory you can issue

```bash
$ vagrant up
```

and wait for a while (don't worry, the long download and package
installation is done just once). The working directory is sync'ed with
`~/src/github.com/zettio/weave` on the VM, so you can edit files and
use git and so on in the regular filesystem.

To build and run the code, you need to use the VM. To log in and build
the weave image, do

```bash
$ vagrant ssh
vm$ cd src/github.com/zettio/weave
vm$ make
```

The docker daemon is also running in this VM, so you can then do

```bash
vm$ sudo ./weave launch
vm$ docker ps
```

and so on.

You can provide extra Vagrant configuration by putting a file
`Vagrant.local` in the same place as `Vagrantfile`; for instance, to
forward additional ports.
