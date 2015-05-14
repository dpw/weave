#! /bin/bash

. ./config.sh

R1=10.2.1.0/24
C1=c1:
C2=c2:
C3=c3:10.2.2.34
C4=c4:10.2.2.37

PING="ping -nq -W 1 -c 1"

weave_on1() {
    assert_raises "weave_on $HOST1 $@"
}

run_on1() {
    assert_raises "run_on   $HOST1 $@"
}

exec_on1() {
    assert_raises "exec_on  $HOST1 $@"
}

check_container_connectivity() {
    exec_on1 "${C1%:*} $PING ${C2#*:}"
    exec_on1 "${C3%:*} $PING ${C4#*:}"
    # fails due to #620
    # exec_on1 "${C3#:} ! $PING ${C1#*:}"
}

start_suite "exposing weave network to host"

weave_on $HOST1 launch -iprange $R1

for c in $C1 $C2; do
    weave_on $HOST1 run -t --name=${c%:*} gliderlabs/alpine /bin/sh
done
for c in $C3 $C4; do
    weave_on $HOST1 run ${c#*:}/24 -t --name=${c%:*} gliderlabs/alpine /bin/sh
done

# Note can't use weave_on here because it echoes the command
C1IP=$(DOCKER_HOST=tcp://$HOST1:2375 $WEAVE ps c1 | grep -o -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')

# absence of host connectivity by default
run_on1 "! $PING ${C1#*:}"
check_container_connectivity

# host connectivity after 'expose'
weave_on1 "expose"
run_on1   "  $PING $C1IP"
run_on1   "! $PING ${C3#*:}"
check_container_connectivity

# idempotence of 'expose'
weave_on1 "expose"
run_on1   "  $PING $C1IP"

# no host connectivity after 'hide'
weave_on1 "hide"
run_on1   "! $PING $C1IP"

# idempotence of 'hide'
weave_on1 "hide"

end_suite
