#!make

SHELL = bash

.PHONY: format
format:
	@find . -regex '.*\.\(c\|h\)' -exec clang-format -style=file -i {} \;

.PHONY: kern-trace
kern-trace:
	@sudo cat /sys/kernel/debug/tracing/trace_pipe|grep bpf_trace_printk

.PHONY: test-up
test-up: test-reset
	# Configure load-balancer end-point h1
	@echo 1 > /proc/sys/net/ipv4/ip_forward
	@sudo iptables -t nat -A POSTROUTING -o ens33 -j MASQUERADE
	@sudo ip netns add h1
	@sudo ip link add cni0 type veth peer name eth0 netns h1
	@sudo ip link set cni0 up
	@sudo ip addr add 10.0.0.1/24 dev cni0
	@sudo ip -n h1 link set eth0 up
	@sudo ip netns exec h1 ifconfig eth0 10.0.0.2/24 up
	@sudo ip netns exec h1 ip route add default via 10.0.0.1
	@sudo ip netns exec h1 ifconfig lo up

.PHONY: test-reset
test-reset:
	@sudo ip link del cni0 || true
	@sudo ip netns del h1 || true
	@sudo iptables -t nat -F || true

.PHONY: test-tc-attach
test-tc-attach:
	@sudo ip netns exec h1 tc qdisc add dev eth0 clsact
	@sudo ip netns exec h1 tc filter add dev eth0 ingress bpf object-pinned /sys/fs/bpf/fsm/classifier_sidecar_ingress
	@sudo ip netns exec h1 tc filter add dev eth0 egress bpf object-pinned /sys/fs/bpf/fsm/classifier_sidecar_egress

.PHONY: test-tc-detach
test-tc-detach:
	@sudo ip netns exec h1 tc filter del dev eth0 ingress || true
	@sudo ip netns exec h1 tc filter del dev eth0 egress || true
	@sudo ip netns exec h1 tc qdisc del dev eth0 clsact || true

.PHONY: test-tc-show
test-tc-show:
	@sudo ip netns exec h1 tc filter show dev eth0 ingress
	@sudo ip netns exec h1 tc filter show dev eth0 egress

.PHONY: pipy-demo
pipy-demo:
	@pipy -e "pipy().listen(8080).serveHTTP(new Message('hi, it works in sys.\n'))"

.PHONY: h1-curl-1
h1-curl-1:
	@sudo ip netns exec h1 curl 10.0.0.1:8080

.PHONY: h1-pipy-demo
h1-pipy-demo:
	@sudo ip netns exec h1 pipy -e "pipy().listen(8080).serveHTTP(new Message('hi, it works in h1.\n'))"

.PHONY: curl-1
curl-1:
	@curl 10.0.0.2:8080