#!make

SHELL = bash

.PHONY: format
format:
	find . -regex '.*\.\(c\|h\)' -exec clang-format -style=file -i {} \;

.PHONY: test-init
test-init: test-reset
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

.PHONY: test-attach
test-attach:
	@sudo ip netns exec h1 tc qdisc add dev eth0 clsact
	@sudo ip netns exec h1 tc filter add dev eth0 ingress bpf object-pinned /sys/fs/bpf/fsm/classifier_sidecar_ingress
	@sudo ip netns exec h1 tc filter add dev eth0 egress bpf object-pinned /sys/fs/bpf/fsm/classifier_sidecar_egress

.PHONY: test-detach
test-detach:
	@sudo ip netns exec h1 tc filter del dev eth0 ingress
	@sudo ip netns exec h1 tc filter del dev eth0 egress
	@sudo ip netns exec h1 tc qdisc del dev eth0 clsact