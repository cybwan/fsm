#!make

SHELL = bash

.PHONY: format
format:
	find . -regex '.*\.\(c\|h\)' -exec clang-format -style=file -i {} \;

.PHONY: test-init
test-init:
	# Configure load-balancer end-point h1
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
	@sudo ip link del cni0
	@sudo ip netns del h1