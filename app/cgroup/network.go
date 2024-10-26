package cgroup

import "github.com/cilium/ebpf"

type BPFCgroupNetworkDirection struct {
	Name       string
	AttachType ebpf.AttachType
}

var BPFCgroupNetworkDirections = []BPFCgroupNetworkDirection{
	{
		Name:       "ingress",
		AttachType: ebpf.AttachCGroupInetIngress,
	},
	{
		Name:       "egress",
		AttachType: ebpf.AttachCGroupInetEgress,
	},
}
