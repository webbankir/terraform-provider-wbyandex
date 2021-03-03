// Code generated by protoc-gen-goext. DO NOT EDIT.

package compute

import (
	timestamp "github.com/golang/protobuf/ptypes/timestamp"
)

func (m *Instance) SetId(v string) {
	m.Id = v
}

func (m *Instance) SetFolderId(v string) {
	m.FolderId = v
}

func (m *Instance) SetCreatedAt(v *timestamp.Timestamp) {
	m.CreatedAt = v
}

func (m *Instance) SetName(v string) {
	m.Name = v
}

func (m *Instance) SetDescription(v string) {
	m.Description = v
}

func (m *Instance) SetLabels(v map[string]string) {
	m.Labels = v
}

func (m *Instance) SetZoneId(v string) {
	m.ZoneId = v
}

func (m *Instance) SetPlatformId(v string) {
	m.PlatformId = v
}

func (m *Instance) SetResources(v *Resources) {
	m.Resources = v
}

func (m *Instance) SetStatus(v Instance_Status) {
	m.Status = v
}

func (m *Instance) SetMetadata(v map[string]string) {
	m.Metadata = v
}

func (m *Instance) SetBootDisk(v *AttachedDisk) {
	m.BootDisk = v
}

func (m *Instance) SetSecondaryDisks(v []*AttachedDisk) {
	m.SecondaryDisks = v
}

func (m *Instance) SetNetworkInterfaces(v []*NetworkInterface) {
	m.NetworkInterfaces = v
}

func (m *Instance) SetFqdn(v string) {
	m.Fqdn = v
}

func (m *Instance) SetSchedulingPolicy(v *SchedulingPolicy) {
	m.SchedulingPolicy = v
}

func (m *Instance) SetServiceAccountId(v string) {
	m.ServiceAccountId = v
}

func (m *Instance) SetNetworkSettings(v *NetworkSettings) {
	m.NetworkSettings = v
}

func (m *Instance) SetPlacementPolicy(v *PlacementPolicy) {
	m.PlacementPolicy = v
}

func (m *Resources) SetMemory(v int64) {
	m.Memory = v
}

func (m *Resources) SetCores(v int64) {
	m.Cores = v
}

func (m *Resources) SetCoreFraction(v int64) {
	m.CoreFraction = v
}

func (m *Resources) SetGpus(v int64) {
	m.Gpus = v
}

func (m *AttachedDisk) SetMode(v AttachedDisk_Mode) {
	m.Mode = v
}

func (m *AttachedDisk) SetDeviceName(v string) {
	m.DeviceName = v
}

func (m *AttachedDisk) SetAutoDelete(v bool) {
	m.AutoDelete = v
}

func (m *AttachedDisk) SetDiskId(v string) {
	m.DiskId = v
}

func (m *NetworkInterface) SetIndex(v string) {
	m.Index = v
}

func (m *NetworkInterface) SetMacAddress(v string) {
	m.MacAddress = v
}

func (m *NetworkInterface) SetSubnetId(v string) {
	m.SubnetId = v
}

func (m *NetworkInterface) SetPrimaryV4Address(v *PrimaryAddress) {
	m.PrimaryV4Address = v
}

func (m *NetworkInterface) SetPrimaryV6Address(v *PrimaryAddress) {
	m.PrimaryV6Address = v
}

func (m *NetworkInterface) SetSecurityGroupIds(v []string) {
	m.SecurityGroupIds = v
}

func (m *PrimaryAddress) SetAddress(v string) {
	m.Address = v
}

func (m *PrimaryAddress) SetOneToOneNat(v *OneToOneNat) {
	m.OneToOneNat = v
}

func (m *PrimaryAddress) SetDnsRecords(v []*DnsRecord) {
	m.DnsRecords = v
}

func (m *OneToOneNat) SetAddress(v string) {
	m.Address = v
}

func (m *OneToOneNat) SetIpVersion(v IpVersion) {
	m.IpVersion = v
}

func (m *OneToOneNat) SetDnsRecords(v []*DnsRecord) {
	m.DnsRecords = v
}

func (m *DnsRecord) SetFqdn(v string) {
	m.Fqdn = v
}

func (m *SchedulingPolicy) SetPreemptible(v bool) {
	m.Preemptible = v
}

func (m *NetworkSettings) SetType(v NetworkSettings_Type) {
	m.Type = v
}

func (m *PlacementPolicy) SetPlacementGroupId(v string) {
	m.PlacementGroupId = v
}

func (m *PlacementPolicy) SetHostAffinityRules(v []*PlacementPolicy_HostAffinityRule) {
	m.HostAffinityRules = v
}

func (m *PlacementPolicy_HostAffinityRule) SetKey(v string) {
	m.Key = v
}

func (m *PlacementPolicy_HostAffinityRule) SetOp(v PlacementPolicy_HostAffinityRule_Operator) {
	m.Op = v
}

func (m *PlacementPolicy_HostAffinityRule) SetValues(v []string) {
	m.Values = v
}