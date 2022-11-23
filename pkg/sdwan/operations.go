// Copyright (c) 2022 Cisco Systems, Inc. and its affiliates
// All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package sdwan

type OperationType string

const (
	OperationDelete OperationType = "delete"
	OperationAdd    OperationType = "add"
	OperationUpdate OperationType = "update"
)

// type Operation struct {
// 	Type OperationType
// 	// DEPRECATED: use ResourceName instead
// 	ApplicationName string

// 	// ResourceName is the name of the resource that generated the event,
// 	// *not* its kind or type.
// 	ResourceName string

// 	// DEPRECATED: use ServerNames instead
// 	Servers []string

// 	// List of servers, i.e. "api.example.com". Depending on the SDWAN
// 	// controller, this may be ignored if provided together with IPs.
// 	ServerNames []string

// 	// List of IPs in a CIDR form, i.e. "10.10.10.0/24". Depending on the
// 	// SDWAN controller, this may be ignored if provided together with Servers.
// 	IPs []string

// 	// CustomProbe to use for SDWAN. Can be either an FQDN, i.e.
// 	// "api.example.com", or a URL, i.e. "https://api.example.com", or an IP,
// 	// i.e. "10.10.10.21".
// 	CustomProbe string

// 	// The primary port to use for the servers/ips.
// 	PrimaryPort int32
// }

type Operation struct {
	Type OperationType

	ResourceType string
	ResourceName string

	Data         ResourceData
	PreviousData *ResourceData
}

type ResourceData struct {
	// List of servers, i.e. "api.example.com". Depending on the SDWAN
	// controller, this may be ignored if provided together with IPs.
	ServerNames []string

	// List of IPs in a CIDR form, i.e. "10.10.10.0/24". Depending on the
	// SDWAN controller, this may be ignored if provided together with Servers.
	IPs []string

	// CustomProbe to use for SDWAN. Can be either an FQDN, i.e.
	// "api.example.com", or a URL, i.e. "https://api.example.com", or an IP,
	// i.e. "10.10.10.21".
	CustomProbe string

	// Ports used for the resource.
	Ports []ProtocolAndPort
}

type ProtocolAndPort struct {
	Port     uint32
	Protocol string
}
