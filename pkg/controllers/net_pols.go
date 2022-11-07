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

package controllers

import (
	"context"
	"fmt"
	"net"
	"reflect"

	"github.com/CloudNativeSDWAN/egress-watcher/pkg/sdwan"
	"github.com/rs/zerolog"
	netv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

const (
	netPolsCtrlName string = "network-policy-event-handler"
)

type NetworkPolicyOptions struct {
	WatchAllNetworkPolicies bool `yaml:"watchAllNetworkPolicies"`
}

type netPolsEventHandler struct {
	options *NetworkPolicyOptions
	opsChan chan *sdwan.Operation
	log     zerolog.Logger
}

func NewNetworkPolicyController(mgr manager.Manager, options *NetworkPolicyOptions, opsChan chan *sdwan.Operation, log zerolog.Logger) (controller.Controller, error) {
	if opsChan == nil {
		return nil, fmt.Errorf("no operations channel provided")
	}

	npHandler := &netPolsEventHandler{options, opsChan, log}

	c, err := controller.New(netPolsCtrlName, mgr, controller.Options{
		Reconciler: reconcile.Func(func(c context.Context, r reconcile.Request) (reconcile.Result, error) {
			return reconcile.Result{}, nil
		}),
	})

	if err != nil {
		return nil, err
	}

	err = c.Watch(&source.Kind{Type: &netv1.NetworkPolicy{}}, npHandler)
	if err != nil {
		return nil, err
	}

	return c, nil
}

// Update handles update events.
func (n *netPolsEventHandler) Update(ue event.UpdateEvent, wq workqueue.RateLimitingInterface) {
	l := n.log.With().Str("event-handler", "Update").Logger()
	defer wq.Done(ue.ObjectNew)

	curr, currok := ue.ObjectNew.(*netv1.NetworkPolicy)
	old, oldok := ue.ObjectOld.(*netv1.NetworkPolicy)
	if !currok || !oldok {
		return
	}

	currParsedIps := getIps(curr)
	oldParsedIps := getIps(old)

	currIps := map[string]bool{}
	for _, currIp := range currParsedIps {
		currIps[currIp] = true
	}

	oldIps := map[string]bool{}
	for _, oldIp := range oldParsedIps {
		oldIps[oldIp] = true
	}

	if !shouldWatchLabel(curr.Labels, n.options.WatchAllNetworkPolicies) {
		if !shouldWatchLabel(old.Labels, n.options.WatchAllNetworkPolicies) {
			return
		}

		l.Info().Str("reason", "no watch enabled").Msg("sending delete...")
		n.opsChan <- &sdwan.Operation{
			Type:            sdwan.OperationRemove,
			ApplicationName: curr.Name,
			Servers:         oldParsedIps,
		}
		return
	}

	if n.options.WatchAllNetworkPolicies {
		l.Info().Str("reason", "change to New IPs from Old IPs").
			Strs("new-hosts", currParsedIps).
			Strs("old-hosts", oldParsedIps).
			Msg("sending update...")

		// First, delete...
		n.opsChan <- &sdwan.Operation{
			Type:            sdwan.OperationRemove,
			ApplicationName: curr.Name,
			Servers:         oldParsedIps,
		}

		// ... then, add
		n.opsChan <- &sdwan.Operation{
			Type:            sdwan.OperationAdd,
			ApplicationName: curr.Name,
			Servers:         currParsedIps,
		}
	}

	if len(currParsedIps) == 0 {
		if len(oldParsedIps) == 0 {
			return
		}

		l.Info().Str("reason", "no valid hosts").Msg("sending delete...")
		n.opsChan <- &sdwan.Operation{
			Type:            sdwan.OperationRemove,
			ApplicationName: curr.Name,
			Servers:         oldParsedIps,
		}

		return
	}

	if reflect.DeepEqual(currIps, oldIps) {
		return
	}

	l.Info().Str("reason", "different IPs").
		Strs("new-IPs", currParsedIps).
		Strs("old-IPs", oldParsedIps).
		Msg("sending update...")

	// First, delete...
	n.opsChan <- &sdwan.Operation{
		Type:            sdwan.OperationRemove,
		ApplicationName: curr.Name,
		Servers:         oldParsedIps,
	}

	// ... then, add
	n.opsChan <- &sdwan.Operation{
		Type:            sdwan.OperationAdd,
		ApplicationName: curr.Name,
		Servers:         currParsedIps,
	}
}

// Delete handles delete events.
func (n *netPolsEventHandler) Delete(de event.DeleteEvent, wq workqueue.RateLimitingInterface) {
	l := n.log.With().Str("event-handler", "Delete").Logger()
	defer wq.Done(de.Object)

	l.Info().Msg("deleting...")

	netpol, ok := de.Object.(*netv1.NetworkPolicy)
	if !ok {
		l.Error().Msg("could not unmarshal network policy!")
		return
	}

	if !shouldWatchLabel(netpol.Labels, n.options.WatchAllNetworkPolicies) {
		return
	}

	parsedIps := getIps(netpol)

	if len(parsedIps) == 0 {
		l.Debug().Msg("no valid IPs detected: skipping...")
		return
	}

	n.opsChan <- &sdwan.Operation{
		Type:            sdwan.OperationRemove,
		ApplicationName: netpol.Name,
		Servers:         parsedIps,
	}
}

// Create handles create events.
func (n *netPolsEventHandler) Create(ce event.CreateEvent, wq workqueue.RateLimitingInterface) {
	l := n.log.With().Str("event-handler", "Create").Logger()
	defer wq.Done(ce.Object)

	netpol, ok := ce.Object.(*netv1.NetworkPolicy)
	if !ok {
		l.Error().Msg("could not unmarshal network policy!")
		return
	}

	parsedIps := getIps(netpol)

	if len(parsedIps) == 0 {
		l.Debug().Msg("no valid IPs detected: skipping...")
		return
	}

	if len(parsedIps) > 8 {
		l.Warn().Msg("CIDRs/IP addresses should not be more than 8. Only the first 8 would be selected")
		parsedIps = parsedIps[0:8]
	}

	l = l.With().Strs("IPs", parsedIps).Logger()

	n.opsChan <- &sdwan.Operation{
		Type:            sdwan.OperationAdd,
		ApplicationName: netpol.Name,
		Servers:         parsedIps,
	}
}

// Generic handles generic events.
func (n *netPolsEventHandler) Generic(ge event.GenericEvent, wq workqueue.RateLimitingInterface) {
	// We don't really know what to do with generic events.
	// We will just ignore this.
	wq.Done(ge.Object)
}

func getIps(n *netv1.NetworkPolicy) (ips []string) {
	for _, host := range n.Spec.Egress {
		for _, ip := range host.To {
			ipv4Addr, _, _ := net.ParseCIDR(ip.IPBlock.CIDR)
			if len(validation.IsValidIP(ipv4Addr.String())) == 0 {
				ips = append(ips, ipv4Addr.String())
			}
		}
	}
	return ips
}
