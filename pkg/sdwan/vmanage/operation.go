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

package vmanage

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/CloudNativeSDWAN/egress-watcher/pkg/sdwan"
	vmanagego "github.com/CloudNativeSDWAN/egress-watcher/pkg/vmanage-go"
	"github.com/CloudNativeSDWAN/egress-watcher/pkg/vmanage-go/pkg/applist"
	"github.com/CloudNativeSDWAN/egress-watcher/pkg/vmanage-go/pkg/approute"
	"github.com/CloudNativeSDWAN/egress-watcher/pkg/vmanage-go/pkg/cloudx"
	"github.com/CloudNativeSDWAN/egress-watcher/pkg/vmanage-go/pkg/customapp"
	"github.com/CloudNativeSDWAN/egress-watcher/pkg/vmanage-go/pkg/status"
	"github.com/rs/zerolog"
)

const (
	defaultOpTimeout     time.Duration = 5 * time.Minute
	defaultReauthTimeout time.Duration = 30 * time.Second
	customAppListDesc    string        = "Managed by Egress Watcher."
	maxRetryOperations   int           = 5
)

type OperationsHandler struct {
	client        *vmanagego.Client
	waitingWindow time.Duration
	log           zerolog.Logger
}

func NewOperationsHandler(client *vmanagego.Client, waitingWindow time.Duration, log zerolog.Logger) *OperationsHandler {
	return &OperationsHandler{client, waitingWindow, log}
}

func (o *OperationsHandler) WatchForOperations(mainCtx context.Context, opsChan chan *sdwan.Operation) error {
	// ----------------------------------------
	// Init
	// ----------------------------------------

	ops := []*sdwan.Operation{}
	waitingTimer := time.NewTimer(o.waitingWindow)
	// We stop it immediately, because we only want it to be active
	// when we have at least one operation.
	waitingTimer.Stop()

	o.log.Info().Msg("worker in free mode")

	// ----------------------------------------
	// Watch for the operation
	// ----------------------------------------

	for {
		select {

		// -- Need to quit?
		case <-mainCtx.Done():
			o.log.Err(mainCtx.Err()).Msg("cancel requested")
			waitingTimer.Stop()
			return nil

		// -- Received an operation?
		case op := <-opsChan:
			o.log.Info().
				Str("type", string(op.Type)).
				Str("name", op.ResourceName).
				Strs("hosts", op.Data.ServerNames).
				Msg("received operation request")

			if len(ops) == 0 {
				if o.waitingWindow > 0 {
					o.log.Info().Str("waiting-duration", o.waitingWindow.String()).Msg("starting waiting mode")
				}

				waitingTimer.Reset(o.waitingWindow)
			}

			ops = append(ops, op)
			for len(opsChan) > 0 && o.waitingWindow == 0 {
				// If the waiting window is disabled, then we will try to get
				// all other pending operations, so we will not only work on
				// one operation at time: that would be disastrous for
				// performance!
				ops = append(ops, <-opsChan)
			}

		// -- Need to go into busy mode (i.e. apply configuration on vManage)?
		case <-waitingTimer.C:
			o.busyMode(mainCtx, ops)

			// Reset
			ops = []*sdwan.Operation{}
			o.log.Info().Msg("back in free mode")
		}
	}
}

func (o *OperationsHandler) busyMode(ctx context.Context, operations []*sdwan.Operation) {
	ops, err := o.adaptOperations(ctx, operations)
	if err != nil {
		o.log.Err(err).Msg("error occurred before activating busy mode")
		return
	}
	o.log.Info().Msg("busy mode")

	appListsNamesToEnable := []string{}
	appListsNamesToDisable := []string{}

	// Create a list of custom application lists that need to be
	// disabled prior to be deleted.
	if len(ops.delete) > 0 {
		appListsNamesToDisable = func() []string {
			names := []string{}
			for _, del := range ops.delete {
				names = append(names, del.ResourceName)
			}
			return names
		}()
	}

	// Create whatever needs to be created.
	if len(ops.create) > 0 {
		appListsNamesToEnable = o.handleCreateOps(ctx, ops.create)
	}

	if len(ops.update) > 0 {
		o.handleUpdateOps(ctx, ops.update)
	}

	// Next operation will probably take some time, so let's check if
	// the user/k8s wants us to quit before taking any action.
	if ctx.Err() != nil {
		o.log.Err(ctx.Err()).Msg("stopped before applying new configuration")
		return
	}

	// Now do start busy mode
	if err := o.applyConfiguration(ctx, appListsNamesToEnable, appListsNamesToDisable); err != nil {
		o.log.Err(err).Msg("error occurred while applying configuration")
		return
	}

	if ctx.Err() != nil {
		o.log.Err(ctx.Err()).Msg("stopped before applying new configuration")
		return
	}

	// Now delete other stuff
	if len(ops.delete) > 0 {
		o.handleDeleteOps(ctx, ops.delete)
	}
}

func (o *OperationsHandler) handleCreateOps(mainCtx context.Context, toCreate []*sdwan.Operation) []string {
	appListsToEnable := []string{}

	// ----------------------------------------
	// Create the custom applications (and lists)
	// ----------------------------------------

	for _, create := range toCreate {
		l := o.log.With().
			Str("name", create.ResourceName).
			Logger()
		if len(create.Data.ServerNames) > 0 {
			l = l.With().Str("host", create.Data.ServerNames[0]).Logger()
		} else {
			l = l.With().Strs("ips", create.Data.IPs).Logger()
		}

		l.Debug().Msg("creating custom application...")

		appID, err := o.client.CustomApplications().
			Create(mainCtx, customapp.CreateUpdateOptions{
				Name:        create.ResourceName,
				ServerNames: create.Data.ServerNames,
				L3L4Attributes: func() customapp.L3L4Attributes {
					if len(create.Data.IPs) == 0 {
						return customapp.L3L4Attributes{}
					}

					return customapp.L3L4Attributes{
						TCP: func() []customapp.IPsAndPorts {
							ports := []int32{}
							for _, port := range create.Data.Ports {
								ports = append(ports, int32(port.Port))
							}

							return []customapp.IPsAndPorts{
								{IPs: create.Data.IPs, Ports: &customapp.Ports{Values: ports}},
							}
						}(),
					}
				}(),
			})
		if err != nil {
			l.Err(err).Msg("cannot create custom application: skipping...")
			continue
		}

		l.Info().Str("id", *appID).
			Msg("custom application successfully created")
		l = l.With().Logger()
		l.Debug().Msg("creating custom application list...")

		applistID, err := o.client.ApplicationLists().
			Create(mainCtx, applist.CreateUpdateOptions{
				Name:        create.ResourceName,
				Description: customAppListDesc,
				Applications: []applist.Application{
					{
						Name: create.ResourceName,
						ID:   *appID,
					},
				},
				Probe: getProbe(*create),
			})
		if err != nil {
			l.Err(err).Msg("cannot create custom application list, " +
				"removing custom application just created...")

			if err := o.client.CustomApplications().Delete(mainCtx, *appID); err != nil {
				l.Err(err).Msg("cannot delete custom application")
			}

			continue
		}

		l.Info().Str("id", *applistID).
			Msg("custom application list successfully created")
		appListsToEnable = append(appListsToEnable, create.ResourceName)
	}

	return appListsToEnable
}

func (o *OperationsHandler) handleDeleteOps(mainCtx context.Context, toDelete []*sdwan.Operation) {
	// Get application lists ID to delete
	listsToDelete := map[string]*applist.ApplicationList{}
	lists, _ := o.client.ApplicationLists().List(mainCtx)
	for _, list := range lists {
		for _, del := range toDelete {
			if del.ResourceName == list.Name {
				listsToDelete[list.Name] = list
			}
		}
	}

	for _, list := range listsToDelete {
		l := o.log.With().Str("id", list.ID).Str("name", list.Name).Logger()
		if list.ReferenceCount > 0 {
			l.Warn().Int("references", list.ReferenceCount).
				Msg("application list will not be deleted because it is " +
					"referenced somewhere else")
			continue
		}

		// Get ID of apps to delete
		appIDs := []string{}
		for _, apps := range list.Applications {
			appIDs = append(appIDs, apps.ID)
		}

		l.Debug().Msg("deleting application list...")
		if err := o.client.ApplicationLists().
			Delete(mainCtx, list.ID); err != nil {
			l.Err(err).Msg("cannot delete custom application list")
			continue
		}
		l.Info().Msg("custom application list successfully deleted")

		for _, appID := range appIDs {
			l := o.log.With().Str("application-id", appID).Logger()

			err := o.client.CustomApplications().Delete(mainCtx, appID)
			if err != nil {
				l.Err(err).Msg("cannot delete custom application")
			} else {
				l.Info().Msg("successfully deleted")
			}
		}
	}
}

func (o *OperationsHandler) handleUpdateOps(mainCtx context.Context, toUpdate []*sdwan.Operation) {
	log := o.log.With().Str("handler", "updater").Logger()
	log.Info().Msg("handling updates...")

	for _, upd := range toUpdate {
		l := log.With().
			Str("server-name", upd.Data.ServerNames[0]).
			Str("custom-application-name", upd.ResourceName).
			Logger()

		ca, err := o.client.CustomApplications().GetByName(mainCtx, upd.ResourceName)
		if err != nil {
			l.Err(err).Msg("could not get custom application, skipping...")
			continue
		}

		l.Debug().Msg("updating custom application...")
		caOpts := ca.GetCreateUpdateOptions()
		// TODO: set data
		caOpts.ServerNames = upd.Data.ServerNames
		if err := o.client.CustomApplications().Update(mainCtx, ca.ID, caOpts); err != nil {
			l.Err(err).Msg("could not update custom application")
			continue
		}
		l.Info().Msg("custom application updated successfully")

		l = log.With().
			Str("custom-application-list-name", upd.ResourceName).
			Str("server-name", upd.Data.ServerNames[0]).
			Logger()

		al, err := o.client.ApplicationLists().GetByName(mainCtx, upd.ResourceName)
		if err != nil {
			l.Err(err).Msg("could not get custom application list, skipping...")
		}

		l.Debug().Msg("updating custom application list...")
		opts := al.GetCreateUpdateOptions()
		opts.Probe = getProbe(*upd)
		if err := o.client.ApplicationLists().Update(mainCtx, al.ID, opts); err != nil {
			l.Err(err).Msg("could not update custom application list")
		} else {
			l.Info().Msg("custom application updated successfully")
		}
	}
}

func (o *OperationsHandler) applyConfiguration(mainCtx context.Context, toEnable, toDisable []string) error {
	if len(toEnable) == 0 && len(toDisable) == 0 {
		o.log.Info().Msg("no configuration to apply, skipping...")
		return nil
	}

	o.log.Debug().Msg("toggling applications...")
	pushRequired, err := o.client.CloudExpress().Applications().
		Toggle(mainCtx, cloudx.ToggleOptions{
			Enable:  toEnable,
			Disable: toDisable,
		})
	if err != nil {
		return fmt.Errorf("error while toggling applications: %w", err)
	}

	if !pushRequired {
		// TODO: should we just avoid applying configuration or return like
		// we are doing now?
		o.log.Info().Msg("no push is required")
		return nil
	}

	o.log.Info().Msg("applying configuration to all devices...")
	operationID, err := o.client.CloudExpress().Devices().
		ApplyConfigurationToAllDevices(mainCtx)
	if err != nil {
		return fmt.Errorf("cannot apply configuration to devices: %w", err)
	}

	o.log.Info().Str("operation-id", *operationID).Msg("waiting for operation to complete...")
	summary, err := o.client.Status().WaitForOperationToFinish(mainCtx, status.WaitOptions{
		OperationID: *operationID,
	})
	if err != nil {
		return fmt.Errorf("error while checking operation id: %w", err)
	}
	o.log.Debug().Str("status-summary", summary.Status).Msg("finished")

	o.log.Debug().Msg("getting approute policies to update")
	appRoutePols, err := o.client.AppRoute().List(context.Background())
	if err != nil {
		return fmt.Errorf("cannot get list of approutes: %w", err)
	}
	o.log.Info().Msg("retrieved list of approutes policies")

	for _, arPol := range appRoutePols {
		processID, err := o.client.AppRoute().
			UpdateApplicationListsOnPolicy(mainCtx, arPol.ID, approute.AddRemoveAppListOptions{
				Add:    toEnable,
				Remove: toDisable,
			})
		if err != nil {
			return fmt.Errorf("cannot update approute policy %s (ID %s): %w", arPol.Name, arPol.ID, err)
		}
		o.log.Info().Str("approute-policy", arPol.Name).
			Str("process-id", *processID).
			Msg("successfully updated approute policy and received process ID")

		for _, activatedID := range arPol.ActivatedByVSmartPolicies {
			vpol, err := o.client.VSmartPolicies().Get(mainCtx, activatedID)
			if err != nil {
				return fmt.Errorf("cannot get vSmart policy with ID %s: %w", activatedID, err)
			}
			l := o.log.With().Str("vSmart-policy-name", vpol.Name).Str("vSmart-policy-ID", vpol.ID).Logger()

			if err := o.client.VSmartPolicies().
				UpdateCentralPolicy(context.Background(), *vpol); err != nil {
				return fmt.Errorf("cannot update vSmart policy %s (ID %s): %w", vpol.Name, vpol.ID, err)
			}
			l.Info().Msg("successfully updated vSmart policy")

			operationID, err := o.client.VSmartPolicies().
				ActivatePolicy(context.Background(), vpol.ID, *processID)
			if err != nil {
				return fmt.Errorf("cannot activate vSmart policy policy %s (ID %s): %w", vpol.Name, vpol.ID, err)
			}
			l.Info().Str("operation-ID", *operationID).
				Msg("waiting for vManage to activate vSmart policy...")

			summary, err := o.client.Status().
				WaitForOperationToFinish(mainCtx, status.WaitOptions{
					OperationID: *operationID,
				})
			if err != nil {
				return fmt.Errorf("cannot check operation status: %w", err)
			}

			l.Info().Str("status-summary", summary.Status).Msg("finished activating vSmart policy")
		}
	}

	return err
}

type parsedOperationsResult struct {
	create []*sdwan.Operation
	update []*sdwan.Operation
	delete []*sdwan.Operation
}

func (o *OperationsHandler) adaptOperations(ctx context.Context, toCategorize []*sdwan.Operation) (*parsedOperationsResult, error) {
	parsedResults := &parsedOperationsResult{
		create: []*sdwan.Operation{},
		update: []*sdwan.Operation{},
		delete: []*sdwan.Operation{},
	}

	customApps, err := o.client.CustomApplications().List(ctx)
	if err != nil {
		return nil, err
	}

	caMap := func() map[string]*customapp.CustomApplication {
		m := map[string]*customapp.CustomApplication{}
		for _, app := range customApps {
			m[app.Name] = app
		}
		return m
	}()

	// Before categorizing the operation, we need to split updates. This is
	// because we have a custom application per server name.
	// TODO: must be done for the IPs as well
	newUpds := []*sdwan.Operation{}
	newDels := []*sdwan.Operation{}
	newCreate := []*sdwan.Operation{}
	for _, cat := range toCategorize {
		if cat.Type == sdwan.OperationUpdate {
			updRes := splitUpdateOperations(cat)
			if len(updRes.update) > 0 {
				newUpds = append(newUpds, updRes.update...)
			}
			if len(updRes.delete) > 0 {
				newDels = append(newDels, updRes.delete...)
			}
			if len(updRes.create) > 0 {
				newCreate = append(newCreate, updRes.create...)
			}
		}
	}

	if len(newUpds) > 0 {
		toCategorize = append(toCategorize, newUpds...)
	}
	if len(newDels) > 0 {
		toCategorize = append(toCategorize, newDels...)
	}
	if len(newCreate) > 0 {
		toCategorize = append(toCategorize, newCreate...)
	}

	acceptedProtos := map[string]bool{
		"http":  true,
		"https": true,
		"tls":   true,
		"grpc":  true,
		"http2": true,
		"tcp":   true,
	}

	// Categorize the operation: things that need to be created and
	// ones that must be deleted.
	for _, cat := range toCategorize {
		// First, is the protocol supported by vManage?
		// TODO: move this up in the select case before busy mode
		parsedPorts := []sdwan.ProtocolAndPort{}
		for _, port := range cat.Data.Ports {
			if _, exists := acceptedProtos[strings.ToLower(port.Protocol)]; exists {
				parsedPorts = append(parsedPorts, port)
			}
		}
		if len(parsedPorts) == 0 {
			o.log.Err(errors.New("no supported protocols found")).
				Str("name", cat.ResourceName).Msg("error occurred while parsing protocols: skipping...")
			continue
		}

		for _, serverName := range cat.Data.ServerNames {
			if serverName == "" {
				continue
			}

			// We're going to create a custom application for each host we
			// find, and we're going to call it based on the host itself.
			// e.g.: "api.example.com" will be "api_example_com".
			name := replaceDots(serverName)

			// Recreate the operation
			op := *cat
			op.ResourceName = name
			op.Data.ServerNames = []string{serverName}
			op.Data.Ports = parsedPorts

			switch cat.Type {
			case sdwan.OperationAdd:
				if _, exists := caMap[name]; exists {
					op.Type = sdwan.OperationUpdate
				}

				parsedResults.create = append(parsedResults.create, &op)
			case sdwan.OperationUpdate:
				if op.PreviousData == nil {
					// Note that we take a differente approach with updates
					// (above), and when we parse updates we also remove the
					// previous data because we don't use it. With this check
					// we make sure we skip those un-parsed operations.
					parsedResults.update = append(parsedResults.update, &op)
				}
			case sdwan.OperationDelete:
				if _, exists := caMap[name]; exists {
					parsedResults.delete = append(parsedResults.delete, &op)
				}
			}
		}

		// Now do IPs
		if len(cat.Data.IPs) > 0 {
			op := *cat
			op.ResourceName = replaceDots(cat.Data.IPs[0])
			op.Data.IPs = cat.Data.IPs
			op.Data.Ports = parsedPorts
		}

	}

	return parsedResults, nil
}

func splitUpdateOperations(op *sdwan.Operation) parsedOperationsResult {
	split := parsedOperationsResult{
		create: []*sdwan.Operation{},
		update: []*sdwan.Operation{},
		delete: []*sdwan.Operation{},
	}

	for _, currServName := range op.Data.ServerNames {
		found := false
		parsedOp := &sdwan.Operation{
			ResourceType: op.ResourceType,
			ResourceName: replaceDots(currServName),
			Data: sdwan.ResourceData{
				ServerNames: []string{currServName},
				Ports:       op.Data.Ports,
			},
		}

		for _, prevServerName := range op.PreviousData.ServerNames {
			if currServName == prevServerName {
				parsedOp.Type = sdwan.OperationUpdate
				split.update = append(split.update, parsedOp)
				found = true
				break
			}
		}

		if !found {
			parsedOp.Type = sdwan.OperationAdd
			split.create = append(split.create, parsedOp)
		}
	}

	for _, prevServName := range op.PreviousData.ServerNames {
		found := false
		parsedOp := &sdwan.Operation{
			ResourceType: op.ResourceType,
			ResourceName: replaceDots(prevServName),
			Data: sdwan.ResourceData{
				ServerNames: []string{prevServName},
				Ports:       op.Data.Ports,
			},
		}

		for _, currServName := range op.Data.ServerNames {
			if prevServName == currServName {
				found = true
				break
			}
		}

		if !found {
			parsedOp.Type = sdwan.OperationDelete
			split.delete = append(split.delete, parsedOp)
		}
	}

	return split
}

func replaceDots(hostName string) string {
	return strings.ReplaceAll(
		strings.ReplaceAll(hostName, ".", "_"),
		"*", "_")
}

func getProbe(op sdwan.Operation) applist.Probe {
	if len(op.Data.IPs) > 0 {
		return applist.Probe{
			Type:  applist.IPProbe,
			Value: op.Data.IPs[0],
		}
	}

	serverName := op.Data.ServerNames[0]
	if strings.Contains(serverName, "*") {
		serverName = serverName[2:]
	}

	// Default probe
	probeType := applist.FQDNProbe
	value := serverName

	for _, port := range op.Data.Ports {
		switch port.Port {
		case 80:
			switch strings.ToLower(port.Protocol) {
			case "http":
				probeType = applist.URLProbe
				value = "http://" + serverName
			case "https":
				probeType = applist.URLProbe
				value = "https://" + serverName
			}
		case 443:
			switch strings.ToLower(port.Protocol) {
			case "http":
				// This is probably a corner case.
				probeType = applist.URLProbe
				value = "http://" + serverName
			case "https":
				// In this case we return immediately because https takes
				// precedence.
				return applist.Probe{
					Type:  applist.URLProbe,
					Value: "https://" + serverName,
				}
			}
		}
	}

	return applist.Probe{
		Type:  probeType,
		Value: value,
	}
}
