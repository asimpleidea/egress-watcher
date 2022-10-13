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

package status

import (
	"strings"
	"time"
)

type Summary struct {
	Action              string  `json:"action"`
	Name                string  `json:"name"`
	DetailsURL          string  `json:"detailsURL"`
	StartTime           string  `json:"startTime"`
	EndTime             string  `json:"endTime"`
	UserSessionUsername string  `json:"userSessionUserName"`
	UserSessionIP       string  `json:"userSessionIP"`
	TenantName          string  `json:"tenantName"`
	Total               int     `json:"total"`
	Status              string  `json:"status"`
	Counts              *Counts `json:"count,omitempty"`
}

type Counts struct {
	InProgress *int `json:"In progress,omitempty"`
	Success    *int `json:"Success"`
}

func (s *Summary) Finished() bool {
	return strings.ToLower(s.Status) == "done"
}

func (s *Summary) Successful() bool {
	if s.Counts == nil {
		return false
	}

	if s.Counts.Success == nil {
		return false
	}

	return *s.Counts.Success == s.Total
}

type WaitOptions struct {
	Duration    time.Duration
	OperationID string
}
