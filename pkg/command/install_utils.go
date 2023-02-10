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

package command

import (
	"context"
	"fmt"
	"time"

	"github.com/enescakir/emoji"
	"gopkg.in/yaml.v3"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type installer struct {
	namespace string
	name      string
	clientset *kubernetes.Clientset

	namespaceExisted bool
	saExisted        bool
}

func newInstaller(clientset *kubernetes.Clientset, namespace, name string) (*installer, error) {
	if clientset == nil {
		return nil, fmt.Errorf("no clientset provided")
	}
	if namespace == "" {
		namespace = defaultNamespace
	}
	if name == "" {
		name = defaultName
	}

	inst := &installer{
		clientset: clientset,
		namespace: namespace,
		name:      name,
	}

	// Check if namespace already exists
	nsExisted, err := func() (bool, error) {
		ctx, canc := context.WithTimeout(context.Background(), 10*time.Second)
		defer canc()

		_, err := clientset.CoreV1().Namespaces().Get(ctx, namespace, metav1.GetOptions{})
		if err != nil {
			if k8serrors.IsNotFound(err) {
				return false, nil
			}

			return false, err
		}

		return true, nil
	}()
	if err != nil {
		return nil, fmt.Errorf("cannot check if namespace %s already exists: %w", namespace, err)
	}
	if nsExisted {
		inst.namespaceExisted = nsExisted
		return inst, nil
	}

	// Check if service account already exists
	saName := name + "-service-account"
	saExisted, err := func() (bool, error) {
		ctx, canc := context.WithTimeout(context.Background(), 10*time.Second)
		defer canc()

		_, err := clientset.CoreV1().ServiceAccounts(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			if k8serrors.IsNotFound(err) {
				return false, nil
			}

			return false, err
		}

		return true, nil
	}()
	if err != nil {
		return nil, fmt.Errorf("cannot check if service account %s already exists: %w", saName, err)
	}

	inst.saExisted = saExisted
	return inst, nil
}

func (i *installer) install(ctx context.Context, containerImage string, opts Options) error {
	// Array of functions to execute for installing
	installers := []func(context.Context) error{
		i.createClusterRole,
		i.createClusterRoleBinding,
		i.createNamespace,
		i.createServiceAccount,
		func(ctx context.Context) error {
			return i.createSecret(ctx, opts)
		},
		func(ctx context.Context) error {
			return i.createConfigMap(ctx, opts)
		},
		func(ctx context.Context) error {
			return i.createDeployment(ctx, containerImage)
		},
	}

	// Array of resources for printing
	resources := []string{
		"cluster role",
		"cluster role binding",
		"namespace",
		"service account",
		"secret",
		"config map",
		"deployment",
	}

	for index, inst := range installers {
		fmt.Printf("creating %s...", resources[index])

		if err := inst(ctx); err != nil {
			fmt.Println(" ", emoji.CrossMark, err)
			i.cleanUp()
			return err
		}

		fmt.Println(" ", emoji.CheckMarkButton)
	}

	return nil
}

func (i *installer) createClusterRole(ctx context.Context) (err error) {
	name := i.name + "-cluster-role"

	cr := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: i.namespace,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"networking.istio.io"},
				Resources: []string{"serviceentries"},
				Verbs:     []string{"watch", "get", "list"},
			},
			{
				APIGroups: []string{"networking.k8s.io"},
				Resources: []string{"networkpolicies"},
				Verbs:     []string{"watch", "get", "list"},
			},
		},
	}

	_, err = i.clientset.RbacV1().ClusterRoles().
		Create(ctx, cr, metav1.CreateOptions{})
	return
}

func (i *installer) createClusterRoleBinding(ctx context.Context) (err error) {
	name := i.name + "-cluster-role-binding"
	serviceAccountName := i.name + "-service-account"
	clusterRoleName := i.name + "-cluster-role"

	crb := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: i.namespace,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     clusterRoleName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      serviceAccountName,
				Namespace: i.namespace,
			},
		},
	}

	_, err = i.clientset.RbacV1().ClusterRoleBindings().
		Create(ctx, crb, metav1.CreateOptions{})
	return
}

func (i *installer) createNamespace(ctx context.Context) (err error) {
	_, err = i.clientset.CoreV1().Namespaces().
		Create(ctx, &v1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: i.namespace,
			},
		}, metav1.CreateOptions{})

	return
}

func (i *installer) createServiceAccount(ctx context.Context) (err error) {
	name := i.name + "-service-account"

	_, err = i.clientset.CoreV1().ServiceAccounts(i.namespace).Create(context.TODO(), &v1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: i.namespace,
		},
	}, metav1.CreateOptions{})

	return
}

func (i *installer) createSecret(ctx context.Context, opts Options) (err error) {
	name := i.name + "-vmanage-credentials"

	secret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: i.namespace,
		},
		Data: map[string][]byte{
			"username": []byte(opts.Sdwan.Authentication.Username),
			"password": []byte(opts.Sdwan.Authentication.Password),
		},
		Type: "Opaque",
	}

	_, err = i.clientset.CoreV1().Secrets(i.namespace).
		Create(ctx, secret, metav1.CreateOptions{})
	return
}

func (i *installer) createConfigMap(ctx context.Context, opts Options) (err error) {
	name := i.name + "-settings"
	yamlOpts, err := yaml.Marshal(opts)
	if err != nil {
		return fmt.Errorf("cannot marshal options to yaml: %w", err)
	}

	_, err = i.clientset.CoreV1().
		ConfigMaps(i.namespace).Create(ctx, &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: i.namespace,
		},

		Data: map[string]string{
			"settings.yaml": string(yamlOpts),
		},
	}, metav1.CreateOptions{})
	return
}

func (i *installer) createDeployment(ctx context.Context, containerImage string) (err error) {
	deploymentsClient := i.clientset.AppsV1().Deployments(i.namespace)
	secretName := i.name + "-vmanage-credentials"
	configVolumeName := "config-volume"
	serviceAccountName := i.name + "-service-account"
	settingsName := i.name + "-settings"

	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      i.name,
			Namespace: i.namespace,
			Labels: map[string]string{
				"app": defaultName,
			},
		},
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": defaultName,
				},
			},
			Template: v1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app": defaultName,
					},
				},
				Spec: v1.PodSpec{

					Containers: []v1.Container{
						{
							Name:            i.namespace,
							Image:           containerImage,
							ImagePullPolicy: v1.PullAlways,
							Args: []string{
								"run",
								"with-vmanage",
								"--settings-file=/settings/settings.yaml",
								"--sdwan.username=$(SDWAN_USERNAME)",
								"--sdwan.password=$(SDWAN_PASSWORD)",
								"—verbosity=0",
							},
							VolumeMounts: []v1.VolumeMount{
								{
									Name:      configVolumeName,
									MountPath: "/settings",
								},
							},
							Resources: v1.ResourceRequirements{
								Limits: v1.ResourceList{
									"memory": resource.MustParse("100Mi"),
								},
								Requests: v1.ResourceList{
									"cpu":    resource.MustParse("100m"),
									"memory": resource.MustParse("50Mi"),
								},
							},

							Env: []v1.EnvVar{
								{
									Name: "SDWAN_USERNAME",
									ValueFrom: &v1.EnvVarSource{
										SecretKeyRef: &v1.SecretKeySelector{
											LocalObjectReference: v1.LocalObjectReference{
												Name: secretName,
											},
											Key: "username",
										},
									},
								},

								{
									Name: "SDWAN_PASSWORD",
									ValueFrom: &v1.EnvVarSource{
										SecretKeyRef: &v1.SecretKeySelector{
											LocalObjectReference: v1.LocalObjectReference{
												Name: secretName,
											},
											Key: "password",
										},
									},
								},
							},
						},
					},

					Volumes: []v1.Volume{
						{
							Name: configVolumeName,
							VolumeSource: v1.VolumeSource{
								ConfigMap: &v1.ConfigMapVolumeSource{
									LocalObjectReference: v1.LocalObjectReference{
										Name: settingsName,
									},
								},
							},
						},
					},
					ServiceAccountName: serviceAccountName,
				},
			},
		},
	}

	_, err = deploymentsClient.Create(ctx, deployment, metav1.CreateOptions{})
	return
}

func (i *installer) cleanUp() error {
	secretName := i.name + "-vmanage-credentials"
	serviceAccountName := i.name + "-service-account"
	settingsName := i.name + "-settings"
	clusterRoleBindingName := i.name + "-cluster-role-binding"
	clusterRoleName := i.name + "-cluster-role"

	fmt.Println("undoing changes ", emoji.BackArrow)

	// Remove the cluster role
	err := i.clientset.RbacV1().ClusterRoles().
		Delete(context.TODO(), clusterRoleName, metav1.DeleteOptions{})
	if err != nil && !k8serrors.IsNotFound(err) {
		fmt.Println("could not delete cluster role: %w", err)
	}

	// Remove the cluster role binding
	err = i.clientset.RbacV1().ClusterRoleBindings().
		Delete(context.TODO(), clusterRoleBindingName, metav1.DeleteOptions{})
	if err != nil && !k8serrors.IsNotFound(err) {
		fmt.Println("could not delete cluster role binding: %w", err)
	}

	// Remove the deployment
	err = i.clientset.AppsV1().Deployments(i.namespace).
		Delete(context.TODO(), i.name, metav1.DeleteOptions{})
	if err != nil && !k8serrors.IsNotFound(err) {
		fmt.Println("could not delete deployment: %w", err)
	}

	// Remove the service account
	if !i.saExisted {
		err = i.clientset.CoreV1().ServiceAccounts(i.namespace).
			Delete(context.TODO(), serviceAccountName, metav1.DeleteOptions{})
		if err != nil && !k8serrors.IsNotFound(err) {
			fmt.Println("could not delete service account: %w", err)
		}
	}

	// Remove the configmap
	err = i.clientset.CoreV1().ConfigMaps(i.namespace).
		Delete(context.TODO(), settingsName, metav1.DeleteOptions{})
	if err != nil && !k8serrors.IsNotFound(err) {
		fmt.Println("could not delete configmap: %w", err)
	}

	// Remove the secret
	err = i.clientset.CoreV1().Secrets(i.namespace).
		Delete(context.TODO(), secretName, metav1.DeleteOptions{})
	if err != nil && !k8serrors.IsNotFound(err) {
		fmt.Println("could not delete secret: %w", err)
	}

	// Remove the namespace
	if !i.namespaceExisted {
		err = i.clientset.CoreV1().Namespaces().
			Delete(context.TODO(), i.namespace, metav1.DeleteOptions{})
		if err != nil && !k8serrors.IsNotFound(err) {
			fmt.Println("could not delete namespace: %w", err)
		}
	}

	return nil
}
