package command

import (
	"context"
	"fmt"
	"time"

	"github.com/CloudNativeSDWAN/egress-watcher/pkg/controllers"
	"github.com/CloudNativeSDWAN/egress-watcher/pkg/sdwan"
	"gopkg.in/yaml.v3"
	appsv1 "k8s.io/api/apps/v1"
	apiv1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func createNamespace(clientset *kubernetes.Clientset, usernamespace string) {
	ns := &apiv1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: usernamespace,
		},
	}

	_, err := clientset.CoreV1().Namespaces().Create(context.TODO(), ns, metav1.CreateOptions{})
	if err != nil {
		fmt.Println("ERROR:", err)
	}
}
func createServiceAccount(clientset *kubernetes.Clientset, usernamespace, name string) {
	servacc := &apiv1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ServiceAccount",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "egress-watcher-service-account",
			Namespace: usernamespace,
		},
	}

	serviceAccountOut, err := clientset.CoreV1().ServiceAccounts(usernamespace).Create(context.TODO(), servacc, metav1.CreateOptions{})

	//secretOut, err := kubeClient.clientset.CoreV1().Secrets(cr.Namespace).Create(secret)
	if err != nil {
		fmt.Println("ERROR:", err)
	}
	fmt.Printf("Created serviceaccount %v.\n", serviceAccountOut.GetObjectMeta().GetName())
}

func createClusterRole(clientset *kubernetes.Clientset, usernamespace, name string) {
	cr := &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ClusterRole",
			APIVersion: "rbac.authorization.k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "egress-watcher-role",
			Namespace: usernamespace,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{
					"networking.istio.io"},
				Resources: []string{"serviceentries"},
				Verbs: []string{
					"watch",
					"get",
					"list",
				},
			},
		},
	}

	clusterRoleOut, err := clientset.RbacV1().ClusterRoles().Create(context.TODO(), cr, metav1.CreateOptions{})

	if err != nil {
		fmt.Println("ERROR:", err)
	}
	fmt.Printf("Created clusterRole %v.\n", clusterRoleOut.GetObjectMeta().GetName())
}

func createClusterRoleBinding(clientset *kubernetes.Clientset, usernamespace, name string) {
	crb := &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ClusterRoleBinding",
			APIVersion: "rbac.authorization.k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "egress-watcher-role-binding",
			Namespace: usernamespace,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "egress-watcher-role",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "egress-watcher-service-account",
				Namespace: usernamespace,
			},
		},
	}

	clusterRoleBindingOut, err := clientset.RbacV1().ClusterRoleBindings().Create(context.TODO(), crb, metav1.CreateOptions{})

	if err != nil {
		fmt.Println("ERROR:", err)
	}
	fmt.Printf("Created clusterRoleBindingccount %v.\n", clusterRoleBindingOut.GetObjectMeta().GetName())

}

func createConfigMap(clientset *kubernetes.Clientset, usernamespace, name, usersettingsfilename, sdwan_url, sdwan_username, sdwan_pass string) {
	defWindow := 30 * time.Second
	opt := Options{
		ServiceEntryController: &controllers.ServiceEntryOptions{
			WatchAllServiceEntries: false,
		},

		Sdwan: &sdwan.Options{
			WaitingWindow: &defWindow,
			BaseURL:       sdwan_url,
			Authentication: &sdwan.Authentication{
				Username: sdwan_username,
				Password: sdwan_pass,
			},
		},
	}
	yaml_opt, _ := yaml.Marshal(opt)
	cm := apiv1.ConfigMap{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ConfigMap",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "egress-watcher-settings",
			Namespace: usernamespace,
		},

		Data: map[string]string{
			usersettingsfilename: string(yaml_opt),
		},
	}

	configOut, _ := clientset.CoreV1().ConfigMaps(usernamespace).Create(context.TODO(), &cm, metav1.CreateOptions{})
	fmt.Printf("Created configmap %v.\n", configOut.GetObjectMeta().GetName())
}

func createSecret(clientset *kubernetes.Clientset, usernamespace, name, sdwan_username, sdwan_pass string) {
	secr := &apiv1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "vmanage-credentials",
			Namespace: usernamespace,
		},
		Data: map[string][]byte{
			"username": []byte(sdwan_username),
			"password": []byte(sdwan_pass),
		},
		Type: "Opaque",
	}

	//clientset := clientset.Interface
	secretOut, err := clientset.CoreV1().Secrets(usernamespace).Create(context.TODO(), secr, metav1.CreateOptions{})

	//secretOut, err := kubeClient.clientset.CoreV1().Secrets(cr.Namespace).Create(secret)
	if err != nil {
		fmt.Println("ERROR:", err)
	}
	fmt.Printf("Created secret %v.\n", secretOut.GetObjectMeta().GetName())
}

func createDeployment(clientset *kubernetes.Clientset, sdwan_url string, usernamespace string, image string) {

	//deploymentsClient := clientset.AppsV1().Deployments(apiv1.NamespaceDefault)
	deploymentsClient := clientset.AppsV1().Deployments(usernamespace)

	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "egress-watcher",
			Namespace: "egress-watcher",
			Labels: map[string]string{
				"app": "egress-watcher"},
		},
		Spec: appsv1.DeploymentSpec{
			//Replicas: "2",
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": "egress-watcher",
				},
			},
			Template: apiv1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app": "egress-watcher",
					},
				},
				Spec: apiv1.PodSpec{
					Containers: []apiv1.Container{
						{
							Name:            "egress-watcher",
							Image:           image,
							ImagePullPolicy: "Always",
							Args: []string{
								"run",
								"with-vmanage",
								"--settings-file=/settings/settings.yaml",
								"--sdwan.username=$(SDWAN_USERNAME)",
								"--sdwan.password=$(SDWAN_PASSWORD)",
								"—verbosity=0",
							},
							VolumeMounts: []apiv1.VolumeMount{
								{
									Name:      "config-volume",
									MountPath: "/settings",
								},
							},
							Resources: apiv1.ResourceRequirements{
								Limits: apiv1.ResourceList{
									"cpu":    resource.MustParse("200m"),
									"memory": resource.MustParse("100Mi"),
								},

								Requests: apiv1.ResourceList{
									"cpu":    resource.MustParse("100m"),
									"memory": resource.MustParse("50Mi"),
								},
							},

							Env: []apiv1.EnvVar{{
								Name: "SDWAN_USERNAME",
								ValueFrom: &apiv1.EnvVarSource{
									SecretKeyRef: &apiv1.SecretKeySelector{
										LocalObjectReference: apiv1.LocalObjectReference{
											Name: "vmanage-credentials",
										},
										Key: "username",
									},
								}},

								{
									Name: "SDWAN_PASSWORD",
									ValueFrom: &apiv1.EnvVarSource{
										SecretKeyRef: &apiv1.SecretKeySelector{
											LocalObjectReference: apiv1.LocalObjectReference{
												Name: "vmanage-credentials",
											},
											Key: "password",
										},
									}},
							},
						}},

					Volumes: []apiv1.Volume{
						{Name: "config-volume",
							VolumeSource: apiv1.VolumeSource{
								ConfigMap: &apiv1.ConfigMapVolumeSource{
									LocalObjectReference: apiv1.LocalObjectReference{
										Name: "egress-watcher-settings"},
								},
							},
						},
					},
					ServiceAccountName: "egress-watcher-service-account",
				},
			},
		},
	}

	// Create Deployment
	fmt.Println("Creating deployment...")
	result, err := deploymentsClient.Create(context.TODO(), deployment, metav1.CreateOptions{})
	if err != nil {
		panic(err)
	}
	fmt.Printf("Created deployment %q.\n", result.GetObjectMeta().GetName())

}

// func main() {
// 	var kubeconfig *string
// 	if home := homedir.HomeDir(); home != "" {
// 		kubeconfig = flag.String("kubeconfig", filepath.Join(home, ".kube", "config"), "(optional) absolute path to the clientset file")
// 	} else {
// 		kubeconfig = flag.String("kubeconfig", "", "absolute path to the clientset file")
// 	}
// 	flag.Parse()

// 	// use the current context in clientset
// 	config, err := clientcmd.BuildConfigFromFlags("", *kubeconfig)
// 	if err != nil {
// 		panic(err.Error())
// 	}

// 	// create the clientset
// 	clientset, err := kubernetes.NewForConfig(config)
// 	if err != nil {
// 		return fmt.Errorf("canno")
// 	}

// 	//Take inputs from user
// 	fmt.Println("Hi user , please enter your sdwan username :")
// 	scanner := bufio.NewScanner(os.Stdin)
// 	scanner.Scan()
// 	err = scanner.Err()
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	sdwan_username := scanner.Text()
// 	//fmt.Printf("read line: %s-\n", sdwan_username)

// 	// enter password
// 	fmt.Println("Please enter your sdwan password :")
// 	scanner_pass := bufio.NewScanner(os.Stdin)
// 	scanner_pass.Scan()
// 	error := scanner_pass.Err()
// 	if error != nil {
// 		log.Fatal(error)
// 	}
// 	sdwan_pass := scanner_pass.Text()
// 	//fmt.Printf("read line: %s-\n", sdwan_pass)

// 	//enter base_url
// 	fmt.Println("Please enter your sdwan base_url :")
// 	scanner_url := bufio.NewScanner(os.Stdin)
// 	scanner_url.Scan()
// 	error_url := scanner_url.Err()
// 	if error_url != nil {
// 		log.Fatal(error_url)
// 	}
// 	sdwan_url := scanner_url.Text()
// 	fmt.Printf("read line: %s", sdwan_url)

// 	usernamespace := "egress-watcher"
// 	usersettingsfilename := "./settings.yaml"
// 	//nscreation := "kubectl create ns egress-watcher"
// 	out, err := exec.Command("kubectl", "create", "ns", "egress-watcher").Output()

// 	if err != nil {
// 		fmt.Printf("%s, %s", err, out)
// 	}
// 	fmt.Println("Command Successfully Executed")

// 	//template_yaml(clientset, "new-deployment", usernamespace)
// 	//CreateDeployment(clientset, "new-deployment", usernamespace)
// 	CreateSecret(clientset, usernamespace, "vmanage-credentials", sdwan_username, sdwan_pass)
// 	CreateConfigMap(clientset, usernamespace, "egress-watcher-settings", usersettingsfilename, sdwan_url, sdwan_username, sdwan_pass)
// 	CreateServiceAccount(clientset, usernamespace, "egress-watcher-service-account")
// 	CreateClusterRole(clientset, usernamespace, "egress-watcher-role")
// 	CreateClusterRoleBinding(clientset, usernamespace, "egress-watcher-role-binding")
// 	CreateDeployment(clientset, "new-deployment", usernamespace)

// 	/*sleepcmd := "sleep 2"
// 	out1, err1 := exec.Command("sleep","2").Output()

// 	if err1 != nil {
// 		fmt.Printf("%s, %s", err1, out1)
// 	}
// 	fmt.Println("Command Successfully Executed")

// 	setimage := "kubectl set image deployment/egress-watcher egress-watcher=" + "os.ExpandEnv('$IMAGE') -n egress-watcher"
// 	cmd3 := strings.Split(setimage, "")
// 	execute(cmd3)

// 	setpodname := "export POD_NAME=$(kubectl get pods --template '{{range .items}}{{.metadata.name}}{{\"\n\"}}{{end}}' -n egress-watcher | grep egress-watcher)"
// 	fmt.Println(setpodname)
// 	*/

// }
