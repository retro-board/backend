package kube

import (
	"context"
	"flag"
	"fmt"
	"path/filepath"

	bugLog "github.com/bugfixes/go-bugfixes/logs"
	v1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

type Kube struct {
	CTX         context.Context
	Development bool

	Subdomain string
	Domain    string

	ClusterIssuer string
	Namespace     string
}

func NewKube(ctx context.Context, development bool, subdomain, domain, clusterIssuer, namespace string) *Kube {
	return &Kube{
		CTX:         ctx,
		Development: development,

		Subdomain: subdomain,
		Domain:    domain,

		ClusterIssuer: clusterIssuer,
		Namespace:     namespace,
	}
}

func (k *Kube) getConfig() (*rest.Config, error) {
	if !k.Development {
		return rest.InClusterConfig()
	}

	kubeconfig := flag.String("kubeconfig", filepath.Join(homedir.HomeDir(), ".kube", "config"), "absolute path")
	flag.Parse()
	return clientcmd.BuildConfigFromFlags("", *kubeconfig)
}

func (k *Kube) CreateSubdomain() error {
	config, err := k.getConfig()
	if err != nil {
		return bugLog.Error(err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return bugLog.Error(err)
	}

	ingressClassName := "nginx"
	pathType := v1.PathTypePrefix

	ingConfig := v1.Ingress{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Ingress",
			APIVersion: "networking.k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-ingress", k.Subdomain),
			Namespace: k.Namespace,
			Annotations: map[string]string{
				"cert-manager.io/cluster-issuer":             k.ClusterIssuer,
				"nginx.ingress.kubernetes.io/rewrite-target": "/",
			},
			Labels: map[string]string{
				"app": "frontend",
			},
		},
		Spec: v1.IngressSpec{
			IngressClassName: &ingressClassName,
			TLS: []v1.IngressTLS{
				{
					Hosts: []string{
						fmt.Sprintf("%s.%s", k.Subdomain, k.Domain),
					},
					SecretName: fmt.Sprintf("%s-%s-tls", k.Subdomain, k.Domain),
				},
			},
			Rules: []v1.IngressRule{
				{
					Host: fmt.Sprintf("%s.%s", k.Subdomain, k.Domain),
					IngressRuleValue: v1.IngressRuleValue{
						HTTP: &v1.HTTPIngressRuleValue{
							Paths: []v1.HTTPIngressPath{
								{
									Path:     "/",
									PathType: &pathType,
									Backend: v1.IngressBackend{
										Service: &v1.IngressServiceBackend{
											Name: "frontend",
											Port: v1.ServiceBackendPort{
												Number: 80,
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	_, err = clientset.NetworkingV1().Ingresses(k.Namespace).Create(k.CTX, &ingConfig, metav1.CreateOptions{})
	if err != nil {
		return bugLog.Error(err)
	}

	return nil
}
