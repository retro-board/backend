package kube

import (
	"context"
	"fmt"

	bugLog "github.com/bugfixes/go-bugfixes/logs"
	v1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type Kube struct {
	CTX context.Context

	Subdomain string
	Domain    string

	ClusterIssuer string
	Namespace     string
}

func NewKube(ctx context.Context, subdomain, domain, clusterIssuer, namespace string) *Kube {
	return &Kube{
		CTX: ctx,

		Subdomain: subdomain,
		Domain:    domain,

		ClusterIssuer: clusterIssuer,
		Namespace:     namespace,
	}
}

func (k *Kube) CreateSubdomain() error {
	config, err := rest.InClusterConfig()
	if err != nil {
		return bugLog.Error(err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return bugLog.Error(err)
	}

	ingressClassName := "nginx"
	pathType := v1.PathTypePrefix

	ing, err := clientset.NetworkingV1().Ingresses(k.Subdomain).Create(k.CTX, &v1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-ingress", k.Subdomain),
			Namespace: k.Namespace,
			Annotations: map[string]string{
				"cert-manager.io/cluster-issuer":             k.ClusterIssuer,
				"nginx.ingress.kubernetes.io/rewrite-target": "/",
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
					Host: k.Subdomain,
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
	}, metav1.CreateOptions{})
	if err != nil {
		return bugLog.Error(err)
	}

	if ing.Status.LoadBalancer.Ingress == nil {
		return bugLog.Error(fmt.Errorf("no ingress"))
	}

	return nil
}
