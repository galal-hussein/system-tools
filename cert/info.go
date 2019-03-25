package cert

import (
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/rancher/rke/cluster"
	"github.com/rancher/rke/hosts"
	"github.com/rancher/rke/k8s"
	"github.com/rancher/rke/pki"
	"github.com/rancher/system-tools/clients"
	"github.com/rancher/types/apis/management.cattle.io/v3"
	"github.com/rancher/types/config"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/cert"
)

const (
	NamespaceCattleSystem  = "cattle-system"
	KubeConfigTempPath     = "./cluster_kubeconfig.yml"
	FullStateConfigMapName = "full-cluster-state"
)

var InfoFlags = []cli.Flag{
	cli.StringFlag{
		Name:   "kubeconfig,c",
		EnvVar: "KUBECONFIG",
		Usage:  "management cluster kubeconfig",
	},
	cli.StringFlag{
		Name:  "cluster",
		Usage: "downstream cluster name",
	},
}

func DoInfo(ctx *cli.Context) error {
	clusterName := ctx.String("cluster")
	logrus.Infof("Check certificates Info for cluster [%s]", clusterName)
	restConfig, err := clients.GetRestConfig(ctx)
	if err != nil {
		return err
	}
	k8sClient, err := clients.GetClientSet(ctx)
	if err != nil {
		return err
	}
	management, err := config.NewManagementContext(*restConfig)
	if err != nil {
		return err
	}
	// Get Cluster by name
	cluster, err := management.Management.Clusters(clusterName).Get(clusterName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	logrus.Infof("Get kubeconfig for cluster [%s]", clusterName)
	// Get Cluster config
	rkeConfig := cluster.Spec.RancherKubernetesEngineConfig
	if rkeConfig == nil {
		return fmt.Errorf("The cluster [%s] isn't a RKE cluster", cluster.Name)
	}

	// Get Cluster Nodes
	nodes := []v3.RKEConfigNode{}
	nodesList, err := management.Management.Nodes(clusterName).List(metav1.ListOptions{})
	for _, item := range nodesList.Items {
		nodes = append(nodes, *item.Status.NodeConfig)
	}
	rkeConfig.Nodes = nodes

	clusterKubeConfig, err := getClusterKubeConfig(k8sClient, clusterName)
	if err != nil {
		return err
	}
	logrus.Infof("Write temporary kubeconfig for cluster [%s]", clusterName)
	if err := writeTempConfig(clusterKubeConfig, clusterName); err != nil {
		return err
	}

	downstreamClient, err := clients.GetCustomClientSet(KubeConfigTempPath)
	if err != nil {
		return err
	}
	clusterState, err := getClusterState(downstreamClient)
	if err != nil {
		return err
	}
	showClusterCertificates(clusterState)
	return nil
}

func getClusterKubeConfig(k8sClient *kubernetes.Clientset, clusterName string) (string, error) {
	// get KubeConfig
	secretName := "c-" + clusterName
	clusterSecret, err := k8sClient.CoreV1().Secrets(NamespaceCattleSystem).Get(secretName, metav1.GetOptions{})
	if err != nil {
		return "", err
	}
	var jsonConfig map[string]interface{}
	err = json.Unmarshal(clusterSecret.Data["cluster"], &jsonConfig)
	if err != nil {
		return "", err
	}
	metadata := jsonConfig["metadata"].(map[string]interface{})
	return metadata["state"].(string), nil
}

func writeTempConfig(kubeconfig, clusterName string) error {
	logrus.Debugf("Writing temporary kubeconfig file for cluster [%s]", clusterName)
	if err := ioutil.WriteFile(KubeConfigTempPath, []byte(kubeconfig), 0640); err != nil {
		return fmt.Errorf("Failed to wrute temporary kubeconfig file cluster [%s]: %v", clusterName, err)
	}
	logrus.Infof("Successfully wrote temporary kubeconfig file for cluster [%s] at [%s]", clusterName, KubeConfigTempPath)
	return nil
}

func getClusterState(k8sClient *kubernetes.Clientset) (*cluster.FullState, error) {
	fullStateConfigMap, err := k8s.GetConfigMap(k8sClient, FullStateConfigMapName)
	if err != nil {
		return nil, err
	}
	fullState := cluster.FullState{}
	fullStateDate := fullStateConfigMap.Data[FullStateConfigMapName]
	err = json.Unmarshal([]byte(fullStateDate), &fullState)
	if err != nil {
		return nil, fmt.Errorf("Failed to unmarshal cluster state")
	}
	return &fullState, nil
}

func showClusterCertificates(clusterState *cluster.FullState) error {
	componentsCerts := []string{
		pki.KubeAPICertName,
		pki.KubeControllerCertName,
		pki.KubeSchedulerCertName,
		pki.KubeProxyCertName,
		pki.KubeNodeCertName,
		pki.KubeAdminCertName,
		pki.RequestHeaderCACertName,
		pki.APIProxyClientCertName,
	}
	etcdHosts := hosts.NodesToHosts(clusterState.CurrentState.RancherKubernetesEngineConfig.Nodes, "etcd")
	for _, host := range etcdHosts {
		etcdName := pki.GetEtcdCrtName(host.InternalAddress)
		componentsCerts = append(componentsCerts, etcdName)
	}
	for _, component := range componentsCerts {
		componentCert := clusterState.CurrentState.CertificatesBundle[component]
		if componentCert.CertificatePEM != "" {
			certificates, err := cert.ParseCertsPEM([]byte(componentCert.CertificatePEM))
			if err != nil {
				return fmt.Errorf("failed to read certificate [%s]: %v", component, err)
			}
			certificate := certificates[0]
			logrus.Infof("Certificate [%s] has expiration date: [%v]", component, certificate.NotAfter)
		}
	}
	return nil
}
