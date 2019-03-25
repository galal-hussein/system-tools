package cert

import (
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/rancher/rke/cluster"
	"github.com/rancher/rke/k8s"
	"github.com/rancher/system-tools/clients"
	"github.com/rancher/types/apis/management.cattle.io/v3"
	"github.com/rancher/types/config"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	yaml "gopkg.in/yaml.v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
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
	if err := writeTempConfig(clusterKubeConfig, clusterName); err != nil {
		return err
	}

	downstreamClient, err := clients.GetCustomClientSet(KubeConfigTempPath)
	if err != nil {
		return err
	}
	clusterState, err := getClusterState(downstreamClient)
	fmt.Println(clusterState)
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
		return fmt.Errorf("Failed temporary kubeconfig file cluster [%s]: %v", clusterName, err)
	}
	logrus.Infof("Successfully temporary kubeconfig file for cluster [%s] at [%s]", clusterName, KubeConfigTempPath)
	return nil
}

func getClusterState(k8sClient *kubernetes.Clientset) (*cluster.FullState, error) {
	fullStateConfigMap, err := k8s.GetConfigMap(k8sClient, FullStateConfigMapName)
	if err != nil {
		return nil, err
	}
	fullState := &cluster.FullState{}
	fullStateDate := fullStateConfigMap.Data[FullStateConfigMapName]
	err = yaml.Unmarshal([]byte(fullStateDate), &fullState)
	if err != nil {
		return nil, fmt.Errorf("Failed to unmarshal cluster state")
	}
	return fullState, nil
}
