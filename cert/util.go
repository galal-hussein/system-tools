package cert

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/rancher/kontainer-engine/drivers/rke/rkecerts"
	"github.com/rancher/kontainer-engine/types"
	rkecluster "github.com/rancher/rke/cluster"
	"github.com/rancher/rke/hosts"
	"github.com/rancher/rke/k8s"
	"github.com/rancher/rke/log"
	"github.com/rancher/rke/pki"
	"github.com/rancher/system-tools/clients"
	"github.com/rancher/types/apis/management.cattle.io/v3"
	"github.com/rancher/types/config"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	"golang.org/x/sync/errgroup"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/cert"
)

func updateClusterObjectInRancher(k8sClient *kubernetes.Clientset, clusterName, clientCert, clientKey string, certs map[string]pki.CertificatePKI) error {
	secretName := "c-" + clusterName
	logrus.Infof("Update cluster secret object [%s] in Rancher environment", secretName)

	clusterSecret, err := k8sClient.CoreV1().Secrets(NamespaceCattleSystem).Get(secretName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	var clusterInfo types.ClusterInfo
	err = json.Unmarshal(clusterSecret.Data["cluster"], &clusterInfo)
	if err != nil {
		return err
	}

	certsStr, err := rkecerts.ToString(certs)
	if err != nil {
		return err
	}
	clusterInfo.Metadata["clientCert"] = base64.StdEncoding.EncodeToString([]byte(clientCert))
	clusterInfo.Metadata["clientKey"] = base64.StdEncoding.EncodeToString([]byte(clientKey))
	clusterInfo.Metadata["Certs"] = certsStr

	clusterData, err := json.Marshal(clusterInfo)
	if err != nil {
		return err
	}
	clusterSecret.Data["cluster"] = clusterData
	return k8s.UpdateSecret(k8sClient, clusterSecret.Data, secretName)
}

func getClusterKubeConfig(k8sClient *kubernetes.Clientset, clusterName string) (string, error) {
	logrus.Infof("Get kubeconfig for cluster [%s]", clusterName)
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

func getClusterState(k8sClient *kubernetes.Clientset, clusterName string) (*rkecluster.FullState, error) {
	logrus.Infof("Fetching cluster [%s] full state from kubernetes", clusterName)
	fullStateConfigMap, err := k8s.GetConfigMap(k8sClient, FullStateConfigMapName)
	if err != nil {
		return nil, err
	}
	fullState := rkecluster.FullState{}
	fullStateDate := fullStateConfigMap.Data[FullStateConfigMapName]
	err = json.Unmarshal([]byte(fullStateDate), &fullState)
	if err != nil {
		return nil, fmt.Errorf("Failed to unmarshal cluster state")
	}
	return &fullState, nil
}

func writeTempConfig(kubeconfig, clusterName string) error {
	logrus.Infof("Write temporary kubeconfig for cluster [%s]", clusterName)
	kubeConfigPath := pki.GetLocalKubeConfig(clusterName, "")
	if err := ioutil.WriteFile(kubeConfigPath, []byte(kubeconfig), 0640); err != nil {
		return fmt.Errorf("Failed to wrute temporary kubeconfig file cluster [%s]: %v", kubeConfigPath, err)
	}
	logrus.Infof("Successfully wrote temporary kubeconfig file for cluster [%s] at [%s]", clusterName, kubeConfigPath)
	return nil
}

func showClusterCertificates(k8sClient *kubernetes.Clientset, clusterName string, rkeconfig *v3.RancherKubernetesEngineConfig) error {
	var certMap map[string]pki.CertificatePKI
	var nodes []v3.RKEConfigNode

	clusterFullState, err := getClusterState(k8sClient, clusterName)
	if err == nil {
		certMap = clusterFullState.CurrentState.CertificatesBundle
		nodes = clusterFullState.CurrentState.RancherKubernetesEngineConfig.Nodes
	} else {
		logrus.Infof("possible legacy cluster, trying to fetch certs from kubernetes")
		externalFlags := rkecluster.GetExternalFlags(false, false, false, "", clusterName)
		rkeClusterObj, err := rkecluster.InitClusterObject(context.Background(), rkeconfig, externalFlags)
		if err != nil {
			return err
		}
		certMap, err = rkecluster.GetClusterCertsFromKubernetes(context.Background(), rkeClusterObj)
		if err != nil {
			return err
		}
		nodes = rkeconfig.Nodes
	}

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
	etcdHosts := hosts.NodesToHosts(nodes, "etcd")
	for _, host := range etcdHosts {
		etcdName := pki.GetEtcdCrtName(host.InternalAddress)
		componentsCerts = append(componentsCerts, etcdName)
	}
	for _, component := range componentsCerts {
		componentCert := certMap[component]
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

func saveClusterCertsToKubernetes(ctx context.Context, kubeClient *kubernetes.Clientset, crts map[string]pki.CertificatePKI) error {
	log.Infof(ctx, "[certificates] Save kubernetes certificates as secrets")
	var errgrp errgroup.Group
	for crtName, crt := range crts {
		name := crtName
		certificate := crt
		errgrp.Go(func() error {
			return saveCertAsSecret(kubeClient, name, certificate)
		})
	}
	if err := errgrp.Wait(); err != nil {
		return err

	}
	log.Infof(ctx, "[certificates] Successfully saved certificates as kubernetes secret [%s]", pki.CertificatesSecretName)
	return nil
}

func saveCertAsSecret(kubeClient *kubernetes.Clientset, crtName string, crt pki.CertificatePKI) error {
	logrus.Debugf("[certificates] Saving certificate [%s] to kubernetes", crtName)
	timeout := make(chan bool, 1)

	// build secret Data
	secretData := make(map[string][]byte)
	if crt.Certificate != nil {
		secretData["Certificate"] = cert.EncodeCertPEM(crt.Certificate)
		secretData["EnvName"] = []byte(crt.EnvName)
		secretData["Path"] = []byte(crt.Path)
	}
	if crt.Key != nil {
		secretData["Key"] = cert.EncodePrivateKeyPEM(crt.Key)
		secretData["KeyEnvName"] = []byte(crt.KeyEnvName)
		secretData["KeyPath"] = []byte(crt.KeyPath)
	}
	if len(crt.Config) > 0 {
		secretData["ConfigEnvName"] = []byte(crt.ConfigEnvName)
		secretData["Config"] = []byte(crt.Config)
		secretData["ConfigPath"] = []byte(crt.ConfigPath)
	}
	go func() {
		for {
			err := k8s.UpdateSecret(kubeClient, secretData, crtName)
			if err != nil {
				time.Sleep(time.Second * 5)
				continue
			}
			timeout <- true
			break
		}
	}()
	select {
	case <-timeout:
		return nil
	case <-time.After(time.Second * 5):
		return fmt.Errorf("[certificates] Timeout waiting for kubernetes to be ready")
	}
}

func setupRancherKubernetesEngineConfig(ctx *cli.Context, clusterName string) (*v3.RancherKubernetesEngineConfig, error) {
	logrus.Infof("Setup rkeconfig for cluster [%s]", clusterName)
	restConfig, err := clients.GetRestConfig(ctx)
	if err != nil {
		return nil, err
	}
	management, err := config.NewManagementContext(*restConfig)
	if err != nil {
		return nil, err
	}
	// Get Cluster by name
	cluster, err := management.Management.Clusters(clusterName).Get(clusterName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	// Get Cluster config
	rkeConfig := cluster.Spec.RancherKubernetesEngineConfig
	if rkeConfig == nil {
		return nil, fmt.Errorf("The cluster [%s] isn't a RKE cluster", cluster.Name)
	}

	// Get Cluster Nodes
	nodes := []v3.RKEConfigNode{}
	nodesList, err := management.Management.Nodes(clusterName).List(metav1.ListOptions{})
	for _, item := range nodesList.Items {
		nodes = append(nodes, *item.Status.NodeConfig)
	}
	rkeConfig.Nodes = nodes

	return rkeConfig, nil
}
