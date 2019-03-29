package cert

import (
	"context"
	"fmt"

	rkecluster "github.com/rancher/rke/cluster"
	"github.com/rancher/rke/cmd"
	"github.com/rancher/rke/hosts"
	"github.com/rancher/rke/pki"
	"github.com/rancher/system-tools/clients"
	"github.com/rancher/types/apis/management.cattle.io/v3"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

const (
	NamespaceCattleSystem  = "cattle-system"
	KubeConfigTempPath     = "./cluster_kubeconfig.yml"
	FullStateConfigMapName = "full-cluster-state"
)

var CertFlags = []cli.Flag{
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
	k8sClient, err := clients.GetClientSet(ctx)
	if err != nil {
		return err
	}

	rkeConfig, err := setupRancherKubernetesEngineConfig(ctx, clusterName)
	if err != nil {
		return err
	}

	clusterKubeConfig, err := getClusterKubeConfig(k8sClient, clusterName)
	if err != nil {
		return err
	}

	if err := writeTempConfig(clusterKubeConfig, clusterName); err != nil {
		return err
	}
	downstreamClient, err := clients.GetCustomClientSet(pki.GetLocalKubeConfig(clusterName, ""))
	if err != nil {
		return err
	}

	return showClusterCertificates(downstreamClient, clusterName, rkeConfig)
}

func DoRotate(ctx *cli.Context) error {
	clusterName := ctx.String("cluster")

	k8sClient, err := clients.GetClientSet(ctx)
	if err != nil {
		return err
	}

	rkeConfig, err := setupRancherKubernetesEngineConfig(ctx, clusterName)
	if err != nil {
		return err
	}

	clusterKubeConfig, err := getClusterKubeConfig(k8sClient, clusterName)
	if err != nil {
		return err
	}

	if err := writeTempConfig(clusterKubeConfig, clusterName); err != nil {
		return err
	}

	downstreamClient, err := clients.GetCustomClientSet(pki.GetLocalKubeConfig(clusterName, ""))
	if err != nil {
		return err
	}

	if fullState, err := getClusterState(downstreamClient, clusterName); err == nil {
		fmt.Println(fullState)
		fmt.Println(err)
		logrus.Infof("Cluster [%s] is not a legacy cluster, please use rotate certificate from Rancher UI", clusterName)
		return nil
	}

	externalFlags := rkecluster.GetExternalFlags(false, false, false, "", clusterName)
	externalFlags.Legacy = true
	rkeConfig.RotateCertificates = &v3.RotateCertificates{}
	if err := cmd.ClusterInit(context.Background(), rkeConfig, hosts.DialersOptions{}, externalFlags); err != nil {
		return err
	}
	_, _, clientCert, clientKey, newCerts, err := cmd.ClusterUp(context.Background(), hosts.DialersOptions{}, externalFlags)

	if err := saveClusterCertsToKubernetes(context.Background(), downstreamClient, newCerts); err != nil {
		return err
	}

	return updateClusterObjectInRancher(k8sClient, clusterName, clientCert, clientKey, newCerts)
}
