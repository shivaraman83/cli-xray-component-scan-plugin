package commands

import (
	"errors"
	"github.com/jfrog/jfrog-cli-core/plugins/components"
	"github.com/jfrog/jfrog-cli-core/utils/config"
	"github.com/jfrog/jfrog-client-go/artifactory/services/utils"
	"github.com/jfrog/jfrog-client-go/httpclient"
	clientutils "github.com/jfrog/jfrog-client-go/utils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"strconv"
	"strings"
)

func ScanPackages() components.Command {
	return components.Command{
		Name:        "scan",
		Description: "Scans components using Xray",
		//Aliases:     []string{"hi"},
		Arguments: getScanArguments(),
		//Flags:       ""getHelloFlags""(),
		//EnvVars:     getHelloEnvVar(),
		Action: func(c *components.Context) error {
			return scanCmd(c)
		},
	}
}

func getScanArguments() []components.Argument {
	return []components.Argument{
		{
			Name:        "Component Name",
			Description: "The name of the component for which you need licensing and vulnerability information",
		},
	}
}

type scanConfiguration struct {
	componentId string
}

func scanCmd(c *components.Context) error {
	if len(c.Arguments) != 1 {
		return errors.New("Wrong number of arguments. Expected: 1, " + "Received: " + strconv.Itoa(len(c.Arguments)))
	}
	var conf = new(scanConfiguration)
	conf.componentId = c.Arguments[0]

	artDetails, err := config.GetArtifactorySpecificConfig("", true, true)
	if err != nil {
		return err
	}

	artAuth, err := artDetails.CreateArtAuthConfig()

	//log.Output(artAuth)
	//rtDetails, err :=config.NewConfigBuilder().SetServiceDetails(ddtails).SetCertificatesPath(ddtails.GetClientCertPath()).Build()

	url, err := utils.BuildArtifactoryUrl(strings.ReplaceAll(artAuth.GetUrl(), "/artifactory/", "/xray/"),
		"api/v1/summary/component", nil)
	if err != nil {
		return err
	}
	httpClientDetails := artAuth.CreateHttpClientDetails()

	client, err := httpclient.ClientBuilder().Build()
	if err != nil {
		return err
	}
	httpClientDetails.Headers = map[string]string{
		"Content-Type": "application/json",
	}

	_, body, err := client.SendPost(url, []byte("{\"component_details\":[{\"component_id\":\""+conf.componentId+"\"}]}"), httpClientDetails)

	if err != nil {
		return err
	}
	log.Output(clientutils.IndentJson(body))
	return nil
}
