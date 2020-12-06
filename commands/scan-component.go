package commands

import (
	"encoding/json"
	"errors"
	"github.com/jfrog/jfrog-cli-core/plugins/components"
	"github.com/jfrog/jfrog-cli-plugin-template/scanUtils"
	"github.com/jfrog/jfrog-client-go/httpclient"
	//"github.com/kr/pretty"
	"strconv"
	//"time"
)

func ScanComponent() components.Command {
	return components.Command{
		Name:        "scan-component",
		Description: "Scans components using Xray",
		Aliases:     []string{"s"},
		Arguments:   getScanArguments(),
		Flags:       getScanFlags(),
		//EnvVars:     getHelloEnvVar(),
		Action: func(c *components.Context) error {
			return scanCmd(c)
		},
	}
}

func getScanFlags() []components.Flag {
	return []components.Flag{
		components.StringFlag{
			Name: "v",
			Description: "\"high\" If you need only high vulnernability information " +
				"\"all\" for all the vulnerability information",
		},
		components.StringFlag{
			Name:        "l",
			Description: "To fetch all the license information ",
		},
	}

}

type scanConfiguration struct {
	componentId string
	vulnFlag    string
	licenseFlag string
	cacheRepo   string
}

func getScanArguments() []components.Argument {
	return []components.Argument{
		{
			Name:        "Component Name",
			Description: "Name of the component which Xray has to scan",
		},
	}
}

//https://mholt.github.io/json-to-go/
//https://play.golang.org/p/Z3yszFl01L
//https://www.jfrog.com/confluence/display/JFROG/Xray+REST+API
//https://tutorialedge.net/golang/parsing-json-with-golang/

//./cli-xray-component-scan-plugin scan "deb://debian:buster:curl:7.64.0-4"
//./cli-xray-component-scan-plugin scan "npm://debug:2.2.0"

func scanCmd(c *components.Context) error {

	if len(c.Arguments) != 1 {
		return errors.New("Wrong number of arguments. Expected: 1, " + "Received: " + strconv.Itoa(len(c.Arguments)))
	}

	var conf = new(scanUtils.ScanConfiguration)
	conf.ComponentId = c.Arguments[0]
	conf.VulnFlag = c.GetStringFlagValue("v")
	conf.LicenseFlag = c.GetStringFlagValue("l")

	rtDetails, err := scanUtils.GetRtDetails(c)
	url := scanUtils.GetXrayRestAPIUrl(err, rtDetails)
	artAuth, err := rtDetails.CreateArtAuthConfig()
	client, err := httpclient.ClientBuilder().Build()
	if err != nil {
		return err
	}
	httpClientDetails := artAuth.CreateHttpClientDetails()
	httpClientDetails.Headers = map[string]string{
		"Content-Type": "application/json",
	}
	var payload = "{\"component_details\":[{\"component_id\":\"" + conf.ComponentId + "\"}]}"

	_, body, err := client.SendPost(url, []byte(payload), httpClientDetails)

	var scanData scanUtils.ScanOutput
	err = json.Unmarshal(body, &scanData)

	if err != nil {
		return err
	}

	err = scanUtils.PrintOutput(conf, scanData, err)
	if err != nil {
		return err
	}
	return nil

}

//scanGitRepo http://github.com/cockroachdb/cockroach “/Users/shimi/go-cache”
