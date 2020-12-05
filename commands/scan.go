package commands

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jfrog/jfrog-cli-core/artifactory/commands"
	"github.com/jfrog/jfrog-cli-core/plugins/components"
	"github.com/jfrog/jfrog-cli-core/utils/config"
	"github.com/jfrog/jfrog-client-go/artifactory/services/utils"
	"github.com/jfrog/jfrog-client-go/httpclient"
	clientutils "github.com/jfrog/jfrog-client-go/utils"
	"io/ioutil"
	"os/exec"
	//"github.com/kr/pretty"
	//"github.com/jfrog/jfrog-client-go/utils/log"
	"strconv"
	"strings"
	//"time"
)

const ServerIdFlag = "server-id"

func ScanComponent() components.Command {
	return components.Command{
		Name:        "scan",
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

func ScanPackages() components.Command {
	//var compNames = []string{"deb://debian:buster:curl:7.64.0-4", "npm://debug:2.2.0", "go://github.com/ulikunitz/xz:0.5.6"}
	return components.Command{
		Name:        "scanPackages",
		Description: "Scans a list of Packages/Components using Xray",
		//Aliases:     []string{"hi"},
		Arguments: getScanArguments(),
		Flags:     getScanFlags(),
		//EnvVars:     getHelloEnvVar(),
		Action: func(c *components.Context) error {
			return scanPackageList(c)
		},
	}
}

func ScanGitRepo() components.Command {
	return components.Command{
		Name:        "scanGitRepo",
		Description: "Scans components using Xray",
		//Aliases:     []string{"hi"},
		Arguments: getScanArguments(),
		//Flags:       ""getHelloFlags""(),
		//EnvVars:     getHelloEnvVar(),
		Action: func(c *components.Context) error {
			return scanGit(c)
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

type scanOutput struct {
	Artifacts []struct {
		General struct {
			Name        string `json:"name"`
			PkgType     string `json:"pkg_type"`
			ComponentID string `json:"component_id"`
		} `json:"general"`
		Issues []struct {
			Summary     string `json:"summary"`
			Description string `json:"description"`
			IssueType   string `json:"issue_type"`
			Severity    string `json:"severity"`
			Provider    string `json:"provider"`
			Cves        []struct {
				Cve    string `json:"cve"`
				CvssV2 string `json:"cvss_v2"`
			} `json:"cves"`
			Created    string `json:"created"`
			Components []struct {
				ComponentID   string   `json:"component_id"`
				FixedVersions []string `json:"fixed_versions"`
			} `json:"components"`
		} `json:"issues"`
		Licenses []struct {
			Name        string   `json:"name"`
			FullName    string   `json:"full_name"`
			MoreInfoURL []string `json:"more_info_url"`
			Components  []string `json:"components"`
		} `json:"licenses"`
	} `json:"artifacts"`
}

func scanPackageList(c *components.Context) error {

	if len(c.Arguments) == 0 {
		return errors.New("Wrong number of arguments. Expected: String array, " + "Received: " + strconv.Itoa(len(c.Arguments)))
	}

	compNames := c.Arguments

	return scanPackages(compNames, c)
}

func scanPackages(compNames []string, c *components.Context) error {
	var sb strings.Builder
	var payload strings.Builder
	for _, element := range compNames {
		sb.WriteString("{\"component_id\":\"" + element + "\"},")
	}

	var conf = new(scanConfiguration)
	conf.componentId = c.Arguments[0]
	conf.vulnFlag = c.GetStringFlagValue("v")
	conf.licenseFlag = c.GetStringFlagValue("l")

	fmt.Println("LicenseFlag " + conf.licenseFlag)
	fmt.Println("VulnFlag " + conf.vulnFlag)

	var payloadComp = strings.TrimSuffix(sb.String(), ",")
	payload.WriteString("{\"component_details\":[" + payloadComp + "]}")

	fmt.Println("Payload::::", payload.String())

	rtDetails, err := GetRtDetails(c)
	url := getXrayRestAPIUrl(err, rtDetails)
	artAuth, err := rtDetails.CreateArtAuthConfig()
	client, err := httpclient.ClientBuilder().Build()
	if err != nil {
		return err
	}
	httpClientDetails := artAuth.CreateHttpClientDetails()
	httpClientDetails.Headers = map[string]string{
		"Content-Type": "application/json",
	}

	_, body, err := client.SendPost(url, []byte(payload.String()), httpClientDetails)

	var scanData scanOutput
	err = json.Unmarshal(body, &scanData)

	data := clientutils.IndentJson(body)
	scanOutputJSON := make(map[string][]scanOutput)
	err = json.Unmarshal([]byte(data), &scanOutputJSON)

	//log.Output(clientutils.IndentJson(body))
	if err != nil {
		return err
	}
	if conf.licenseFlag == "" && conf.vulnFlag == "" {
		for i := range scanData.Artifacts {
			err := printGeneral(scanData, i)
			err = printIssues(scanData, i)
			err = printLicenses(scanData, i)
			if err != nil {
				return err
			}
		}
	}

	if conf.vulnFlag == "all" {
		for i := range scanData.Artifacts {
			err = printIssues(scanData, i)
			if err != nil {
				return err
			}
		}
	}

	if conf.vulnFlag == "high" {
		for i := range scanData.Artifacts {
			iss := scanData.Artifacts[i].Issues
			for j := range iss {
				if iss[j].Severity == "High" {
					issue, err := json.MarshalIndent(iss[j], "", " ")
					fmt.Println("Issue:::: " + string(issue))
					if err != nil {
						return err
					}
				}
			}

		}
	}

	if conf.licenseFlag == "all" {
		for i := range scanData.Artifacts {
			err = printLicenses(scanData, i)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func scanCmd(c *components.Context) error {

	if len(c.Arguments) != 1 {
		return errors.New("Wrong number of arguments. Expected: 1, " + "Received: " + strconv.Itoa(len(c.Arguments)))
	}

	var conf = new(scanConfiguration)
	conf.componentId = c.Arguments[0]
	conf.vulnFlag = c.GetStringFlagValue("v")
	conf.licenseFlag = c.GetStringFlagValue("l")

	rtDetails, err := GetRtDetails(c)
	url := getXrayRestAPIUrl(err, rtDetails)
	artAuth, err := rtDetails.CreateArtAuthConfig()
	client, err := httpclient.ClientBuilder().Build()
	if err != nil {
		return err
	}
	httpClientDetails := artAuth.CreateHttpClientDetails()
	httpClientDetails.Headers = map[string]string{
		"Content-Type": "application/json",
	}
	var payload = "{\"component_details\":[{\"component_id\":\"" + conf.componentId + "\"}]}"

	_, body, err := client.SendPost(url, []byte(payload), httpClientDetails)

	var scanData scanOutput
	err = json.Unmarshal(body, &scanData)

	if err != nil {
		return err
	}

	if conf.vulnFlag == "all" {
		for i := range scanData.Artifacts {
			err = printIssues(scanData, i)
			if err != nil {
				return err
			}
		}
	}

	if conf.vulnFlag == "high" {
		for i := range scanData.Artifacts {
			iss := scanData.Artifacts[i].Issues
			for j := range iss {
				if iss[j].Severity == "High" {
					issue, err := json.MarshalIndent(iss[j], "", " ")
					fmt.Println("Issue:::: " + string(issue))
					if err != nil {
						return err
					}
				}
			}

		}
	}

	if conf.licenseFlag == "all" {
		for i := range scanData.Artifacts {
			err = printLicenses(scanData, i)
			if err != nil {
				return err
			}
		}
	}

	if conf.licenseFlag == "" && conf.vulnFlag == "" {
		for i := range scanData.Artifacts {
			err := printGeneral(scanData, i)
			err = printIssues(scanData, i)
			err = printLicenses(scanData, i)
			if err != nil {
				return err
			}
		}
	}
	return nil

}

func printGeneral(scanData scanOutput, i int) error {
	general, err := json.MarshalIndent(scanData.Artifacts[i].General, "", " ")
	fmt.Println("General:::: " + string(general))
	if err != nil {
		return err
	}
	return nil
}

func printIssues(scanData scanOutput, i int) error {
	issues, err := json.MarshalIndent(scanData.Artifacts[i].Issues, "", " ")
	fmt.Println("Issues:::: " + string(issues))
	if err != nil {
		return err
	}
	return nil
}

func printLicenses(scanData scanOutput, i int) error {
	licenses, err := json.MarshalIndent(scanData.Artifacts[i].Licenses, "", " ")
	fmt.Println("Licenses:::: " + string(licenses))
	if err != nil {
		return err
	}
	return nil
}

func getXrayRestAPIUrl(err error, rtDetails *config.ArtifactoryDetails) string {
	url, err := utils.BuildArtifactoryUrl(strings.ReplaceAll(rtDetails.GetUrl(), "/artifactory/", "/xray/"),
		"api/v1/summary/component", nil)
	return url
}

func scanGit(c *components.Context) error {
	if len(c.Arguments) != 2 {
		return errors.New("Wrong number of arguments. Expected: 2, " + "Received: " + strconv.Itoa(len(c.Arguments)))
	}
	var conf = new(scanConfiguration)
	conf.componentId = c.Arguments[0]
	//Invoke the process to get the list of gomodules
	grepCmd := exec.Command("./magic", c.Arguments[1])
	grepIn, _ := grepCmd.StdinPipe()
	grepOut, _ := grepCmd.StdoutPipe()
	grepCmd.Start()
	grepIn.Write([]byte(c.Arguments[0]))
	grepIn.Close()
	grepBytes, _ := ioutil.ReadAll(grepOut)
	grepCmd.Wait()
	//After the list of Strings are received, please pass it to scanPackages(compNames []string)
	result := string(grepBytes)
	return scanPackages(strings.Split(strings.TrimSuffix(result, "\n"), "\n"), c)
}

func GetRtDetails(c *components.Context) (*config.ArtifactoryDetails, error) {
	serverId := c.GetStringFlagValue(ServerIdFlag)
	details, err := commands.GetConfig(serverId, false)
	if err != nil {
		return nil, err
	}
	if details.Url == "" {
		return nil, errors.New("no server-id was found, or the server-id has no url")
	}
	details.Url = clientutils.AddTrailingSlashIfNeeded(details.Url)
	err = config.CreateInitialRefreshableTokensIfNeeded(details)
	if err != nil {
		return nil, err
	}
	return details, nil
}

//scanGitRepo http://github.com/cockroachdb/cockroach “/Users/shimi/go-cache”
