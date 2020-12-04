package commands

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jfrog/jfrog-cli-core/plugins/components"
	"github.com/jfrog/jfrog-cli-core/utils/config"
	"github.com/jfrog/jfrog-client-go/artifactory/services/utils"
	"github.com/jfrog/jfrog-client-go/auth"
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

func ScanComponent() components.Command {
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

func ScanPackages() components.Command {
	var compNames = []string{"deb://debian:buster:curl:7.64.0-4", "npm://debug:2.2.0", "go://github.com/ulikunitz/xz:0.5.6"}
	return components.Command{
		Name:        "scanPackages",
		Description: "Scans a list of Packages/Components using Xray",
		//Aliases:     []string{"hi"},
		Arguments: getScanArgumentsJson(),
		//Flags:       ""getHelloFlags""(),
		//EnvVars:     getHelloEnvVar(),
		Action: func(c *components.Context) error {
			return scanPackageList(compNames)
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

type inputscanJson struct {
	Components []struct {
		ComponentID string `json:"ComponentId"`
	} `json:"Components"`
}

type scanConfiguration struct {
	componentId string
}

func getScanArguments() []components.Argument {
	return []components.Argument{
		{
			Name: "Component Name",
		},
	}
}

func getScanArgumentsJson() []components.Argument {
	return []components.Argument{
		{
			Name: "Component Name",
		},
	}
}

/*func getScanArgumentsJson(array []compNames) {
	for i := 0; i < len(array); i++ {
		fmt.Println(array[i].componentName)
	}
}*/

type compNames struct {
	componentName string
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

func scanPackageList(compNames []string) error {

	var sb strings.Builder
	var payload strings.Builder
	for i := range compNames {
		sb.WriteString("{\"component_id\":\"" + compNames[i] + "\"},")
	}
	var payloadComp = strings.TrimSuffix(sb.String(), ",")
	payload.WriteString("{\"component_details\":[" + payloadComp + "]}")

	fmt.Println("Payload:::: %+v", payload.String())

	artAuth, url, client, err := artConf()
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
	printGeneral(scanData)
	printIssues(scanData)
	printLicenses(scanData)

	return nil
}

func scanCmd(c *components.Context) error {
	if len(c.Arguments) != 1 {
		return errors.New("Wrong number of arguments. Expected: 1, " + "Received: " + strconv.Itoa(len(c.Arguments)))
	}
	var conf = new(scanConfiguration)
	conf.componentId = c.Arguments[0]

	artAuth, url, client, err := artConf()
	if err != nil {
		return err
	}
	httpClientDetails := artAuth.CreateHttpClientDetails()
	httpClientDetails.Headers = map[string]string{
		"Content-Type": "application/json",
	}

	_, body, err := client.SendPost(url, []byte("{\"component_details\":[{\"component_id\":\""+conf.componentId+"\"}]}"), httpClientDetails)

	var scanData scanOutput
	err = json.Unmarshal(body, &scanData)

	if err != nil {
		return err
	}
	printGeneral(scanData)
	printIssues(scanData)
	printLicenses(scanData)
	return nil
}

func scanGit(c *components.Context) error {
	if len(c.Arguments) != 1 {
		return errors.New("Wrong number of arguments. Expected: 1, " + "Received: " + strconv.Itoa(len(c.Arguments)))
	}
	var conf = new(scanConfiguration)
	conf.componentId = c.Arguments[0]
	//Invoke the process to get the list of gomodules
	grepCmd := exec.Command("./magic", "/Users/shimi/go-cache")
	grepIn, _ := grepCmd.StdinPipe()
	grepOut, _ := grepCmd.StdoutPipe()
	grepCmd.Start()
	grepIn.Write([]byte(c.Arguments[0]))
	grepIn.Close()
	grepBytes, _ := ioutil.ReadAll(grepOut)
	grepCmd.Wait()
	//After the list of Strings are received, please pass it to scanPackages(compNames []string)
	result := string(grepBytes)
	scanPackageList(strings.Split(strings.TrimSuffix(result, "\n"),"\n"))
	return nil
}

func artConf() (auth.ServiceDetails, string, *httpclient.HttpClient, error) {
	artDetails, err := config.GetArtifactorySpecificConfig("", true, true)
	if err != nil {
		return nil, "", nil, err
	}
	artAuth, err := artDetails.CreateArtAuthConfig()

	url, err := utils.BuildArtifactoryUrl(strings.ReplaceAll(artAuth.GetUrl(), "/artifactory/", "/xray/"),
		"api/v1/summary/component", nil)
	if err != nil {
		return nil, "", nil, err
	}
	client, err := httpclient.ClientBuilder().Build()
	if err != nil {
		return nil, "", nil, err
	}
	return artAuth, url, client, nil
}

func printIssues(scanData scanOutput) error {
	for i := range scanData.Artifacts {
		issues, error := json.MarshalIndent(scanData.Artifacts[i].Issues, "", " ")
		fmt.Println("Issues:::: " + string(issues))
		if error != nil {
			return error
		}
	}
	return nil
}

func printGeneral(scanData scanOutput) error {
	for i := range scanData.Artifacts {
		general, error := json.MarshalIndent(scanData.Artifacts[i].General, "", " ")
		fmt.Println("Component Data:::: " + string(general))
		if error != nil {
			return error
		}
	}
	return nil
}

func printLicenses(scanData scanOutput) error {
	for i := range scanData.Artifacts {
		licenses, error := json.MarshalIndent(scanData.Artifacts[i].Licenses, "", " ")
		fmt.Println("Licenses:::: " + string(licenses))
		if error != nil {
			return error
		}
	}
	return nil
}

/*func scanPackageList(c *components.Context) error {

	//bytes, err := json.Marshal(c.Arguments)
	var b = []byte(`{"Components":[{"ComponentId":"deb://debian:buster:curl:7.64.0-4"},{"ComponentId":"npm://debug:2.2.0"}]}`)
	var inputCompJson inputscanJson

	err := json.Unmarshal(b, &inputCompJson)

	var sb strings.Builder
	var payload strings.Builder
	for i := range inputCompJson.Components {
		sb.WriteString("{\"component_id\":\"" + inputCompJson.Components[i].ComponentID + "\"},")
	}
	var payloadComp = strings.TrimSuffix(sb.String(), ",")
	payload.WriteString("{\"component_details\":[" + payloadComp + "]}")

	fmt.Printf("Payload:::: %+v", payload.String())

	artDetails, err := config.GetArtifactorySpecificConfig("", true, true)
	if err != nil {
		return err
	}

	artAuth, err := artDetails.CreateArtAuthConfig()

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

	_, body, err := client.SendPost(url, []byte(payload.String()), httpClientDetails)

	var scanData scanOutput
	err = json.Unmarshal(body, &scanData)

	data := clientutils.IndentJson(body)
	scanOutputJSON := make(map[string][]scanOutput)
	err = json.Unmarshal([]byte(data), &scanOutputJSON)

	log.Output(clientutils.IndentJson(body))
	if err != nil {
		return err
	}
	//fmt.Printf("\n\n Scan Result:::: %+v", scanOutputJSON)
	for i := range scanData.Artifacts {
		fmt.Printf("\n\nScan Result::::%# v", pretty.Formatter(scanData.Artifacts[i].Issues))
		//fmt.Printf("\n\n Scan Result-Vulnerability:::: %+v", scanData.Artifacts[i].Issues)
		//fmt.Printf("\n\n Scan Result-Licensing:::: %+v", scanData.Artifacts[i].Licenses)
		fmt.Printf("\n\nScan Result::::%# v", pretty.Formatter(scanData.Artifacts[i].Licenses))
	}

	return nil
}*/

/*
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

	//log.Output(clientutils.IndentJson(body))

	var scanData scanOutput
	err = json.Unmarshal(body, &scanData)

	//data := clientutils.IndentJson(body)
	//scanOutputJSON := make(map[string][]scanOutput)
	//err = json.Unmarshal([]byte(data), &scanOutputJSON)


	if err != nil {
		return err
	}
	for i := range scanData.Artifacts {
		issues, error := json.MarshalIndent(scanData.Artifacts[i].Issues,"", " ")
		fmt.Println("Issues:::: "+ string(issues))
		licenses, error := json.MarshalIndent(scanData.Artifacts[i].Licenses,"", " ")
		fmt.Println("Licenses:::: "+ string(licenses))
		if error != nil {
			return error
		}
	}
	return nil
}*/
