package scanUtils

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
	"github.com/jfrog/jfrog-client-go/utils/log"
	"strings"
)

const ServerIdFlag = "server-id"

type ScanConfiguration struct {
	ComponentId string
	VulnFlag    string
	LicenseFlag string
	cacheRepo   string
}

type ScanOutput struct {
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

func PrintGeneral(scanData ScanOutput, i int) error {
	general, err := json.MarshalIndent(scanData.Artifacts[i].General, "", " ")
	fmt.Println("General:::: " + string(general))
	if err != nil {
		return err
	}
	return nil
}

func PrintIssues(scanData ScanOutput, i int) error {
	issues, err := json.MarshalIndent(scanData.Artifacts[i].Issues, "", " ")
	fmt.Println("Vulnerabilties:::: " + string(issues))
	if err != nil {
		return err
	}
	return nil
}

func PrintOnlyValidVulnerabilities(scanData ScanOutput, i int) error {
	issues, err := json.MarshalIndent(scanData.Artifacts[i].Issues, "", " ")
	iss := scanData.Artifacts[i].Issues
	for j := range iss {
		if iss[j].Severity != "" {
			fmt.Println("Vulnerabilties:::: " + string(issues))
		}
	}
	if err != nil {
		return err
	}
	return nil
}

func PrintLicenses(scanData ScanOutput, i int) error {
	licenses, err := json.MarshalIndent(scanData.Artifacts[i].Licenses, "", " ")
	fmt.Println("Licenses:::: " + string(licenses))
	if err != nil {
		return err
	}
	return nil
}

func GetXrayRestAPIUrl(err error, rtDetails *config.ArtifactoryDetails) string {
	url, err := utils.BuildArtifactoryUrl(strings.ReplaceAll(rtDetails.GetUrl(), "/artifactory/", "/xray/"),
		"api/v1/summary/component", nil)
	return url
}

func PrintOnlyHighVulnerabilities(scanData ScanOutput) error {
	for i := range scanData.Artifacts {
		iss := scanData.Artifacts[i].Issues
		for j := range iss {
			if iss[j].Severity == "High" {
				issue, err := json.MarshalIndent(iss[j], "", " ")
				fmt.Println("Vulnerability:::: " + string(issue))
				if err != nil {
					return err
				}
			}
		}

	}
	return nil
}

func ScanPackages(compNames []string, c *components.Context) error {
	var sb strings.Builder
	var payload strings.Builder
	for _, element := range compNames {
		sb.WriteString("{\"component_id\":\"" + element + "\"},")
	}

	var conf = new(ScanConfiguration)
	conf.ComponentId = c.Arguments[0]
	conf.VulnFlag = c.GetStringFlagValue("v")
	conf.LicenseFlag = c.GetStringFlagValue("l")

	log.Debug("LicenseFlag " + conf.LicenseFlag)
	log.Debug("VulnFlag" + conf.VulnFlag)

	var payloadComp = strings.TrimSuffix(sb.String(), ",")
	payload.WriteString("{\"component_details\":[" + payloadComp + "]}")

	log.Debug("Payload ::::" + payload.String())

	rtDetails, err := GetRtDetails(c)
	url := GetXrayRestAPIUrl(err, rtDetails)
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

	var scanData ScanOutput
	err = json.Unmarshal(body, &scanData)

	//data := clientutils.IndentJson(body)
	//scanOutputJSON := make(map[string][]scanOutput)
	///err = json.Unmarshal([]byte(data), &scanOutputJSON)

	//log.Output(clientutils.IndentJson(body))
	if err != nil {
		return err
	}
	err = PrintOutput(conf, scanData, err)
	if err != nil {
		return err
	}

	return nil
}

func PrintOutput(conf *ScanConfiguration, scanData ScanOutput, err error) error {

	b, _ := json.MarshalIndent(scanData, "", " ")
	fmt.Println(string(b))

	if conf.LicenseFlag == "" && conf.VulnFlag == "" {
		for i := range scanData.Artifacts {
			err := PrintGeneral(scanData, i)
			err = PrintIssues(scanData, i)
			err = PrintLicenses(scanData, i)
			if err != nil {
				return err
			}
		}
	}

	if conf.VulnFlag == "all" {
		for i := range scanData.Artifacts {
			err = PrintIssues(scanData, i)
			if err != nil {
				return err
			}
		}
	}

	if conf.VulnFlag == "high" {
		err := PrintOnlyHighVulnerabilities(scanData)
		if err != nil {
			return err
		}
	}

	if conf.LicenseFlag == "all" {
		for i := range scanData.Artifacts {
			err = PrintLicenses(scanData, i)
			if err != nil {
				return err
			}
		}
	}
	return nil
}
