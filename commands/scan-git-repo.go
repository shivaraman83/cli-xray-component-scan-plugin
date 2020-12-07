package commands

import (
	"errors"
	"github.com/jfrog/jfrog-cli-core/plugins/components"
	"github.com/jfrog/jfrog-cli-plugin-template/scanUtils"
	"github.com/jfrog/jfrog-client-go/artifactory/services"
	"github.com/mholt/archiver"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	//"github.com/kr/pretty"
	"github.com/jfrog/jfrog-client-go/artifactory"
	rtConfig "github.com/jfrog/jfrog-client-go/config"
	"strconv"
	"strings"
	//"time"
)

func ScanGitRepo() components.Command {
	return components.Command{
		Name:        "scan-git-repo",
		Description: "Scans components using Xray",
		//Aliases:     []string{"hi"},
		Arguments: getScanArguments(),
		Flags:     getScanFlagsForGit(),
		//EnvVars:     getHelloEnvVar(),
		Action: func(c *components.Context) error {
			return scanGit(c)
		},
	}
}

func getScanFlagsForGit() []components.Flag {
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
		components.StringFlag{
			Name:         "cacheRepo",
			Description:  "The cache repository in Artifactory to use for GitHub scanning.",
			DefaultValue: "GoScanCache",
		},
		components.BoolFlag{
			Name:         "updateCache",
			Description:  "Whether to update/upload the local go.mod cache back to Artifactory",
			DefaultValue: false,
		},
		components.BoolFlag{
			Name:         "downloadCache",
			Description:  "Whether to download the go.mod cache from Artifactory",
			DefaultValue: false,
		},
	}

}

//https://mholt.github.io/json-to-go/
//https://play.golang.org/p/Z3yszFl01L
//https://www.jfrog.com/confluence/display/JFROG/Xray+REST+API
//https://tutorialedge.net/golang/parsing-json-with-golang/

//./cli-xray-component-scan-plugin scan "deb://debian:buster:curl:7.64.0-4"
//./cli-xray-component-scan-plugin scan "npm://debug:2.2.0"

func scanGit(c *components.Context) error {
	if len(c.Arguments) != 2 {
		return errors.New("Wrong number of arguments. Expected: 2, " + "Received: " + strconv.Itoa(len(c.Arguments)))
	}
	var conf = new(scanConfiguration)
	conf.componentId = c.Arguments[0]
	conf.cacheRepo = c.GetStringFlagValue("cacheRepo")

	//Invoke the process to get the list of gomodules
	cacheFolder := c.Arguments[1]

	if c.GetBoolFlagValue("downloadCache") {
		err2 := downloadCache(c, cacheFolder)
		if err2 != nil {
			return err2
		}
	}

	magicCmd := exec.Command("./magic", cacheFolder)
	magicIn, _ := magicCmd.StdinPipe()
	magicOut, _ := magicCmd.StdoutPipe()
	_ = magicCmd.Start()
	_, _ = magicIn.Write([]byte(c.Arguments[0]))
	_ = magicIn.Close()
	magicBytes, _ := ioutil.ReadAll(magicOut)
	_ = magicCmd.Wait()
	//After the list of Strings are received, please pass it to scanPackages(compNames []string)
	result := string(magicBytes)

	if c.GetBoolFlagValue("updateCache") {
		err2 := uploadCache(c, cacheFolder)
		if err2 != nil {
			return err2
		}
	}
	return scanUtils.ScanPackages(strings.Split(strings.TrimSuffix(result, "\n"), "\n"), c)
}

func downloadCache(c *components.Context, cacheFolder string) error {
	rtDetails, err := scanUtils.GetRtDetails(c)
	if err != nil {
		return err
	}
	authDetails, err := rtDetails.CreateArtAuthConfig()
	if err != nil {
		return err
	}
	rtConf, err := rtConfig.NewConfigBuilder().Build()
	if err != nil {
		return err
	}

	x, err := artifactory.New(&authDetails, rtConf)
	if err != nil {
		return err
	}

	downloadService := services.NewDownloadService(x.Client())
	downloadService.SetThreads(1)
	downloadService.SetServiceDetails(authDetails)
	params := services.NewDownloadParams()
	params.SetPattern("GoScanCache/goModCache.tgz")
	params.SetTarget(cacheFolder + "/goModCache.tgz")
	_, _, err = downloadService.DownloadFiles(params)
	if err != nil {
		return err
	}

	z := archiver.TarGz
	err = z.Open(cacheFolder+"/goModCache.tgz", cacheFolder)
	if err != nil {
		return err
	}
	e := os.Remove(cacheFolder + "/goModCache.tgz")
	if e != nil {
		return e
	}
	return nil
}

func uploadCache(c *components.Context, cacheFolder string) error {
	z := archiver.TarGz

	files, err := ioutil.ReadDir(cacheFolder)
	if err != nil {
		log.Fatal(err)
	}
	var filesToTar []string
	for _, file := range files {
		filesToTar = append(filesToTar, cacheFolder+"/"+file.Name())
	}

	err = z.Make("goModCache.tgz", filesToTar)
	if err != nil {
		return err
	}
	rtDetails, err := scanUtils.GetRtDetails(c)
	if err != nil {
		return err
	}
	authDetails, err := rtDetails.CreateArtAuthConfig()
	if err != nil {
		return err
	}
	rtConf, err := rtConfig.NewConfigBuilder().Build()
	if err != nil {
		return err
	}

	x, err := artifactory.New(&authDetails, rtConf)
	if err != nil {
		return err
	}
	params := services.NewUploadParams()
	params.SetPattern("goModCache.tgz")
	params.SetTarget("GoScanCache/")
	upService := services.NewUploadService(x.Client())
	upService.SetThreads(1)
	upService.SetServiceDetails(authDetails)
	_, _, err = upService.UploadFiles(params)
	if err != nil {
		return err
	}
	// remove the compressed cache after upload
	e := os.Remove("goModCache.tgz")
	if e != nil {
		return e
	}
	return nil
}

//scanGitRepo http://github.com/cockroachdb/cockroach “/Users/shimi/go-cache”