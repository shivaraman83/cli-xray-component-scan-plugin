package commands

import (
	"errors"
	"github.com/jfrog/jfrog-cli-core/plugins/components"
	"github.com/jfrog/jfrog-cli-plugin-template/scanUtils"
	"strconv"
	//"time"
)

func ScanPackages() components.Command {
	//var compNames = []string{"deb://debian:buster:curl:7.64.0-4", "npm://debug:2.2.0", "go://github.com/ulikunitz/xz:0.5.6"}
	return components.Command{
		Name:        "scan-components",
		Description: "Scans a list of Packages/Components using Xray",
		//Aliases:     []string{"hi"},
		Arguments: getScanPackagesArguments(),
		Flags:     getScanPackagesFlags(),
		//EnvVars:     getHelloEnvVar(),
		Action: func(c *components.Context) error {
			return scanPackageList(c)
		},
	}
}

func getScanPackagesFlags() []components.Flag {
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

func getScanPackagesArguments() []components.Argument {
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

func scanPackageList(c *components.Context) error {
	if len(c.Arguments) == 0 {
		return errors.New("Wrong number of arguments. Expected: String array, " + "Received: " + strconv.Itoa(len(c.Arguments)))
	}
	compNames := c.Arguments
	return scanUtils.ScanPackages(compNames, c)
}

//scanGitRepo http://github.com/cockroachdb/cockroach “/Users/shimi/go-cache”
