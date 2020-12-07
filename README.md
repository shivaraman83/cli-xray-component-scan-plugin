# hello-frog

## About this plugin
This plugin can scan a component,a list of components(artifact/binaries) or a Golang gitrepo to identify the vulnerabilities and also to provide licensing information using Jfrog Xray.

## Installation with JFrog CLI
Installing the latest version:

`$ jfrog plugin install xray-scan`

Installing a specific version:

`$ jfrog plugin install xray-scan@version`

Uninstalling a plugin

`$ jfrog plugin uninstall xray-scan`


## Component Identifiers
The plugin requires the component id's to be passed as per the format displayed here -https://www.jfrog.com/confluence/display/JFROG/Xray+REST+API#XrayRESTAPI-ComponentIdentifiers



## Usage
### Commands
* scan-component
    - Arguments:
        - componentId - Component Id of the artifact
    - Flags:
        - v: Displays only vulnerability information **[Default: false]** **[high: For high vulnerabilities only]** **[all: To view all the vulnerabilities]**
        - l: Displays only licensing information **[Default: false]** **[all: To view license]**
    - Example:
    ```
  $ jfrog xray-scan scan-component "deb://debian:buster:curl:7.64.0-4"
  $ jfrog xray-scan scan-component -v all "deb://debian:buster:curl:7.64.0-4"
  $ jfrog xray-scan scan-component -v high "deb://debian:buster:curl:7.64.0-4"
  $ jfrog xray-scan scan-component -l all "deb://debian:buster:curl:7.64.0-4"
  ```
  
* scan-components
    - Arguments:
        - String Array of componentId's - Component Id's of all the artifacts
    - Flags:
        - v: Displays only vulnerability information **[Default: false]** **[high: For high vulnerabilities only]** **[all: To view all the vulnerabilities]**
        - l: Displays only licensing information **[Default: false]** **[all: To view license]**
    - Example:
    ```
  $ jfrog xray-scan scan-components "deb://debian:buster:curl:7.64.0-4" "npm://debug:2.2.0" "go://github.com/ethereum/go-ethereum:1.8.2"
  $ jfrog xray-scan scan-components --v all "deb://debian:buster:curl:7.64.0-4" "npm://debug:2.2.0" "go://github.com/ethereum/go-ethereum:1.8.2"
  $ jfrog xray-scan scan-components --v high "deb://debian:buster:curl:7.64.0-4" "npm://debug:2.2.0" "go://github.com/ethereum/go-ethereum:1.8.2"
  $ jfrog xray-scan scan-components --l all "deb://debian:buster:curl:7.64.0-4" "npm://debug:2.2.0" "go://github.com/ethereum/go-ethereum:1.8.2"
  ```
  
 * scan-git-repo
     - Arguments:
         - A GitHub URL containing a GoLang project (go.mod) file
         - A local cache folder on your local box(where you are executing the plugin) for caching the go modules
     - Flags:
         - v: Displays only vulnerability information **[Default: false]** **[high: For high vulnerabilities only]** **[all: To view all the vulnerabilities]**
         - l: Displays only licensing information **[Default: false]** **[all: To view license]**
         - cacheRepo: Repository name where the go dependency(go.mod) tree is saved. This is by default stored inside CLI configured artifactory instance  **[Default: GoScanCache]**
         - downloadCache: To download the go.mod cache from Artifactory to your local box(Where the plugin is executed)
         - uploadCache:  To update/upload the local go.mod cache(Where plugin is executed) back to Artifactory instance
     - Example:
     ```
   $ jfrog xray-scan scan-git-repo http://github.com/cockroachdb/cockroach "/Users/sivas/Workspace/plugin-cache"
   $ jfrog xray-scan scan-git-repo --downloadCache=true  http://github.com/cockroachdb/cockroach "/Users/sivas/Workspace/plugin-cache"
   $ jfrog xray-scan scan-git-repo --updateCache=true  http://github.com/cockroachdb/cockroach "/Users/sivas/Workspace/plugin-cache"
   $ jfrog xray-scan scan-git-repo --downloadCache=true --v all http://github.com/cockroachdb/cockroach "/Users/sivas/Workspace/plugin-cache"
   $ jfrog xray-scan scan-git-repo --downloadCache=true --l all http://github.com/cockroachdb/cockroach "/Users/sivas/Workspace/plugin-cache"
   ```

### Environment variables
None.

## Additional info
None.

## Release Notes
The release notes are available [here](RELEASE.md).


CD into the new repository created.
Build and test your plugin by running the following commands.

$ cd cli-xray-component-scan-plugin
$ go build -o xray-scan
$ ./xray-scan --help

