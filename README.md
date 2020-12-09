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
The plugin requires the component id's to be passed as per the format displayed  here- https://www.jfrog.com/confluence/display/JFROG/Xray+REST+API#XrayRESTAPI-ComponentIdentifiers



## Usage
### Commands
* scan-components
    - Arguments:
        - String Array of componentId's - Component Id's of all the artifacts
    - Flags:
        - v: Displays only vulnerability information **[Default: false]** **[high: For high vulnerabilities only]** **[all: To view all the vulnerabilities]**
        - l: Displays only licensing information **[Default: false]** **[all: To view license]**
    - Example:
    ```
  $ jfrog xray-scan sc "deb://debian:buster:curl:7.64.0-4"
  $ jfrog xray-scan sc --v all "deb://debian:buster:curl:7.64.0-4"
  $ jfrog xray-scan scan-components --v high "deb://debian:buster:curl:7.64.0-4"
  $ jfrog xray-scan scan-components --l all "deb://debian:buster:curl:7.64.0-4"
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
   Since the output is a json payload, you can easily modify the output structure as per your preference and you can write your own automation with it using this plugin. Below is an example where we are using jQuery to fetch only the required information.
     - Example: 
   ```
   $ jfrog xray-scan scan-git-repo https://github.com/cockroachdb/cockroach "/Users/sivas/Workspace/plugin-cache" | jq '.[] | select(.vulnerabilities[] | .severity |contains("High")) | { cid: .general.component_id , cves: (.vulnerabilities[].cves[].cvss_v2), fixed: (.vulnerabilities[].components[].fixed_versions) }'
   
   Output :
   {
     "cid": "github.com/apache/thrift:0.0.0-20181211084444-2b7365c54f82",
     "cves": "7.8/CVSS:2.0/AV:N/AC:L/Au:N/C:N/I:N/A:C",
     "fixed": [
       "[0.13.0]"
     ]
   }
   {
     "cid": "github.com/google/flatbuffers:1.11.0",
     "cves": "7.6/AV:N/AC:H/Au:N/C:C/I:C/A:C",
     "fixed": [
       "[1.12.0]"
     ]
   }

   ```
   https://git.jfrog.info/projects/DEVOA/repos/magic/browse - Contains the code which scans a Github URL containing a Go Lang project and returns the dependency tree

### Environment variables
None.

## Additional info
None.

## Release Notes
The release notes are available [here](RELEASE.md).



