# hello-frog

## About this plugin
This plugin can scan a component,a list of components(artifact/binaries) or a Golang gitrepo for vulnerabilities and provide complete licensing information using Jfrog Xray.

## Installation with JFrog CLI
Installing the latest version:

`$ jfrog plugin install hello-frog`

Installing a specific version:

`$ jfrog plugin install hello-frog@version`

Uninstalling a plugin

`$ jfrog plugin uninstall hello-frog`

## Usage
### Commands
* scan
    - Arguments:
        - componentId
    - Flags:
        - shout: Makes output uppercase **[Default: false]**
        - repeat: Greets multiple times **[Default: 1]**
    - Example:
    ```
  $ jfrog hello-frog hello world --shout --repeat=2
  
  NEW GREETING: HELLO WORLD!
  NEW GREETING: HELLO WORLD!
  ```

### Environment variables
* HELLO_FROG_GREET_PREFIX - Adds a prefix to every greet **[Default: New greeting: ]**

## Additional info
None.

## Release Notes
The release notes are available [here](RELEASE.md).



CD into the new repository created.
Build and test your plugin by running the following commands.

$ cd jfrog-cli-plugin-template
$ go build -o hello-frog
$ ./hello-frog --help
$ ./hello-frog hello --help
$ ./hello-frog hello Yey!
