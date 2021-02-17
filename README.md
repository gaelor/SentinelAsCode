![](https://www.metsys.fr/wp-content/themes/metsys/images/svg/metsys-logo.svg "Metsys")
![Build Status](https://github.com/gaelor/SentinelAsCode/actions)

# Azure Sentinel as Code

The purpose of this project is to provide tools to enable automatic deployment of Azure Sentinel environments through Github Actions.

The project has several folders for each of the different Sentinel components that can be configured (Onboard, Connectors, Workbooks, Analytics Rules, Hunting Rules, Playbooks) plus folders for local scripts. In this README we explain some of the basics for each of them but we encourage you to visit each of the folders for more details on how to use the tools.

## LocalScripts

Scripts that are used to automate the deployment of the different Sentinel components

## Scripts

Scripts that are used inside the Github Actions to automate the deployment of the different Sentinel components

## Onboard

Automating the installation of Azure Sentinel on one or more workspaces as defined in config file under Onboard

## Connectors

Build - Automatically connect data sources to start sending data into Sentinel. This can only be done for Microsoft first party services that don't require additional configuration on the data source side

## Workbooks

Collection of custom workbooks in JSON format that can be leveraged to add additional visibility into environments

## Analytics Rules

Definition files containing all the analytics rule alerts to be created in an environment

## Hunting Rules

Definition files containing all the hunting rules to be created in an environment

## Playbooks

Collection of custom playbooks to be added to your Sentinel environment

## Authors

<a href="https://github.com/gaelor"><img src="https://avatars.githubusercontent.com/u/60777331?s=64&v=4" title="Thomas Couilleaux" width="80" height="80">Thomas Couilleaux</a> &nbsp;
<a href="https://github.com/clem-metsys"><img src="https://avatars.githubusercontent.com/u/76099816?s=400&v=4" title="Clément Bonnet" width="80" height="80"></a> &nbsp;
<a href="https://github.com/laurent-cosnuau"><img src="https://avatars.githubusercontent.com/u/66997772?s=400&v=4" title="Laurent Cosnuau" width="80" height="80"></a> &nbsp;