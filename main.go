package main

import (
	"fmt"

	l "github.com/watts-kit/wattsPluginLib"
)

const (
	authorizedKeyFile = "~/.ssh/authorized_keys"
)

func request(pi l.Input) l.Output {
	h := pi.SSHHostListFromConf("host_list")

	// backup the authorized_keys file
	h.RunSSHCommand("cp", authorizedKeyFile, authorizedKeyFile+".bak")

	publicKey := pi.PublicKeyFromParams("pub_key")

	uid := fmt.Sprintf("%s_%s", pi.Conf["prefix"], pi.WaTTSUserID)

	// prefix the line with options if given
	var newLine string
	if options, ok := pi.Params["options"]; ok {
		newLine = fmt.Sprintf("%s %s %s", options.(string), publicKey, uid)
	} else {
		newLine = fmt.Sprintf("%s %s", publicKey, uid)
	}

	// insert the line into the authorized_keys file
	h.RunSSHCommand("echo", newLine, ">>", authorizedKeyFile)

	// we return the host we deploy to as a credential
	credentials := make([]l.Credential, len(h))
	for i, v := range h {
		credentials[i] = l.AutoCredential("host", v)
	}

	// execute the remote script for all hosts in the host list
	return l.PluginGoodRequest(credentials, uid)
}

func revoke(pi l.Input) l.Output {
	// prepare for execution
	h := pi.SSHHostListFromConf("host_list")
	h.RunSSHCommand("sed", "-i.bak", "/"+pi.CredentialState+"/d", authorizedKeyFile)
	return l.PluginGoodRevoke()
}

func main() {
	pluginDescriptor := l.PluginDescriptor{
		Version:        "1.0.0",
		Author:         "Lukas Burgey @ KIT within the INDIGO DataCloud Project",
		DeveloperEmail: "ubedv@student.kit.edu",
		Actions: map[string]l.Action{
			"request": request,
			"revoke":  revoke,
		},
		ConfigParams: []l.ConfigParamsDescriptor{
			l.ConfigParamsDescriptor{Name: "host_list", Type: "string", Default: ""},
			l.ConfigParamsDescriptor{Name: "prefix", Type: "string", Default: ""},
		},
		RequestParams: []l.RequestParamsDescriptor{
			l.RequestParamsDescriptor{
				Key:         "pub_key",
				Name:        "public key",
				Description: "the public key of the service",
				Type:        "textarea",
				Mandatory:   true,
			},
			l.RequestParamsDescriptor{
				Key:         "options",
				Name:        "Options",
				Description: "Options for the authorized_keys file",
				Type:        "textarea",
				Mandatory:   false,
			},
		},
	}
	l.PluginRun(pluginDescriptor)
}
