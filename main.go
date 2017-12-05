package main

import (
	"fmt"
	l "github.com/watts-kit/wattsPluginLib"
	"github.com/watts-kit/wattsPluginLib/remoteScript"
	"github.com/watts-kit/wattsPluginLib/sshKeyGen"
	"strings"
)

func getHostList(conf map[string]interface{}) []string {
	hostListString := fmt.Sprint(conf["host_list"])
	return strings.Split(hostListString, " ")
}

// if the user has provided a public key we use it instead of generating a key pair
func getCredentials(params map[string]interface{}) (publicKey string, credential []l.Credential) {
	if pk, ok := params["pub_key"]; ok {
		publicKey = fmt.Sprint(pk)
		credential = []l.Credential{}
	} else {
		privateKey, publicKey, password, err := sshKeyGen.GenerateKey(4096, 0)
		l.Check(err, 1, "ssh keypair generation")
		credential = []l.Credential{
			l.TextCredential("private key", privateKey),
			l.TextCredential("public key", publicKey),
			l.TextCredential("password", password),
		}
	}
	return
}

func request(pi l.Input) l.Output {

	publicKey, credential := getCredentials(pi.Params)
	state := pi.CredentialState

	// prepare for execution
	remoteCommand := pi.Conf["remote_command"].(string)
	remoteScriptParameter := map[string]interface{}{
		"pub_key": fmt.Sprintf("%s %s_%s", publicKey, pi.Conf["prefix"], pi.WaTTSUserID),
		"state":   state,
	}
	hostList := getHostList(pi.Conf)

	// execute the remote script for all hosts in the host list
	hostReplies, err := remoteScript.ExecuteRemoteScriptOnHosts(
		remoteCommand, remoteScriptParameter, hostList)
	l.Check(err, 1, "execution of the remote script on the hosts failed")

	for host, hostReply := range hostReplies {
		if result, ok := hostReply["result"].(string); ok && result == "ok" {
			if credentialReply, ok := hostReply["credential"].(l.Credential); ok {
				credentialReply["name"] = fmt.Sprint(credentialReply["name"], " @ ", host)
				credential = append(credential, credentialReply)
				continue
			}
			return l.PluginError("invalid credential from " + host)
		}
		if logMsg, ok := hostReply["log_msg"].(string); ok {
			return l.PluginError(logMsg)
		}
		return l.PluginError("request failed on host " + host)
	}
	return l.PluginGoodRequest(credential, state)
}

func revoke(pi l.Input) l.Output {
	// prepare for execution
	remoteCommand := pi.Conf["remote_command"].(string)
	hostList := getHostList(pi.Conf)

	// execute the remote script for all hosts in the host list
	hostReplies, err := remoteScript.ExecuteRemoteScriptOnHosts(
		remoteCommand, pi.Params, hostList)
	l.Check(err, 1, "execution of the remote script on the hosts failed")

	for host, hostReply := range hostReplies {
		if result, ok := hostReply["result"].(string); ok && result == "ok" {
			continue
		}
		if logMsg, ok := hostReply["log_msg"].(string); ok {
			return l.PluginError(logMsg)
		}
		return l.PluginError("request failed on host " + host)
	}
	return l.PluginGoodRevoke()
}

func main() {
	pluginDescriptor := l.PluginDescriptor{
		Version:     "0.1.0",
		Author:      "Lukas Burgey @ KIT within the INDIGO DataCloud Project",
		Name:        "wattsPluginSSH",
		Description: "A watts plugin to deploy ssh keys for users",
		Actions: map[string]l.Action{
			"request": request,
			"revoke":  revoke,
		},
		ConfigParams: []l.ConfigParamsDescriptor{
			l.ConfigParamsDescriptor{Name: "state_prefix", Type: "string", Default: "TTS"},
			l.ConfigParamsDescriptor{Name: "host_list", Type: "string", Default: ""},
			l.ConfigParamsDescriptor{Name: "remote_command", Type: "string", Default: "sudo /home/tts/.config/tts/ssh_vm.py"},
		},
		RequestParams: []l.RequestParamsDescriptor{
			l.RequestParamsDescriptor{Key: "pub_key", Name: "public key",
				Description: "the public key of the service", Type: "textarea", Mandatory: false},
		},
	}
	l.PluginRun(pluginDescriptor)
}
