package aws

import (
	"fmt"
	"log"
	"os"
	"runtime"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/fatih/color"
)

var cyan = color.New(color.FgCyan).SprintFunc()
var red = color.New(color.FgRed).SprintFunc()

func GetIamSimResult(SkipAdminCheck bool, roleArnPtr *string, iamSimulatorMod IamSimulatorModule, localAdminMap map[string]bool) (string, string) {
	var adminRole, canRolePrivEsc string
	canRolePrivEsc = "Skipping, no pmapper data"
	if !SkipAdminCheck {
		var isRoleAdminBool bool
		// If we've seen the function before, skip the isRoleAdmin function and just pull the value from the localAdminMap

		if aws.ToString(roleArnPtr) == "" {
			return "", ""
		}
		roleArn := aws.ToString(roleArnPtr)

		if val, ok := localAdminMap[roleArn]; ok {
			if val {
				// we've seen it before and it's an admin
				adminRole = "YES"
			} else {
				// we've seen it before and it's NOT an admin
				adminRole = "No"
			}
		} else {
			isRoleAdminBool = isRoleAdmin(iamSimulatorMod, roleArnPtr)

			if isRoleAdminBool {
				adminRole = "YES"
				localAdminMap[roleArn] = true
			} else {
				adminRole = "No"
				localAdminMap[roleArn] = false
			}
		}

		if isRoleAdminBool {
			adminRole = "YES"
		} else {
			adminRole = "No"
		}

	} else {
		adminRole = "Skipped"
		canRolePrivEsc = "Skipped"
	}
	return adminRole, canRolePrivEsc
}

func isRoleAdmin(iamSimMod IamSimulatorModule, principal *string) bool {
	adminCheckResult := iamSimMod.isPrincipalAnAdmin(principal)
	if adminCheckResult {
		return true
	} else {
		return false
	}

}

func initPmapperGraph(Caller sts.GetCallerIdentityOutput, AWSProfile string, Goroutines int) (PmapperModule, error) {
	pmapperMod := PmapperModule{
		Caller:     Caller,
		AWSProfile: AWSProfile,
		Goroutines: Goroutines,
	}
	err := pmapperMod.initPmapperGraph()
	if err != nil {
		return pmapperMod, err
	}
	return pmapperMod, nil

}

func generatePmapperDataBasePaths(accountId *string) (string, string) {
	var edgesPath, nodesPath string

	if runtime.GOOS == "darwin" {
		dir, err := os.UserHomeDir()
		if err != nil {
			log.Fatal("Could not get homedir")
		}
		edgesPath = fmt.Sprintf(dir + "/Library/Application Support/com.nccgroup.principalmapper/" + aws.ToString(accountId) + "/graph/edges.json")
		nodesPath = fmt.Sprintf(dir + "/Library/Application Support/com.nccgroup.principalmapper/" + aws.ToString(accountId) + "/graph/nodes.json")

	} else if runtime.GOOS == "linux" || runtime.GOOS == "freebsd" || runtime.GOOS == "openbsd" {
		xdg, ok := os.LookupEnv("XDG_DATA_HOME")
		if ok {
			edgesPath = fmt.Sprintf(xdg + aws.ToString(accountId) + "/graph/edges.json")
			nodesPath = fmt.Sprintf(xdg + aws.ToString(accountId) + "/graph/nodes.json")
		} else {
			dir, err := os.UserHomeDir()
			if err == nil {
				edgesPath = fmt.Sprintf(dir + "/.local/share/principalmapper/" + aws.ToString(accountId) + "/graph/edges.json")
				nodesPath = fmt.Sprintf(dir + "/.local/share/principalmapper/" + aws.ToString(accountId) + "/graph/nodes.json")
			} else {
				log.Fatal("Could not homedir.")
			}
		}

	} else if runtime.GOOS == "windows" {
		dir, err := os.UserConfigDir()
		if err != nil {
			log.Fatal("Could not get userconfigdir")
		}
		edgesPath = fmt.Sprintf(dir + "\\principalmapper" + aws.ToString(accountId) + "\\graph\\edges.json")
		nodesPath = fmt.Sprintf(dir + "\\principalmapper" + aws.ToString(accountId) + "\\graph\\nodes.json")

	}

	return edgesPath, nodesPath
}

func pmapperIsRoleAdmin(pmapperMod PmapperModule, principal *string) bool {
	return pmapperMod.DoesPrincipalHaveAdmin(aws.ToString(principal))

}

func pmapperHasPathToAdmin(pmapperMod PmapperModule, principal *string) bool {
	return pmapperMod.DoesPrincipalHavePathToAdmin(aws.ToString(principal))

}

func GetPmapperResults(SkipAdminCheck bool, pmapperMod PmapperModule, roleArn *string) (string, string) {
	var adminRole, canRolePrivEsc string

	var isRoleAdminBool bool
	var canPrivEscBool bool
	if !SkipAdminCheck {

		if aws.ToString(roleArn) == "" {
			return "", ""
		}
		isRoleAdminBool = pmapperIsRoleAdmin(pmapperMod, roleArn)
		canPrivEscBool = pmapperHasPathToAdmin(pmapperMod, roleArn)
		if canPrivEscBool {
			canRolePrivEsc = "YES"
		} else {
			canRolePrivEsc = "No"
		}

		if isRoleAdminBool {
			adminRole = "YES"
		} else {
			adminRole = "No"
		}
	} else {
		adminRole = "Skipped"
		canRolePrivEsc = "Skipped"
	}
	return adminRole, canRolePrivEsc
}
