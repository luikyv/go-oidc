// Command testrunner automates the execution of a Conformance Suite test plan
// against a specified authorization server.
//
// At the end of the test execution, a zip file is generated containing the
// complete logs of the test plan.
//
// Usage:
//
//	go run cmd/testrunner/main.go --plan=plan_name --config=cs_config [flags]
//
// Required Flags:
//
//	--plan     Specifies the test plan to execute.
//	--config   Path to the configuration file for the Conformance Suite.
//
// Optional Flags:
//
//	--modules             Comma-separated list of test modules to run.
//	                      If omitted, all available modules will be executed.
//	--excluded-modules    Comma-separated list of test modules to skip during
//	                      execution.
//	--response_type       Defines the OAuth 2.0 response type (e.g., code, token).
//	--sender_constrain    Specifies the sender-constrain mechanism to apply to
//	                      tokens (e.g., dpop, mtls).
//	--client_auth_type    Defines the client authentication type (e.g., mtls,
//	                      private_key_jwt).
//	--openid              Indicates the OpenID profile (e.g., openid_connect,
//	                      plain_oauth).
//	--fapi_request_method Specifies the FAPI request method (e.g., unsigned,
//	                      signed_non_repudiation).
//	--fapi_profile        Defines the FAPI profile for testing (e.g., plain_fapi).
//	--fapi_response_mode  Specifies the response mode for FAPI tests (e.g.,
//	                      jarm, plain_response).
//
// Notes:
//
//	Depending on the test plan, some of the optional flags may be required.
//	Be sure to review the test plan documentation for any specific mandatory
//	flags.
//
//	If any flag value contains spaces, enclose the value in double quotes.
//
// Example:
//
//	go run cmd/testrunner/main.go \
//	--plan=authorizationoidcc-dynamic-certification-test-plan_code \
//	--config=config.json \
//	--modules=oidcc-server,oidcc-idtoken-rs256 \
//	--response_type="code id_token"
package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"
)

func main() {
	args := buildArguments()

	plan, err := createTestPlan(
		args.testPlanName,
		args.configFile,
		args.variant,
	)
	if err != nil {
		log.Fatal(err)
	}

	testModules := chosenTestModules(plan, args)
	var testErrs []error
	for _, module := range testModules {
		log.Printf("------------------------------ %s ------------------------------", module)
		err = runTestModule(module, plan)
		log.Printf("------------------------------------------------------------")
		if err != nil {
			testErrs = append(testErrs, err)
		}
	}

	downloadTestPlanLogs(plan.ID)
	if len(testErrs) > 0 {
		log.Fatalf("test plan %s has failures: %v\n", plan.Name, testErrs)
	}

	log.Printf("test plan %s executed successfully\n", plan.Name)
}

const (
	conformanceSuiteURL  string = "https://localhost:8443"
	argTestPlanName      string = "--plan="
	argTestModuleNames   string = "--modules="
	argExcludedModules   string = "--excluded-modules="
	argConfigFile        string = "--config="
	argResponseType      string = "--response_type="
	argSenderConstrain   string = "--sender_constrain="
	argClientAuthType    string = "--client_auth_type="
	argOpenID            string = "--openid="
	argFAPIRequestMethod string = "--fapi_request_method="
	argFAPIProfile       string = "--fapi_profile="
	argFAPIResponseMode  string = "--fapi_response_mode="
)

type testStatus string

const (
	testStatusCreated    = "CREATED"
	testStatusConfigured = "CONFIGURED"
	testStatusWaiting    = "WAITING"
	testStatusRunning    = "RUNNING"
	testStatusFinished   = "FINISHED"
)

type testResult string

const (
	testResultFailed testResult = "FAILED"
	testResultPassed testResult = "PASSED"
	testResultReview testResult = "REVIEW"
)

var httpClient = &http.Client{
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
}

type arguments struct {
	testPlanName        string
	testModules         []string
	excludedTestModules []string
	variant             variant
	configFile          string
}

type testPlan struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	TestModules []struct {
		Name    string `json:"testModule"`
		Variant variant
	} `json:"modules"`
}

type testModule struct {
	ID      string     `json:"testId"`
	Name    string     `json:"testName"`
	Status  testStatus `json:"status"`
	Result  testResult `json:"result"`
	Variant variant    `json:"variant"`
}

type variant struct {
	ServerMetadata     string `json:"server_metadata,omitempty"`
	ClientAuthType     string `json:"client_auth_type,omitempty"`
	ClientRegistration string `json:"client_registration,omitempty"`
	ResponseType       string `json:"response_type,omitempty"`
	ResponseMode       string `json:"response_mode,omitempty"`
	SenderConstrain    string `json:"sender_constrain,omitempty"`
	OpenID             string `json:"openid,omitempty"`
	FAPIRequestMethod  string `json:"fapi_request_method,omitempty"`
	FAPIProfile        string `json:"fapi_profile,omitempty"`
	FAPIResponseMode   string `json:"fapi_response_mode,omitempty"`
}

func (v variant) String() string {
	b, _ := json.Marshal(v)
	return string(b)
}

func chosenTestModules(plan testPlan, args arguments) []string {
	var testModules []string
	for _, m := range plan.TestModules {
		testModules = append(testModules, m.Name)
	}

	// If specific test modules were informed, they are the only ones to be run.
	if len(args.testModules) != 0 {
		testModules = args.testModules
	}

	// Remove excluded test modules.
	if len(args.excludedTestModules) != 0 {
		var filteredModules []string
		for _, m := range testModules {
			if slices.Contains(args.excludedTestModules, m) {
				continue
			}
			filteredModules = append(filteredModules, m)
		}
		testModules = filteredModules
	}

	log.Printf("the following test modules will execute: \n\t-%s\n", strings.Join(testModules, "\n\t-"))
	return testModules
}

// buildArguments parses the command line arguments sent when running this routine.
func buildArguments() arguments {
	args := arguments{}

	for _, arg := range os.Args[1:] {
		// Remove quotes if any.
		arg = strings.Replace(arg, "'", "", -1)
		arg = strings.Replace(arg, "\"", "", -1)

		switch {
		case strings.HasPrefix(arg, argTestPlanName):
			args.testPlanName = strings.Replace(arg, argTestPlanName, "", 1)
		case strings.HasPrefix(arg, argTestModuleNames):
			args.testModules = strings.Split(
				strings.Replace(arg, argTestModuleNames, "", 1),
				",",
			)
		case strings.HasPrefix(arg, argExcludedModules):
			args.excludedTestModules = strings.Split(
				strings.Replace(arg, argExcludedModules, "", 1),
				",",
			)
		case strings.HasPrefix(arg, argConfigFile):
			args.configFile = strings.Replace(arg, argConfigFile, "", 1)
		case strings.HasPrefix(arg, argClientAuthType):
			args.variant.ClientAuthType = strings.Replace(arg, argClientAuthType, "", 1)
		case strings.HasPrefix(arg, argResponseType):
			args.variant.ResponseType = strings.Replace(arg, argResponseType, "", 1)
		case strings.HasPrefix(arg, argSenderConstrain):
			args.variant.SenderConstrain = strings.Replace(arg, argSenderConstrain, "", 1)
		case strings.HasPrefix(arg, argOpenID):
			args.variant.OpenID = strings.Replace(arg, argOpenID, "", 1)
		case strings.HasPrefix(arg, argFAPIRequestMethod):
			args.variant.FAPIRequestMethod = strings.Replace(arg, argFAPIRequestMethod, "", 1)
		case strings.HasPrefix(arg, argFAPIProfile):
			args.variant.FAPIProfile = strings.Replace(arg, argFAPIProfile, "", 1)
		case strings.HasPrefix(arg, argFAPIResponseMode):
			args.variant.FAPIResponseMode = strings.Replace(arg, argFAPIResponseMode, "", 1)
		}
	}

	return args
}

// createTestPlan creates a test plan that will be used to run individual test
// modules.
func createTestPlan(
	name, configFile string,
	variant variant,
) (
	testPlan,
	error,
) {
	log.Printf("create test plan %s\n", name)

	csURL, _ := url.Parse(conformanceSuiteURL + "/api/plan")
	queryParams := csURL.Query()
	queryParams.Add("planName", name)
	queryParams.Add("variant", variant.String())
	csURL.RawQuery = queryParams.Encode()

	config, err := os.ReadFile(configFile)
	if err != nil {
		log.Printf("could not load the configuration file: %v\n", err)
		return testPlan{}, err
	}

	resp, err := httpClient.Post(
		csURL.String(),
		"application/json",
		bytes.NewBuffer(config),
	)
	if err != nil {
		log.Printf("could create the test plan %s due to: %v\n", name, err)
		return testPlan{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		log.Printf("POST /api/plan responded with status %d: %s\n", resp.StatusCode, string(b))
		return testPlan{}, errors.New("could not create the test plan")
	}

	var plan testPlan
	_ = json.NewDecoder(resp.Body).Decode(&plan)
	log.Printf("test plan %s was created with id %s\n", plan.Name, plan.ID)
	return plan, nil
}

// runTestModule runs a single test module from a test plan.
func runTestModule(name string, plan testPlan) error {
	testID, err := createTestModule(name, plan.ID)
	if err != nil {
		return err
	}

	var module testModule
	for {
		module, err = fetchTestModule(testID)
		if err != nil {
			return err
		}

		if !slices.Contains(
			[]testStatus{
				testStatusCreated,
				testStatusConfigured,
				testStatusWaiting,
				testStatusRunning,
			},
			module.Status,
		) {
			log.Printf("finished polling the test with status %s\n", module.Status)
			break
		}

		log.Printf("test status is %s, sleep for 1 second\n", module.Status)
		time.Sleep(1 * time.Second)
	}

	if !slices.Contains([]testResult{testResultPassed, testResultReview}, module.Result) {
		log.Printf("test module with id %s failed with result as %s\n", module.ID, module.Result)
		return fmt.Errorf("test module %s with id %s resulted in %s", module.Name, module.ID, module.Result)
	}

	log.Printf("test module %s with id %s resulted in %s\n", module.Name, module.ID, module.Result)
	return nil
}

// createTestModule creates a test module from a test plan.
func createTestModule(name string, planID string) (string, error) {
	log.Printf("create test module %s for test plan id %s\n", name, planID)

	csURL, _ := url.Parse(conformanceSuiteURL + "/api/runner")
	queryParams := csURL.Query()
	queryParams.Add("test", name)
	queryParams.Add("plan", planID)
	csURL.RawQuery = queryParams.Encode()

	resp, err := httpClient.Post(csURL.String(), "application/json", nil)
	if err != nil {
		log.Printf("error creating the test module %s: %v\n", name, err)
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		log.Printf("POST /api/runner/ responded with status %d: %s\n", resp.StatusCode, string(b))
		return "", errors.New("could not create the test module")
	}

	var testModule struct {
		ID string `json:"id"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&testModule)
	log.Printf("test with id %s created\n", testModule.ID)
	return testModule.ID, nil
}

// fetchTestModule fetches information about a running test module.
func fetchTestModule(id string) (testModule, error) {
	csURL := fmt.Sprintf("%s/api/info/%s", conformanceSuiteURL, id)
	resp, err := httpClient.Get(csURL)
	if err != nil {
		log.Printf("error fetching the test module with id %s: %v\n", id, err)
		return testModule{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		log.Printf("GET /api/runner/{id} responded with status %d: %s\n", resp.StatusCode, string(b))
		return testModule{}, errors.New("could not fetch the test module")
	}

	var module testModule
	_ = json.NewDecoder(resp.Body).Decode(&module)
	return module, nil
}

// downloadTestPlanLogs fetches the test plan logs html in zip format and
// creates a file to store it.
// If an error happens it just aborts the execution.
func downloadTestPlanLogs(planID string) {
	csURL := fmt.Sprintf("%s/api/plan/exporthtml/%s", conformanceSuiteURL, planID)
	resp, err := httpClient.Get(csURL)
	if err != nil {
		log.Printf("error fetching logs for test plan with id %s: %v\n", planID, err)
		return
	}
	defer resp.Body.Close()

	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		log.Printf("GET /api/plan/export/{id} responded with status %d: %s\n", resp.StatusCode, string(b))
		return
	}

	// The conformance suite sends the file name in the header Content-Disposition.
	re := regexp.MustCompile(`filename="(.+)"`)
	fileName := re.FindStringSubmatch(resp.Header.Get("Content-Disposition"))[1]
	log.Println(fileName)
	if err := os.WriteFile(fileName, b, 0644); err != nil {
		log.Printf("could not write test logs for test plan %s\n", planID)
	}
}
