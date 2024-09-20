// Test runner will be given a test plan and a list of test modules that it will
// run against the conformance suite and output their results.
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

	// If the run all modules flag was informed, consider all available modules
	// in the test plan.
	if args.runAllTestModules {
		var modules []string
		for _, m := range plan.TestModules {
			modules = append(modules, m.Name)
		}
		args.testModuleNames = modules
	}

	var testErrs []error
	for _, module := range args.testModuleNames {
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
	argRunAllTestModules string = "--all-modules"
	argConfigFile        string = "--config="
	argResponseType      string = "--response_type="
)

type testStatus string

const (
	testStatusCreated  = "CREATED"
	testStatusWaiting  = "WAITING"
	testStatusRunning  = "RUNNING"
	testStatusFinished = "FINISHED"
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
	testPlanName      string
	runAllTestModules bool
	testModuleNames   []string
	variant           variant
	configFile        string
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
}

func (v variant) String() string {
	b, _ := json.Marshal(v)
	return string(b)
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
			args.testModuleNames = strings.Split(
				strings.Replace(arg, argTestModuleNames, "", 1),
				",",
			)
		case strings.HasPrefix(arg, argRunAllTestModules):
			args.runAllTestModules = true
		case strings.HasPrefix(arg, argConfigFile):
			args.configFile = strings.Replace(arg, argConfigFile, "", 1)
		case strings.HasPrefix(arg, argResponseType):
			args.variant.ResponseType = strings.Replace(arg, argResponseType, "", 1)
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
		log.Printf("test module with id %s failed\n", module.ID)
		return fmt.Errorf("test module with id %s resulted in %s", module.ID, module.Result)
	}

	log.Printf("test module with id %s resulted in %s\n", module.ID, module.Result)
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
