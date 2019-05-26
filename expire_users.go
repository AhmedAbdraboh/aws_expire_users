package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)
var BLACKHOLE_GROUPNAME,
	ACTION_TOPIC_ARN,
	GRACE_PERIOD_STR,
	DISABLE_USERS,
	SEND_EMAIL,
	FROM_ADDRESS,
	EXPLANATION_FOOTER,
	ACTION_SUMMARY,
	REPORT_SUMMARY,
	expired_message, key_expired_message, key_warn_message, password_warn_message, email_subject string
var GRACE_PERIOD int

func main() {
	fmt.Println("Loading function")
	lambda.Start(LambdaHandler)
}

type Event struct {
	Source string `json:"source"`

}

func LambdaHandler(ctx context.Context, event Event) (string, error) {

	eventMarshal, marshalError := json.Marshal(event)
	checkError(marshalError)
	fmt.Printf("Received event: " + string(eventMarshal))
	iam_client_session, sessionError := session.NewSession()
	checkError(sessionError)
	iam_client := iam.New(iam_client_session)
	if event.Source == "aws.iam" {
		process_IAMEvent(event, ctx, iam_client)
	} else {
		process_UsersCron(iam_client)
	}

	return "", nil

}

func process_IAMEvent(event Event, ctx context.Context, iam_client *iam.IAM)  {
	
}

func process_UsersCron(iam_client *iam.IAM) {
	max_age := get_max_password_age(iam_client)
	listAccountAliasesOutput, err :=  iam_client.ListAccountAliases(&iam.ListAccountAliasesInput{})
	checkErrorWithMessage(err, "")
	account_name := listAccountAliasesOutput.AccountAliases[0]

	credential_report := get_credential_report(iam_client)
}

func get_max_password_age(iam_client *iam.IAM) *int64 {
	response, getAccountPasswordPolicyError := iam_client.GetAccountPasswordPolicy(&iam.GetAccountPasswordPolicyInput{})
	if getAccountPasswordPolicyError != nil {
		fmt.Printf("Unexpected error in get_max_password_age: %s" + getAccountPasswordPolicyError.Error())
	}
	return response.PasswordPolicy.MaxPasswordAge
}
func init()  {
	BLACKHOLE_GROUPNAME, ok := os.LookupEnv("BLACKHOLE_GROUPNAME")
	checkEnvError(ok, BLACKHOLE_GROUPNAME)

	ACTION_TOPIC_ARN, ok := os.LookupEnv("ACTION_TOPIC_ARN")
	checkEnvError(ok, ACTION_TOPIC_ARN)

	GRACE_PERIOD_STR, ok := os.LookupEnv("GRACE_PERIOD")
	checkEnvError(ok, GRACE_PERIOD_STR)

	GRACE_PERIOD, parseError := strconv.Atoi(GRACE_PERIOD_STR)
	if parseError != nil {
		fmt.Println("Key Error: " + parseError.Error())
		os.Exit(1)
	}

	DISABLE_USERS, ok := os.LookupEnv("DISABLE_USERS")
	checkEnvError(ok, DISABLE_USERS)

	SEND_EMAIL, ok := os.LookupEnv("SEND_EMAIL")
	checkEnvError(ok, SEND_EMAIL)

	FROM_ADDRESS, ok := os.LookupEnv("FROM_ADDRESS")
	checkEnvError(ok, FROM_ADDRESS)

	EXPLANATION_FOOTER, ok := os.LookupEnv("EXPLANATION_FOOTER")
	checkEnvError(ok, EXPLANATION_FOOTER)

	EXPLANATION_HEADER, ok := os.LookupEnv("EXPLANATION_HEADER")
	checkEnvError(ok, EXPLANATION_HEADER)


	if DISABLE_USERS == "true" {
		expired_message = "\n\tYour Password is %s days post expiration. Your permissions have been revoked. "
		key_expired_message = "\n\tYour AccessKey ID %s is %s days post expiration. It has been deactivated. "
	} else {
		expired_message = "\n\tYour Password is %s days post expiration. You must change your password or risk losing access. "
		key_expired_message = "\n\tYour AccessKey ID %s is %s days post expiration. You must rotate this key or it will be deactivated. "
	}

	key_warn_message = "\n\tYour AccessKey ID %s is %s days from expiration. You must rotate this key or it will be deactivated. "
	password_warn_message = "\n\tYour Password will expire in %s days"

	email_subject = "Credential Expiration Notice From AWS Account: %s"

}
func checkEnvError(ok bool, key string) {
	if !ok {
		fmt.Println("Key Error: " + key + "not found in env")
		os.Exit(1)
	}
}
func checkErrorWithMessage(err error, msg string)  {
	if err != nil {
		fmt.Printf(msg, err.Error())
	}
}

func checkError(err error) {
	if err != nil {
		panic(err)
	}
}

func get_credential_report(iam_client *iam.IAM) []interface{} {
	resp1, err := iam_client.GenerateCredentialReport(&iam.GenerateCredentialReportInput{})
	checkError(err)
	if *resp1.State  == "COMPLETE" {
		response, err := iam_client.GetCredentialReport(&iam.GetCredentialReportInput{})
		checkError(err)
		credential_report_csv := response.Content
		reader := csv.NewReader(bytes.NewReader(credential_report_csv))
		var credential_report []interface{}
		for {
			line, err := reader.Read()
			if err == io.EOF {
				break
			} else if err != nil {
				checkError(err)
			}
			credential_report = append(credential_report, line)
		}
		return credential_report
	} else {
		time.Sleep(2 * time.Second)
		return get_credential_report(iam_client)
	}
}
