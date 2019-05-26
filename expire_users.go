package main

import (
	"context"
	"fmt"
	"github.com/aws/aws-lambda-go/lambda"
	"os"
	"strconv"
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
}

func LambdaHandler(ctx context.Context, name Event) (string, error) {

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
