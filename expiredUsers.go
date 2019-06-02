package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/ses"
	"github.com/aws/aws-sdk-go/service/sns"
	"io"
	"os"
	"strconv"
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
	EXPLANATION_HEADER,
	expired_message, key_expired_message, key_warn_message, password_warn_message, email_subject string
var GRACE_PERIOD int

const (
	PASSWORD_ENABLED      int = 3
	USER                  int = 0
	PASSWORD_LAST_CHANGED int = 5
)

func main() {
	fmt.Println("Loading function")
	lambda.Start(expiredUsers)
}

type RequestParameters struct {
	UserName string `json:"userName"`
}

type ResponseElements struct {
	LoginProfile LoginProfile `json:"loginProfile"`
}

type LoginProfile struct {
	UserName string `json:"userName"`
}

type EventDetail struct {
	EventName         string            `json:"eventName"`
	RequestParameters RequestParameters `json:"requestParameters"`
	ResponseElements  ResponseElements  `json:"responseElements"`
}
type Event struct {
	Source string      `json:"source"`
	Detail EventDetail `json:"detail"`
}

func expiredUsers(ctx context.Context, event Event) (string, error) {

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

func process_IAMEvent(event Event, ctx context.Context, iam_client *iam.IAM) {
	api_call := event.Detail.EventName
	if api_call == "CreateLoginProfile" {
		process_CreateLoginProfile(event, ctx)
	} else if api_call == "EnableMFADevice" {
		process_EnableMFADevice(event, ctx)
	} else if api_call == "DeactivateMFADevice" {
		process_DeactivateMFADevice(event, ctx)
	} else {
		panic("Invalid API Call: " + api_call)
	}

}

func process_EnableMFADevice(event Event, ctx context.Context) {
	username := event.Detail.RequestParameters.UserName
	iam_client_session, sessionError := session.NewSession()
	checkError(sessionError)
	iam_client := iam.New(iam_client_session)
	response, _ := iam_client.ListMFADevices(&iam.ListMFADevicesInput{UserName: &username})
	if len(response.MFADevices) >= 1 {
		fmt.Println(username + " has activated their MFA. Removing from blackhole Group")
		remove_user_from_blackhole(username)
	} else {
		fmt.Println(username + " has no MFA. Adding to blackhole Group")
		add_user_to_blackhole(username, iam_client)
	}
	fmt.Println("EnableMFADevice Execution Complete")

}
func process_CreateLoginProfile(event Event, ctx context.Context) {
	username := event.Detail.ResponseElements.LoginProfile.UserName

	iam_client_session, sessionError := session.NewSession()
	checkError(sessionError)
	iam_client := iam.New(iam_client_session)
	response, _ := iam_client.ListMFADevices(&iam.ListMFADevicesInput{UserName: &username})
	if len(response.MFADevices) == 0 {
		fmt.Println(username + " does not have MFA. Adding to blackhole Group")
		add_user_to_blackhole(username, iam_client)
	} else {
		fmt.Println(username + " has an MFA. Removing from blackhole Group")
		remove_user_from_blackhole(username)
	}

	fmt.Println("CreateLoginProfile Execution Complete")

}
func process_DeactivateMFADevice(event Event, ctx context.Context) {
	username := event.Detail.RequestParameters.UserName
	iam_client_session, sessionError := session.NewSession()
	checkError(sessionError)
	iam_client := iam.New(iam_client_session)
	response, err := iam_client.ListMFADevices(&iam.ListMFADevicesInput{UserName: &username})
	if err != nil {
		fmt.Printf("%s no longer exists", username)
		return
	}

	if len(response.MFADevices) == 0 {
		fmt.Println(username + " does not have MFA. Adding to blackhole Group")
		add_user_to_blackhole(username, iam_client)
	} else {
		fmt.Println(username + " has an MFA. Removing from blackhole Group")
		remove_user_from_blackhole(username)
	}

}

func remove_user_from_blackhole(username string) {
	iam_client_session, sessionError := session.NewSession()
	checkError(sessionError)
	iam_client := iam.New(iam_client_session)
	_, err := iam_client.RemoveUserFromGroup(&iam.RemoveUserFromGroupInput{GroupName: &BLACKHOLE_GROUPNAME, UserName: &username})
	if err != nil {
		handle_error("Removing User from Blackhole Group", username, err.Error())
	}
}
func process_UsersCron(iam_client *iam.IAM) {
	max_age := get_max_password_age(iam_client)
	listAccountAliasesOutput, err := iam_client.ListAccountAliases(&iam.ListAccountAliasesInput{})
	checkErrorWithMessage(err, "")
	account_name := listAccountAliasesOutput.AccountAliases[0]

	credential_report := get_credential_report(iam_client)

	for _, row := range credential_report {
		if row.PasswordEnabled == "true" {
			continue
		}
		message := ""

		if is_user_expired(row.User) == 0 {
			password_expires := days_till_expire(row.PASSWORDLASTCHANGED, max_age)
			if password_expires <= 0 {
				REPORT_SUMMARY = REPORT_SUMMARY + fmt.Sprintf("\n%s's Password expired %d days ago", row.User, password_expires*-1)
				message = message + fmt.Sprintf(expired_message, password_expires*-1)
				add_user_to_blackhole(row.User, iam_client)

			} else if password_expires < GRACE_PERIOD {
				message = message + fmt.Sprintf(password_warn_message, password_expires)
				REPORT_SUMMARY = REPORT_SUMMARY + fmt.Sprintf("\n%s's Password Will expire in %d days", row.User, password_expires)

			}
		}

		response, err := iam_client.ListAccessKeys(&iam.ListAccessKeysInput{UserName: &row.User})
		if err != nil {
			continue
		}

		for _, key := range response.AccessKeyMetadata {
			if *key.Status == "Inactive" {
				continue
			}

			key_expires := days_till_expire(key.CreateDate.String(), max_age)

			if key_expires <= 0 {
				message = message + fmt.Sprintf(key_expired_message, key.AccessKeyId, key_expires*-1)
				disable_users_key(*key.AccessKeyId, row.User, iam_client)
				REPORT_SUMMARY = REPORT_SUMMARY + fmt.Sprintf("\n %s's Key %s expired %d days ago ", row.User, *key.AccessKeyId, key_expires*-1)

			} else if key_expires < GRACE_PERIOD {
				message = message + fmt.Sprintf(key_warn_message, key.AccessKeyId, key_expires)
				REPORT_SUMMARY = REPORT_SUMMARY + fmt.Sprintf("\n %s's Key %s will expire %d days from now ", row.User, *key.AccessKeyId, key_expires)

			}

		}

		if message != "" {
			email_user(row.User, message, *account_name)
		}

		fmt.Println("Action Summary:" + ACTION_SUMMARY)
		if ACTION_SUMMARY != "" {
			send_summary()
		}
		if REPORT_SUMMARY != "" {
			email_user(FROM_ADDRESS, REPORT_SUMMARY, *account_name)
		}

	}
}

func send_summary() {
	session, sessionError := session.NewSession()
	checkError(sessionError)
	client := sns.New(session)
	message := fmt.Sprintf("The following Actions were taken by the Expire Users Script at %s: ", time.Now().String()+ACTION_SUMMARY)
	subject := fmt.Sprintf("Expire Users Report for %d", time.Now().Day())
	_, _ = client.Publish(&sns.PublishInput{
		TopicArn: &ACTION_TOPIC_ARN,
		Message:  &message,
		Subject:  &subject,
	})
}
func email_user(email, message, account_name string) {
	if SEND_EMAIL != "true" {
		return
	}

	if message == "" {
		return
	}
	iam_client_session, sessionError := session.NewSession()
	checkError(sessionError)
	client := ses.New(iam_client_session)
	body := EXPLANATION_HEADER + "\n" + message + "\n\n" + EXPLANATION_FOOTER
	subject := fmt.Sprintf(email_subject, account_name)
	_, err := client.SendEmail(&ses.SendEmailInput{
		Source:      &FROM_ADDRESS,
		Destination: &ses.Destination{ToAddresses: []*string{&email}},
		Message: &ses.Message{
			Subject: &ses.Content{
				Data: &subject,
			},
			Body: &ses.Body{Text: &ses.Content{Data: &body}},
		},
	})
	if err != nil {
		fmt.Printf("Failed to send message to %s: %s", email, err.Error())
		ACTION_SUMMARY = ACTION_SUMMARY + fmt.Sprintf("\nERROR: Message to %s was rejected: %s", email, err.Error())
	}
	ACTION_SUMMARY = ACTION_SUMMARY + fmt.Sprintf("\nEmail Sent to %s", email)

}
func disable_users_key(AccessKeyId, UserName string, iam_client *iam.IAM) {
	if DISABLE_USERS != "true" {
		return
	}

	ACTION_SUMMARY = ACTION_SUMMARY + fmt.Sprintf("\nDisabling AccessKeyId %s for user %s", AccessKeyId, UserName)
	status := "Inactive"
	_, err := iam_client.UpdateAccessKey(&iam.UpdateAccessKeyInput{UserName: &UserName, AccessKeyId: &AccessKeyId, Status: &status})
	if err != nil {
		handle_error("Adding User to Blackhole Group", UserName, err.Error())
	}
}
func add_user_to_blackhole(username string, iam_client *iam.IAM) {
	if DISABLE_USERS != "true" {
		return
	}
	ACTION_SUMMARY = ACTION_SUMMARY + fmt.Sprintf("\nAdding %s to Blackhole Group", username)
	_, err := iam_client.AddUserToGroup(&iam.AddUserToGroupInput{GroupName: &BLACKHOLE_GROUPNAME, UserName: &username})
	if err != nil {
		handle_error("Removing User from Blackhole Group", username, err.Error())
	}

}

func days_till_expire(last_change string, max_age *int64) int {

	lastChanged, err := strconv.ParseInt(last_change, 10, 64)
	if err != nil {
		fmt.Println(err.Error())
		return -99999
	}

	expires := lastChanged + *max_age - time.Now().Unix()
	return time.Unix(expires, 0).Day()

}
func get_max_password_age(iam_client *iam.IAM) *int64 {
	response, getAccountPasswordPolicyError := iam_client.GetAccountPasswordPolicy(&iam.GetAccountPasswordPolicyInput{})
	if getAccountPasswordPolicyError != nil {
		fmt.Printf("Unexpected error in get_max_password_age: %s" + getAccountPasswordPolicyError.Error())
	}
	return response.PasswordPolicy.MaxPasswordAge
}
func init() {
	BLACKHOLE_GROUPNAME, ok := os.LookupEnv("BLACKHOLE_GROUPNAME")
	checkEnvError(ok, "BLACKHOLE_GROUPNAME")

	ACTION_TOPIC_ARN, ok = os.LookupEnv("ACTION_TOPIC_ARN")
	checkEnvError(ok, "ACTION_TOPIC_ARN")

	GRACE_PERIOD_STR, ok = os.LookupEnv("GRACE_PERIOD")
	checkEnvError(ok, "GRACE_PERIOD_STR")

	var parseError error
	GRACE_PERIOD, parseError = strconv.Atoi(GRACE_PERIOD_STR)
	if parseError != nil {
		fmt.Println("Key Error: " + parseError.Error())
		os.Exit(1)
	}

	DISABLE_USERS, ok = os.LookupEnv("DISABLE_USERS")
	checkEnvError(ok, "DISABLE_USERS")

	SEND_EMAIL, ok = os.LookupEnv("SEND_EMAIL")
	checkEnvError(ok, "SEND_EMAIL")

	FROM_ADDRESS, ok = os.LookupEnv("FROM_ADDRESS")
	checkEnvError(ok, "FROM_ADDRESS")

	EXPLANATION_FOOTER, ok = os.LookupEnv("EXPLANATION_FOOTER")
	checkEnvError(ok, "EXPLANATION_FOOTER")

	EXPLANATION_HEADER, ok = os.LookupEnv("EXPLANATION_HEADER")
	checkEnvError(ok, "EXPLANATION_HEADER")

	if DISABLE_USERS == "true" {
		expired_message = "\n\tYour Password is %d days post expiration. Your permissions have been revoked. "
		key_expired_message = "\n\tYour AccessKey ID %s is %s days post expiration. It has been deactivated. "
	} else {
		expired_message = "\n\tYour Password is %d days post expiration. You must change your password or risk losing access. "
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
func checkErrorWithMessage(err error, msg string) {
	if err != nil {
		fmt.Printf(msg, err.Error())
	}
}

func checkError(err error) {
	if err != nil {
		panic(err)
	}
}

func handle_error(action, username, ResponseMetadata string) {
	panic("ERROR" + action + " User: " + username + " Details: " + ResponseMetadata)
}

type CredentialReport struct {
	PasswordEnabled     string `json:"password_enabled"`
	User                string `json:"user"`
	PASSWORDLASTCHANGED string `json:"password_last_changed"`
}

func get_credential_report(iam_client *iam.IAM) []CredentialReport {
	resp1, err := iam_client.GenerateCredentialReport(&iam.GenerateCredentialReportInput{})
	checkError(err)
	if *resp1.State == "COMPLETE" {
		response, err := iam_client.GetCredentialReport(&iam.GetCredentialReportInput{})
		checkError(err)
		credential_report_csv := response.Content
		reader := csv.NewReader(bytes.NewReader(credential_report_csv))
		var credential_report []CredentialReport
		for {
			line, err := reader.Read()
			cr := CredentialReport{}
			if err == io.EOF {
				break
			} else if err != nil {
				checkError(err)
			}
			cr.PasswordEnabled = line[PASSWORD_ENABLED]
			cr.User = line[USER]

			cr.PASSWORDLASTCHANGED = line[PASSWORD_LAST_CHANGED]
			credential_report = append(credential_report, cr)
		}
		return credential_report
	} else {
		time.Sleep(2 * time.Second)
		return get_credential_report(iam_client)
	}
}

func is_user_expired(username string) int {
	iam_client_session, sessionError := session.NewSession()
	checkError(sessionError)
	iam_client := iam.New(iam_client_session)
	respone, err := iam_client.ListGroupsForUser(&iam.ListGroupsForUserInput{UserName: &username})
	if err != nil {
		return 1
	}
	for _, group := range respone.Groups {
		if *group.GroupName == BLACKHOLE_GROUPNAME {
			return 1
		}
	}
	return 0

}
