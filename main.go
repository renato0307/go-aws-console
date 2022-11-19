package main

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/renato0307/go-aws-console/browser"
)

const FederationURL = "https://signin.aws.amazon.com/federation"
const ConsoleURL = "https://console.aws.amazon.com/"
const Issuer = "IssuedGoAWSConsole"

type signinTokenCredentials struct {
	SessionID    string `json:"sessionId"`
	SessionKey   string `json:"sessionKey"`
	SessionToken string `json:"sessionToken"`
}

type signinTokenRes struct {
	SigninToken string `json:"SigninToken"`
}

func getSigninToken(creds credentials.Value) (*signinTokenRes, error) {
	cred := signinTokenCredentials{
		SessionID:    creds.AccessKeyID,
		SessionKey:   creds.SecretAccessKey,
		SessionToken: creds.SessionToken,
	}
	credJSON, err := json.Marshal(cred)
	if err != nil {
		return new(signinTokenRes), err
	}

	u, _ := url.Parse(FederationURL)
	q := u.Query()
	q.Set("Action", "getSigninToken")
	q.Set("SessionDuration", strconv.Itoa(1800))
	q.Set("Session", string(credJSON))
	u.RawQuery = q.Encode()

	resp, err := http.Get(u.String())
	if err != nil {
		return new(signinTokenRes), err
	}
	defer resp.Body.Close()

	byteBody, _ := ioutil.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return new(signinTokenRes), errors.New(string(byteBody))
	}

	signinTokenResponse := new(signinTokenRes)
	err = json.Unmarshal(byteBody, signinTokenResponse)
	if err != nil {
		return new(signinTokenRes), err
	}

	return signinTokenResponse, nil
}

func buildLoginURL(r *signinTokenRes) (string, error) {
	u, _ := url.Parse(FederationURL)
	q := u.Query()
	q.Set("Action", "login")
	q.Set("Issuer", Issuer)
	q.Set("Destination", ConsoleURL)
	q.Set("SigninToken", r.SigninToken)
	u.RawQuery = q.Encode()

	return u.String(), nil
}

func createLoginURL(creds credentials.Value) (string, error) {
	signinTokenResponse, err := getSigninToken(creds)
	if err != nil {
		return "", err
	}

	return buildLoginURL(signinTokenResponse)
}

func main() {
	profile := os.Args[1]
	region := os.Args[2]
	log.Printf("profile: %s\n", profile)
	log.Printf("region: %s\n", region)

	o := session.Options{Profile: profile, Config: aws.Config{Region: &region}}
	session := session.Must(session.NewSessionWithOptions(o))
	creds, _ := session.Config.Credentials.Get()

	loginUrl, err := createLoginURL(creds)
	if err != nil {
		log.Fatalf("could not get login url: %s", err)
	}

	browser.Open("https://signin.aws.amazon.com/oauth?Action=logout")
	browser.Open(loginUrl)
}
