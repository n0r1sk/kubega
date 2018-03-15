/*
Copyright 2017 Mario Kleinsasser and Bernhard Rausch

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"crypto/tls"
	"encoding/json"
	"net/http"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
	gitlab "github.com/xanzy/go-gitlab"
)

// WebhookData is the golang representation of https://kubernetes.io/docs/admin/authentication/#webhook-token-authentication
type WebhookData struct {
	APIVersion string `json:"apiVersion,omitempty"`
	Kind       string `json:"kind,omitempty"`
	Spec       struct {
		Token string `json:"token,omitempty"`
	} `json:"spec"`
	Status struct {
		Authenticated bool `json:"authenticated,omitempty"`
		User          struct {
			Username string   `json:"username,omitempty"`
			UID      string   `json:"uid,omitempty"`
			Groups   []string `json:"groups,omitempty"`
			Extra    struct {
				Extrafield1 []string `json:"extrafield1,omitempty"`
			} `json:"extra,omitempty"`
		} `json:"user,omitempty"`
	} `json:"status,omitempty"`
}

func main() {

	gitlabapiendpoint := os.Getenv("GITLAB_API_ENDPOINT")

	if gitlabapiendpoint == "" {
		log.Fatal("Cannot start Webhook handler, environment variable GITLAB_API_ENDPOINT not set")
	}

	// configure logrus logger
	customFormatter := new(log.TextFormatter)
	customFormatter.TimestampFormat = "2006-01-02 15:04:05"
	customFormatter.FullTimestamp = true
	customFormatter.ForceColors = true
	log.SetFormatter(customFormatter)
	log.SetOutput(os.Stdout)

	log.Info("Gitlab Authn Webhook:", os.Getenv("GITLAB_API_ENDPOINT"))
	http.HandleFunc("/authenticate", func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		var tr WebhookData
		err := decoder.Decode(&tr)
		if err != nil {
			log.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			var res WebhookData
			res.APIVersion = "authentication.k8s.io/v1beta1"
			res.Kind = "TokenReview"
			res.Status.Authenticated = false
			json.NewEncoder(w).Encode(res)

			return
		}

		ht := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		htclient := &http.Client{Transport: ht}

		log.Debug(tr.Spec.Token)
		client := gitlab.NewClient(htclient, tr.Spec.Token)
		client.SetBaseURL(os.Getenv("GITLAB_API_ENDPOINT"))

		// User data
		client.Users.CurrentUser()
		user, _, err := client.Users.CurrentUser()

		if err != nil {
			log.Error(err)
			w.WriteHeader(http.StatusUnauthorized)
			var res WebhookData
			res.APIVersion = "authentication.k8s.io/v1beta1"
			res.Kind = "TokenReview"
			res.Status.Authenticated = false
			json.NewEncoder(w).Encode(res)

			return
		}

		// Group data
		groups, _, err := client.Groups.ListGroups(nil)
		if err != nil {
			log.Error(err)
			w.WriteHeader(http.StatusUnauthorized)
			var res WebhookData
			res.APIVersion = "authentication.k8s.io/v1beta1"
			res.Kind = "TokenReview"
			res.Status.Authenticated = false
			json.NewEncoder(w).Encode(res)
			return
		}

		allgrouppath := make([]string, len(groups))
		for i, g := range groups {
			allgrouppath[i] = strings.ToLower(g.Path)
		}

		// TokenReviewStatus
		username := strings.ToLower(user.Username)
		log.Info("Login as:")
		log.Info(username)
		log.Info("With groups:")
		log.Info(allgrouppath)
		w.WriteHeader(http.StatusOK)

		var trs WebhookData
		trs.APIVersion = "authentication.k8s.io/v1beta1"
		trs.Kind = "TokenReview"
		trs.Status.Authenticated = true
		trs.Status.User.Username = username
		trs.Status.User.UID = username
		trs.Status.User.Groups = allgrouppath
		json.NewEncoder(w).Encode(trs)

	})

	log.Fatal(http.ListenAndServe(":3000", nil))

}
