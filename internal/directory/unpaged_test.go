package directory

import (
	"errors"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

func TestLDAPBooleanSpellings(t *testing.T) {
	for _, value := range []string{"true", "false", "TRUE", "FALSE"} {
		t.Run(value, func(t *testing.T) {
			groups, users := fixtureEntries()
			attribute(users[0], "ak-active").Values = []string{value}
			snapshot, err := fixtureReader(t).collect(t.Context(), fixtureSearch(t, groups, users), fixtureTime)
			if err != nil || len(snapshot.Devices) != 1 || snapshot.Devices[0].Active != (value == "true" || value == "TRUE") {
				t.Fatal("valid LDAP boolean was rejected or misinterpreted")
			}
		})
	}
	for _, value := range []string{"True", "False", "1", "0", " true", "TRUE "} {
		groups, users := fixtureEntries()
		attribute(users[0], "ak-active").Values = []string{value}
		if snapshot, err := fixtureReader(t).collect(t.Context(), fixtureSearch(t, groups, users), fixtureTime); !errors.Is(err, ErrRead) || snapshot.Complete {
			t.Fatal("non-LDAP boolean accepted")
		}
	}
}

func TestBoundedUnpagedCollection(t *testing.T) {
	reader := fixtureReader(t)
	reader.config.Unpaged = true
	groups, users := fixtureEntries()
	calls := 0
	client := searchFunc(func(request *ldap.SearchRequest) (*ldap.SearchResult, error) {
		calls++
		if len(request.Controls) != 0 || !request.EnforceSizeLimit || request.SizeLimit != 17 ||
			request.Scope != ldap.ScopeSingleLevel || request.DerefAliases != ldap.NeverDerefAliases {
			t.Fatal("unpaged search lost its fixed bounds")
		}
		entries := users
		if request.BaseDN == "ou=groups,"+fixtureBase {
			entries = groups
		}
		return &ldap.SearchResult{Entries: entries}, nil
	})
	snapshot, err := reader.collect(t.Context(), client, fixtureTime)
	if err != nil || !snapshot.Complete || len(snapshot.Devices) != 1 || calls != 2 {
		t.Fatal("complete bounded unpaged collection failed")
	}
	for _, name := range []string{"partial error", "control", "referral", "oversized", "duplicate", "nil entry", "nil response"} {
		t.Run(name, func(t *testing.T) {
			client := searchFunc(func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
				response := &ldap.SearchResult{Entries: groups}
				switch name {
				case "partial error":
					return response, &ldap.Error{ResultCode: ldap.LDAPResultSizeLimitExceeded}
				case "control":
					response.Controls = []ldap.Control{ldap.NewControlPaging(2)}
				case "referral":
					response.Referrals = []string{"ldaps://other.example.test:636"}
				case "oversized":
					response.Entries = make([]*ldap.Entry, 17)
				case "duplicate":
					response.Entries = append(response.Entries, groups[0])
				case "nil entry":
					response.Entries = []*ldap.Entry{nil}
				case "nil response":
					return nil, nil
				}
				return response, nil
			})
			entries, err := reader.pages(t.Context(), client, "groups", 16)
			if !errors.Is(err, ErrRead) || entries != nil {
				t.Fatal("partial or ambiguous collection accepted")
			}
		})
	}
}
