package directory

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/mikenorgate/router-policy-agent/internal/policy"
)

const (
	fixtureBase    = "dc=example,dc=test"
	fixtureMAC     = "02:00:00:00:00:01"
	fixtureUserDN  = "cn=" + fixtureMAC + ",ou=users," + fixtureBase
	fixtureGroupDN = "cn=untrusted-placement,ou=groups," + fixtureBase
)

var fixtureTime = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

type searchFunc func(*ldap.SearchRequest) (*ldap.SearchResult, error)

func (f searchFunc) Search(request *ldap.SearchRequest) (*ldap.SearchResult, error) {
	return f(request)
}

func fixtureConfig() Config {
	return Config{URL: "ldaps://ldap.example.test:636", BaseDN: fixtureBase,
		Timeout: time.Second, PageSize: 2, MaximumDevices: 16, MaximumGroups: 16}
}

func fixtureReader(t *testing.T) *Reader {
	t.Helper()
	reader, err := New(fixtureConfig(), func(context.Context) (Credentials, error) {
		return Credentials{BindDN: "cn=reader,ou=users," + fixtureBase, Password: "synthetic-test-only"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return reader
}

func fixtureEntries() (groups, users []*ldap.Entry) {
	groups = []*ldap.Entry{ldap.NewEntry(fixtureGroupDN, map[string][]string{
		"uid": {"placement-id"}, "cn": {"untrusted-placement"},
		"objectClass": {"group", "goauthentik.io/ldap/group"}, "member": {fixtureUserDN},
		policy.Attribute: {`{"schema_version":1,"kind":"placement","vlan_role":"untrusted"}`},
	})}
	users = []*ldap.Entry{ldap.NewEntry(fixtureUserDN, map[string][]string{
		"uid": {"device-id"}, "cn": {fixtureMAC}, "ak-active": {"true"},
		"objectClass": {"user", "goauthentik.io/ldap/user"}, "memberOf": {fixtureGroupDN},
	})}
	return groups, users
}

func attribute(entry *ldap.Entry, name string) *ldap.EntryAttribute {
	for _, value := range entry.Attributes {
		if strings.EqualFold(value.Name, name) {
			return value
		}
	}
	return nil
}

func completeResponse(entries []*ldap.Entry) *ldap.SearchResult {
	return &ldap.SearchResult{Entries: entries, Controls: []ldap.Control{ldap.NewControlPaging(2)}}
}

func fixtureSearch(t *testing.T, groups, users []*ldap.Entry) searchFunc {
	t.Helper()
	return func(request *ldap.SearchRequest) (*ldap.SearchResult, error) {
		if request.Scope != ldap.ScopeSingleLevel || request.DerefAliases != ldap.NeverDerefAliases ||
			request.Filter != "(objectClass=*)" || !request.EnforceSizeLimit || request.SizeLimit != 17 ||
			len(request.Controls) != 1 {
			t.Error("search exceeded fixed read-only contract")
		}
		control, ok := request.Controls[0].(*ldap.ControlString)
		if !ok || !control.Criticality || control.ControlType != ldap.ControlTypePaging {
			t.Error("paging is not critical")
		}
		if request.BaseDN == "ou=groups,"+fixtureBase {
			if !slices.Contains(request.Attributes, policy.Attribute) {
				t.Error("original group policy not requested")
			}
			return completeResponse(groups), nil
		}
		if request.BaseDN != "ou=users,"+fixtureBase || slices.Contains(request.Attributes, policy.Attribute) {
			t.Error("unexpected namespace or merged user policy requested")
		}
		return completeResponse(users), nil
	}
}

func TestCollectOriginalGroupsAndDirectMembership(t *testing.T) {
	groups, users := fixtureEntries()
	// An effective/merged user policy is ignored even if an upstream custom
	// attribute returns it despite the fixed projection.
	users[0].Attributes = append(users[0].Attributes,
		&ldap.EntryAttribute{Name: policy.Attribute, Values: []string{"not group policy"}})
	users = append(users, ldap.NewEntry("cn=human,ou=users,"+fixtureBase, map[string][]string{
		"uid": {"human-id"}, "cn": {"human"}, "objectClass": {"goauthentik.io/ldap/user"},
	}))
	users[0].Attributes = append(users[0].Attributes, &ldap.EntryAttribute{Name: "unrelated", Values: []string{"ignored"}})
	attribute(users[0], "memberOf").Values = append(attribute(users[0], "memberOf").Values,
		"cn="+fixtureMAC+",ou=virtual-groups,"+fixtureBase)
	reader := fixtureReader(t)
	snapshot, err := reader.collect(t.Context(), fixtureSearch(t, groups, users), fixtureTime)
	if err != nil {
		t.Fatal(err)
	}
	if !snapshot.Complete || !snapshot.ObservedAt.Equal(fixtureTime) || len(snapshot.Groups) != 1 ||
		len(snapshot.Devices) != 1 || snapshot.Groups[0].ID != "placement-id" ||
		snapshot.Groups[0].Policy == nil || !snapshot.Groups[0].IsNetwork ||
		!reflect.DeepEqual(snapshot.Devices[0].GroupIDs, []string{"placement-id"}) {
		t.Fatalf("unexpected typed snapshot: %+v", snapshot)
	}
}

func TestCollectRejectsAmbiguousOrIncompleteEntries(t *testing.T) {
	tests := []struct {
		name   string
		change func([]*ldap.Entry, []*ldap.Entry) ([]*ldap.Entry, []*ldap.Entry)
	}{
		{"missing active flag", func(g, u []*ldap.Entry) ([]*ldap.Entry, []*ldap.Entry) {
			attribute(u[0], "ak-active").Values = nil
			return g, u
		}},
		{"invalid active flag", func(g, u []*ldap.Entry) ([]*ldap.Entry, []*ldap.Entry) {
			attribute(u[0], "ak-active").Values = []string{"yes"}
			return g, u
		}},
		{"duplicate active flag", func(g, u []*ldap.Entry) ([]*ldap.Entry, []*ldap.Entry) {
			attribute(u[0], "ak-active").Values = []string{"true", "false"}
			return g, u
		}},
		{"duplicate attribute spelling", func(g, u []*ldap.Entry) ([]*ldap.Entry, []*ldap.Entry) {
			u[0].Attributes = append(u[0].Attributes, &ldap.EntryAttribute{Name: "UID", Values: []string{"shadow"}})
			return g, u
		}},
		{"attribute options", func(g, u []*ldap.Entry) ([]*ldap.Entry, []*ldap.Entry) {
			attribute(u[0], "uid").Name = "uid;binary"
			return g, u
		}},
		{"uid collision", func(g, u []*ldap.Entry) ([]*ldap.Entry, []*ldap.Entry) {
			other := ldap.NewEntry("cn=human,ou=users,"+fixtureBase, map[string][]string{"uid": {"device-id"}, "cn": {"human"}, "objectClass": {"goauthentik.io/ldap/user"}})
			return g, append(u, other)
		}},
		{"group uid collision", func(g, u []*ldap.Entry) ([]*ldap.Entry, []*ldap.Entry) {
			other := ldap.NewEntry("cn=other,ou=groups,"+fixtureBase, map[string][]string{"uid": {"placement-id"}, "cn": {"other"}, "objectClass": {"goauthentik.io/ldap/group"}})
			return append(g, other), u
		}},
		{"wrong namespace", func(g, u []*ldap.Entry) ([]*ldap.Entry, []*ldap.Entry) {
			u[0].DN = "cn=" + fixtureMAC + ",ou=foreign," + fixtureBase
			return g, u
		}},
		{"cn does not match dn", func(g, u []*ldap.Entry) ([]*ldap.Entry, []*ldap.Entry) {
			attribute(u[0], "cn").Values = []string{"02:00:00:00:00:02"}
			return g, u
		}},
		{"group missing reverse member", func(g, u []*ldap.Entry) ([]*ldap.Entry, []*ldap.Entry) {
			attribute(g[0], "member").Values = nil
			return g, u
		}},
		{"user missing reverse membership", func(g, u []*ldap.Entry) ([]*ldap.Entry, []*ldap.Entry) {
			attribute(u[0], "memberOf").Values = nil
			return g, u
		}},
		{"dangling member", func(g, u []*ldap.Entry) ([]*ldap.Entry, []*ldap.Entry) {
			attribute(g[0], "member").Values = append(attribute(g[0], "member").Values, "cn=absent,ou=users,"+fixtureBase)
			return g, u
		}},
		{"unknown group", func(g, u []*ldap.Entry) ([]*ldap.Entry, []*ldap.Entry) {
			attribute(u[0], "memberOf").Values = []string{"cn=absent,ou=groups," + fixtureBase}
			return g, u
		}},
		{"duplicate membership", func(g, u []*ldap.Entry) ([]*ldap.Entry, []*ldap.Entry) {
			attribute(u[0], "memberOf").Values = []string{fixtureGroupDN, strings.ToUpper(fixtureGroupDN)}
			return g, u
		}},
		{"duplicate entry dn", func(g, u []*ldap.Entry) ([]*ldap.Entry, []*ldap.Entry) { return append(g, g[0]), u }},
		{"unexpected object class", func(g, u []*ldap.Entry) ([]*ldap.Entry, []*ldap.Entry) {
			attribute(g[0], "objectClass").Values = []string{"group"}
			return g, u
		}},
		{"policy multi-value", func(g, u []*ldap.Entry) ([]*ldap.Entry, []*ldap.Entry) {
			attribute(g[0], policy.Attribute).Values = []string{"{}", "{}"}
			return g, u
		}},
		{"policy oversized", func(g, u []*ldap.Entry) ([]*ldap.Entry, []*ldap.Entry) {
			attribute(g[0], policy.Attribute).Values = []string{strings.Repeat("x", policy.AttributeLimit+1)}
			return g, u
		}},
		{"policy invalid utf8", func(g, u []*ldap.Entry) ([]*ldap.Entry, []*ldap.Entry) {
			attribute(g[0], policy.Attribute).Values = []string{string([]byte{0xff})}
			return g, u
		}},
		{"foreign virtual group", func(g, u []*ldap.Entry) ([]*ldap.Entry, []*ldap.Entry) {
			attribute(u[0], "memberOf").Values = append(attribute(u[0], "memberOf").Values, "cn=other,ou=virtual-groups,"+fixtureBase)
			return g, u
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			groups, users := fixtureEntries()
			groups, users = test.change(groups, users)
			snapshot, err := fixtureReader(t).collect(t.Context(), fixtureSearch(t, groups, users), fixtureTime)
			if !errors.Is(err, ErrRead) || snapshot.Complete || snapshot.Devices != nil || snapshot.Groups != nil {
				t.Fatalf("ambiguous snapshot was returned: %+v, %v", snapshot, err)
			}
		})
	}
}

func TestInactiveAndMalformedNetworkGroupRemainCompilerInputs(t *testing.T) {
	groups, users := fixtureEntries()
	attribute(users[0], "ak-active").Values = []string{"false"}
	attribute(groups[0], policy.Attribute).Values = []string{"malformed JSON"}
	snapshot, err := fixtureReader(t).collect(t.Context(), fixtureSearch(t, groups, users), fixtureTime)
	if err != nil || snapshot.Devices[0].Active || *snapshot.Groups[0].Policy != "malformed JSON" {
		t.Fatalf("lost deny-relevant compiler input: %+v, %v", snapshot, err)
	}
	attribute(groups[0], policy.Attribute).Values = nil
	// A missing attribute (not an explicitly multi-valued/empty attribute) keeps
	// the reserved network-name marker for the compiler's missing-policy denial.
	groups[0].Attributes = slices.DeleteFunc(groups[0].Attributes, func(a *ldap.EntryAttribute) bool { return a.Name == policy.Attribute })
	snapshot, err = fixtureReader(t).collect(t.Context(), fixtureSearch(t, groups, users), fixtureTime)
	if err != nil || !snapshot.Groups[0].IsNetwork || snapshot.Groups[0].Policy != nil {
		t.Fatalf("missing network policy was erased: %+v, %v", snapshot, err)
	}
}

func TestNestedGroupsDoNotFlattenPolicy(t *testing.T) {
	groups, users := fixtureEntries()
	parentDN := "cn=untrusted-parent,ou=groups," + fixtureBase
	parent := ldap.NewEntry(parentDN, map[string][]string{"uid": {"parent-id"}, "cn": {"untrusted-parent"},
		"objectClass": {"goauthentik.io/ldap/group"}, "member": {fixtureGroupDN}, policy.Attribute: {"invalid parent policy"}})
	groups[0].Attributes = append(groups[0].Attributes, &ldap.EntryAttribute{Name: "memberOf", Values: []string{parentDN}})
	groups = append(groups, parent)
	reader := fixtureReader(t)
	snapshot, err := reader.collect(t.Context(), fixtureSearch(t, groups, users), fixtureTime)
	if err != nil || !reflect.DeepEqual(snapshot.Devices[0].GroupIDs, []string{"placement-id"}) {
		t.Fatalf("parent inherited: %+v, %v", snapshot, err)
	}
	attribute(users[0], "memberOf").Values = append(attribute(users[0], "memberOf").Values, parentDN)
	if snapshot, err := reader.collect(t.Context(), fixtureSearch(t, groups, users), fixtureTime); !errors.Is(err, ErrRead) || snapshot.Complete {
		t.Fatal("inconsistent inherited membership accepted")
	}
}

func TestPagingIsCompleteCriticalAndBounded(t *testing.T) {
	reader := fixtureReader(t)
	groups, _ := fixtureEntries()
	calls := 0
	client := searchFunc(func(request *ldap.SearchRequest) (*ldap.SearchResult, error) {
		control, ok := request.Controls[0].(*ldap.ControlString)
		if !ok || !control.Criticality {
			t.Fatal("noncritical paging")
		}
		decoded, err := ldap.DecodeControl(control.Encode())
		if err != nil {
			t.Fatal(err)
		}
		paging, ok := decoded.(*ldap.ControlPaging)
		if !ok || paging.PagingSize != 2 {
			t.Fatal("invalid paging")
		}
		calls++
		if calls == 1 {
			if len(paging.Cookie) != 0 {
				t.Fatal("first page has cookie")
			}
			control := ldap.NewControlPaging(2)
			control.SetCookie([]byte("synthetic-next"))
			return &ldap.SearchResult{Entries: groups, Controls: []ldap.Control{control}}, nil
		}
		if string(paging.Cookie) != "synthetic-next" {
			t.Fatal("continuation cookie missing")
		}
		return completeResponse(nil), nil
	})
	entries, err := reader.pages(t.Context(), client, "groups", 16)
	if err != nil || len(entries) != 1 || calls != 2 {
		t.Fatalf("paging: %d entries, %d calls, %v", len(entries), calls, err)
	}
	for _, name := range []string{"missing control", "duplicate control", "wrong control", "referral", "partial error", "repeated cookie", "oversized cookie", "oversized result", "nil response", "dependency panic"} {
		t.Run(name, func(t *testing.T) {
			client := searchFunc(func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
				response := completeResponse(nil)
				paging, ok := response.Controls[0].(*ldap.ControlPaging)
				if !ok {
					t.Fatal("broken fixture")
				}
				switch name {
				case "dependency panic":
					panic("synthetic private parser diagnostic")
				case "missing control":
					response.Controls = nil
				case "duplicate control":
					response.Controls = append(response.Controls, ldap.NewControlPaging(2))
				case "wrong control":
					response.Controls = []ldap.Control{ldap.NewControlString("unknown", false, "")}
				case "referral":
					response.Referrals = []string{"ldaps://other.example.test:636"}
				case "partial error":
					return completeResponse(groups), errors.New("private diagnostic must not escape")
				case "repeated cookie":
					paging.SetCookie([]byte("same"))
				case "oversized cookie":
					paging.SetCookie(make([]byte, 4097))
				case "oversized result":
					response.Entries = make([]*ldap.Entry, 17)
				case "nil response":
					return nil, nil
				}
				return response, nil
			})
			entries, err := reader.pages(t.Context(), client, "groups", 16)
			if !errors.Is(err, ErrRead) || entries != nil || strings.Contains(err.Error(), "private diagnostic") {
				t.Fatalf("partial paging escaped: %d, %v", len(entries), err)
			}
		})
	}
}

func TestEmptyDirectoryAndCancelledCollection(t *testing.T) {
	reader := fixtureReader(t)
	snapshot, err := reader.collect(t.Context(), fixtureSearch(t, nil, nil), fixtureTime)
	if err != nil || !snapshot.Complete || len(snapshot.Devices) != 0 || snapshot.Devices == nil || snapshot.Groups == nil {
		t.Fatalf("empty directory: %+v, %v", snapshot, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	snapshot, err = reader.collect(ctx, searchFunc(func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
		t.Error("search after cancellation")
		return nil, nil
	}), fixtureTime)
	if !errors.Is(err, ErrRead) || snapshot.Complete {
		t.Fatal("cancelled collection accepted")
	}
}
