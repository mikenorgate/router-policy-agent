package directory

import (
	"context"
	"encoding/json"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/go-ldap/ldap/v3"
	"github.com/mikenorgate/router-policy-agent/internal/policy"
)

var stableID = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$`)

type groupEntry struct {
	group   policy.Group
	dn      string
	members map[string]bool
	parents map[string]bool
}

func (r *Reader) collect(ctx context.Context, client searcher, observed time.Time) (policy.DirectorySnapshot, error) {
	groups, err := r.pages(ctx, client, "groups", r.config.MaximumGroups)
	if err != nil {
		return policy.DirectorySnapshot{}, ErrRead
	}
	users, err := r.pages(ctx, client, "users", r.config.MaximumDevices)
	if err != nil {
		return policy.DirectorySnapshot{}, ErrRead
	}
	snapshot := policy.DirectorySnapshot{
		ObservedAt: observed, Complete: true,
		Groups: []policy.Group{}, Devices: []policy.Device{},
	}
	byDN := map[string]groupEntry{}
	groupIDs := map[string]bool{}
	for _, entry := range groups {
		group, err := r.group(entry)
		if err != nil || groupIDs[group.group.ID] {
			return policy.DirectorySnapshot{}, ErrRead
		}
		byDN[group.dn], groupIDs[group.group.ID] = group, true
		snapshot.Groups = append(snapshot.Groups, group.group)
	}
	if err := completeMemberships(byDN, users); err != nil {
		return policy.DirectorySnapshot{}, ErrRead
	}
	deviceIDs, macs := map[string]bool{}, map[string]bool{}
	for _, entry := range users {
		if err := ctx.Err(); err != nil {
			return policy.DirectorySnapshot{}, readError(ctx)
		}
		attributes, attrErr := checkedAttributes(entry)
		id, idOK := single(attributes, "uid")
		if attrErr != nil || !idOK || deviceIDs[id] {
			return policy.DirectorySnapshot{}, ErrRead
		}
		deviceIDs[id] = true
		device, isDevice, err := r.device(entry, byDN)
		if err != nil {
			return policy.DirectorySnapshot{}, ErrRead
		}
		if !isDevice {
			continue
		}
		if macs[device.MAC] {
			return policy.DirectorySnapshot{}, ErrRead
		}
		macs[device.MAC] = true
		snapshot.Devices = append(snapshot.Devices, device)
	}
	slices.SortFunc(snapshot.Groups, func(a, b policy.Group) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(snapshot.Devices, func(a, b policy.Device) int { return strings.Compare(a.ID, b.ID) })
	encoded, err := json.Marshal(snapshot)
	if err != nil || len(encoded) > 16<<20 || ctx.Err() != nil {
		return policy.DirectorySnapshot{}, readError(ctx)
	}
	return snapshot, nil
}

func (r *Reader) pages(ctx context.Context, client searcher, unit string, maximum int) ([]*ldap.Entry, error) {
	attributes := []string{"uid", "cn", "objectClass", "ak-active", "memberOf"}
	if unit == "groups" {
		attributes = []string{"uid", "cn", "objectClass", "member", "memberOf", policy.Attribute}
	}
	result := []*ldap.Entry{}
	seenEntries, cookies := map[string]bool{}, map[string]bool{}
	page := ldap.NewControlPaging(r.config.PageSize)
	// Empty intermediate pages are permitted, but cannot create an endless read.
	for range maximum + 1 {
		if err := ctx.Err(); err != nil {
			return nil, readError(ctx)
		}
		request := ldap.NewSearchRequest(
			"ou="+unit+","+r.config.BaseDN,
			ldap.ScopeSingleLevel,
			ldap.NeverDerefAliases,
			maximum+1,
			max(1, int(r.config.Timeout/time.Second)),
			false,
			"(objectClass=*)",
			attributes,
			[]ldap.Control{criticalPage(page)},
		)
		request.EnforceSizeLimit = true
		response, err := safeSearch(client, request)
		if err != nil || response == nil || len(response.Referrals) != 0 {
			return nil, ErrRead
		}
		if len(response.Entries) > maximum-len(result) {
			return nil, ErrRead
		}
		for _, entry := range response.Entries {
			if entry == nil {
				return nil, ErrRead
			}
			dn, err := canonicalDN(entry.DN)
			if err != nil || seenEntries[dn] {
				return nil, ErrRead
			}
			seenEntries[dn] = true
			result = append(result, entry)
		}
		var returned *ldap.ControlPaging
		for _, control := range response.Controls {
			paging, ok := control.(*ldap.ControlPaging)
			if !ok || paging == nil || returned != nil {
				return nil, ErrRead
			}
			returned = paging
		}
		if returned == nil || len(returned.Cookie) > 4096 {
			return nil, ErrRead
		}
		if len(returned.Cookie) == 0 {
			return result, nil
		}
		cookie := string(returned.Cookie)
		if cookies[cookie] {
			return nil, ErrRead
		}
		cookies[cookie] = true
		page.SetCookie(slices.Clone(returned.Cookie))
	}
	return nil, ErrRead
}

// criticalPage retains the library's paging encoding but requires the server
// to reject an unsupported control rather than silently return an unpaged view.
func criticalPage(page *ldap.ControlPaging) ldap.Control {
	encoded := page.Encode()
	return ldap.NewControlString(ldap.ControlTypePaging, true, encoded.Children[1].Data.String())
}

func (r *Reader) group(entry *ldap.Entry) (groupEntry, error) {
	attributes, err := checkedAttributes(entry)
	if err != nil || !slices.Contains(attributes["objectclass"], "goauthentik.io/ldap/group") {
		return groupEntry{}, ErrRead
	}
	id, idOK := single(attributes, "uid")
	name, nameOK := single(attributes, "cn")
	dn, err := r.entryDN(entry.DN, "groups", name)
	if err != nil || !idOK || !nameOK || !stableID.MatchString(id) || !validName(name) {
		return groupEntry{}, ErrRead
	}
	group := policy.Group{ID: id, Name: name, IsNetwork: networkName(name)}
	if values, exists := attributes[policy.Attribute]; exists {
		if len(values) != 1 || len(values[0]) > policy.AttributeLimit || !utf8.ValidString(values[0]) {
			return groupEntry{}, ErrRead
		}
		group.Policy, group.IsNetwork = &values[0], true
	}
	members := map[string]bool{}
	for _, raw := range attributes["member"] {
		member, err := canonicalDN(raw)
		if err != nil || members[member] {
			return groupEntry{}, ErrRead
		}
		members[member] = true
	}
	parents := map[string]bool{}
	for _, raw := range attributes["memberof"] {
		parent, err := canonicalDN(raw)
		if err != nil || parents[parent] {
			return groupEntry{}, ErrRead
		}
		parents[parent] = true
	}
	return groupEntry{group: group, dn: dn, members: members, parents: parents}, nil
}

// completeMemberships rejects dangling references and inconsistent nested-group
// edges. It does not flatten a parent into a device's direct policy membership.
func completeMemberships(groups map[string]groupEntry, users []*ldap.Entry) error {
	userEntries := map[string]bool{}
	for _, entry := range users {
		if entry == nil {
			return ErrRead
		}
		dn, err := canonicalDN(entry.DN)
		if err != nil || userEntries[dn] {
			return ErrRead
		}
		userEntries[dn] = true
	}
	for dn, group := range groups {
		for parentDN := range group.parents {
			parent, ok := groups[parentDN]
			if !ok || !parent.members[dn] {
				return ErrRead
			}
		}
		for memberDN := range group.members {
			if child, ok := groups[memberDN]; ok {
				if !child.parents[dn] {
					return ErrRead
				}
			} else if !userEntries[memberDN] {
				return ErrRead
			}
		}
	}
	return nil
}

func (r *Reader) device(entry *ldap.Entry, groups map[string]groupEntry) (policy.Device, bool, error) {
	attributes, err := checkedAttributes(entry)
	if err != nil || !slices.Contains(attributes["objectclass"], "goauthentik.io/ldap/user") {
		return policy.Device{}, false, ErrRead
	}
	id, idOK := single(attributes, "uid")
	name, nameOK := single(attributes, "cn")
	dn, err := r.entryDN(entry.DN, "users", name)
	if err != nil || !idOK || !nameOK || !stableID.MatchString(id) || !validName(name) {
		return policy.Device{}, false, ErrRead
	}
	mac, isDevice := macSubject(name)
	if !isDevice {
		// The provider may also expose human accounts. They are not MAC subjects.
		return policy.Device{}, false, nil
	}
	active, activeOK := single(attributes, "ak-active")
	if !activeOK || active != "true" && active != "false" {
		return policy.Device{}, false, ErrRead
	}
	device := policy.Device{ID: id, MAC: mac, Active: active == "true", GroupIDs: []string{}}
	memberships := map[string]bool{}
	for _, raw := range attributes["memberof"] {
		membership, err := canonicalDN(raw)
		if err != nil || memberships[membership] {
			return policy.Device{}, false, ErrRead
		}
		memberships[membership] = true
		if _, err := r.entryDN(raw, "virtual-groups", name); err == nil {
			continue
		}
		group, exists := groups[membership]
		if !exists || !group.members[dn] {
			// Inherited parent membership is not a direct policy contribution.
			return policy.Device{}, false, ErrRead
		}
		device.GroupIDs = append(device.GroupIDs, group.group.ID)
	}
	for groupDN, group := range groups {
		if group.members[dn] != memberships[groupDN] {
			// Omitting one membership must not authorize a subset of its groups.
			return policy.Device{}, false, ErrRead
		}
	}
	slices.Sort(device.GroupIDs)
	return device, true, nil
}

func macSubject(name string) (string, bool) {
	mac, err := policy.CanonicalMAC(name)
	return mac, err == nil
}

func (r *Reader) entryDN(raw, unit, name string) (string, error) {
	canonical, err := canonicalDN(raw)
	if err != nil {
		return "", ErrRead
	}
	dn, parseErr := ldap.ParseDN(raw)
	expected, baseErr := ldap.ParseDN("cn=" + ldap.EscapeDN(name) + ",ou=" + unit + "," + r.config.BaseDN)
	if parseErr != nil || baseErr != nil || !expected.EqualFold(dn) {
		return "", ErrRead
	}
	return canonical, nil
}

func checkedAttributes(entry *ldap.Entry) (map[string][]string, error) {
	if entry == nil || len(entry.Attributes) > 16 {
		return nil, ErrRead
	}
	result := map[string][]string{}
	total := 0
	for _, attribute := range entry.Attributes {
		if attribute == nil || len(attribute.Name) > 128 || len(attribute.Values) > 12288 {
			return nil, ErrRead
		}
		name := strings.ToLower(attribute.Name)
		if _, exists := result[name]; exists || name == "" || strings.Contains(name, ";") {
			return nil, ErrRead
		}
		for _, value := range attribute.Values {
			total += len(value)
			if len(value) > policy.AttributeLimit || !utf8.ValidString(value) || total > 1<<20 {
				return nil, ErrRead
			}
		}
		result[name] = attribute.Values
	}
	return result, nil
}

func single(attributes map[string][]string, name string) (string, bool) {
	values := attributes[name]
	if len(values) != 1 {
		return "", false
	}
	return values[0], true
}

func validName(name string) bool {
	return name != "" && len(name) <= 128 && utf8.ValidString(name) &&
		strings.IndexFunc(name, unicode.IsControl) < 0
}

func networkName(name string) bool {
	for _, prefix := range []string{"vlan-", "trusted-", "guest-", "untrusted-", "infrastructure-", "security-", "assessment-"} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}
