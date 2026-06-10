package runtime

import (
	"context"
	"fmt"
	"strings"
	"testing"

	structpb "google.golang.org/protobuf/types/known/structpb"

	pb "github.com/jkylling/bouncer/internal/pb"
	"github.com/jkylling/bouncer/internal/runtime/models"
)

// sample is (action, method, path).
type sample struct {
	action string
	method string
	path   string
}

// sampleBodies holds canned `request.body` shapes for actions whose binds
// read fields out of the body (e.g. gmail.send_draft, where the draft id
// lives in the body and not the URL). The vast majority of actions don't
// need an entry here.
var sampleBodies = map[string]map[string]any{
	"send_draft": {"id": "d1"},
}

// unusedAPI is wired into the coverage tests below: every policy is
// `condition: "true"`, so the runtime never asks the meta layer to call
// upstream — invoking us means the policy/bind layer leaked an upstream
// dependency, which is a bug.
type unusedAPI struct{}

func (unusedAPI) Call(_ context.Context, req *pb.MetaRequest) (*pb.Response, error) {
	panic(fmt.Sprintf("unusedAPI.Call invoked for %q: true-only policies must not touch the meta", req.GetPath()))
}

func sampleRequest(s sample) *pb.Request {
	segs := []string{}
	for _, p := range strings.Split(s.path, "/") {
		if p != "" {
			segs = append(segs, p)
		}
	}
	req := &pb.Request{
		Method:       s.method,
		Path:         s.path,
		PathSegments: segs,
	}
	if body, ok := sampleBodies[s.action]; ok {
		v, err := structpb.NewValue(body)
		if err != nil {
			panic(fmt.Sprintf("sampleRequest: build body for %q: %v", s.action, err))
		}
		req.Body = v
	}
	return req
}

func permitAll(api, action string) models.Policy {
	return models.Policy{
		API:       api,
		Name:      "permit_" + action,
		Action:    fmt.Sprintf("action.name == %q", action),
		Condition: "true",
		Result:    models.Permit,
	}
}

func loadAPIByName(t *testing.T, name string) models.API {
	t.Helper()
	for _, a := range loadAPIs(t) {
		if a.Name == name {
			return a
		}
	}
	t.Fatalf("api config %q missing", name)
	return models.API{}
}

func gmailSamples() []sample {
	return []sample{
		{"list_messages", "GET", "/gmail/v1/users/me/messages"},
		{"get_message", "GET", "/gmail/v1/users/me/messages/m1"},
		{"send_message", "POST", "/gmail/v1/users/me/messages/send"},
		{"insert_message", "POST", "/gmail/v1/users/me/messages"},
		{"import_message", "POST", "/gmail/v1/users/me/messages/import"},
		{"modify_message", "POST", "/gmail/v1/users/me/messages/m1/modify"},
		{"trash_message", "POST", "/gmail/v1/users/me/messages/m1/trash"},
		{"untrash_message", "POST", "/gmail/v1/users/me/messages/m1/untrash"},
		{"delete_message", "DELETE", "/gmail/v1/users/me/messages/m1"},
		{"batch_delete_messages", "POST", "/gmail/v1/users/me/messages/batchDelete"},
		{"batch_modify_messages", "POST", "/gmail/v1/users/me/messages/batchModify"},
		{"list_threads", "GET", "/gmail/v1/users/me/threads"},
		{"get_thread", "GET", "/gmail/v1/users/me/threads/t1"},
		{"modify_thread", "POST", "/gmail/v1/users/me/threads/t1/modify"},
		{"trash_thread", "POST", "/gmail/v1/users/me/threads/t1/trash"},
		{"untrash_thread", "POST", "/gmail/v1/users/me/threads/t1/untrash"},
		{"delete_thread", "DELETE", "/gmail/v1/users/me/threads/t1"},
		{"list_drafts", "GET", "/gmail/v1/users/me/drafts"},
		{"get_draft", "GET", "/gmail/v1/users/me/drafts/d1"},
		{"create_draft", "POST", "/gmail/v1/users/me/drafts"},
		{"update_draft", "PUT", "/gmail/v1/users/me/drafts/d1"},
		{"send_draft", "POST", "/gmail/v1/users/me/drafts/send"},
		{"delete_draft", "DELETE", "/gmail/v1/users/me/drafts/d1"},
		{"list_labels", "GET", "/gmail/v1/users/me/labels"},
		{"get_label", "GET", "/gmail/v1/users/me/labels/l1"},
		{"create_label", "POST", "/gmail/v1/users/me/labels"},
		{"update_label", "PUT", "/gmail/v1/users/me/labels/l1"},
		{"patch_label", "PATCH", "/gmail/v1/users/me/labels/l1"},
		{"delete_label", "DELETE", "/gmail/v1/users/me/labels/l1"},
		{"list_history", "GET", "/gmail/v1/users/me/history"},
		{"get_profile", "GET", "/gmail/v1/users/me/profile"},
		{"watch", "POST", "/gmail/v1/users/me/watch"},
		{"stop", "POST", "/gmail/v1/users/me/stop"},
		{"settings_list_filters", "GET", "/gmail/v1/users/me/settings/filters"},
		{"settings_get_filter", "GET", "/gmail/v1/users/me/settings/filters/f1"},
		{"settings_create_filter", "POST", "/gmail/v1/users/me/settings/filters"},
		{"settings_delete_filter", "DELETE", "/gmail/v1/users/me/settings/filters/f1"},
		{"settings_list_send_as", "GET", "/gmail/v1/users/me/settings/sendAs"},
		{"settings_get_send_as", "GET", "/gmail/v1/users/me/settings/sendAs/a%40x.com"},
		{"settings_create_send_as", "POST", "/gmail/v1/users/me/settings/sendAs"},
		{"settings_update_send_as", "PUT", "/gmail/v1/users/me/settings/sendAs/a%40x.com"},
		{"settings_patch_send_as", "PATCH", "/gmail/v1/users/me/settings/sendAs/a%40x.com"},
		{"settings_delete_send_as", "DELETE", "/gmail/v1/users/me/settings/sendAs/a%40x.com"},
		{"settings_verify_send_as", "POST", "/gmail/v1/users/me/settings/sendAs/a%40x.com/verify"},
		{"settings_list_forwarding_addresses", "GET", "/gmail/v1/users/me/settings/forwardingAddresses"},
		{"settings_get_forwarding_address", "GET", "/gmail/v1/users/me/settings/forwardingAddresses/a%40x.com"},
		{"settings_create_forwarding_address", "POST", "/gmail/v1/users/me/settings/forwardingAddresses"},
		{"settings_delete_forwarding_address", "DELETE", "/gmail/v1/users/me/settings/forwardingAddresses/a%40x.com"},
		{"settings_get_vacation", "GET", "/gmail/v1/users/me/settings/vacation"},
		{"settings_update_vacation", "PUT", "/gmail/v1/users/me/settings/vacation"},
		{"settings_get_imap", "GET", "/gmail/v1/users/me/settings/imap"},
		{"settings_update_imap", "PUT", "/gmail/v1/users/me/settings/imap"},
		{"settings_get_pop", "GET", "/gmail/v1/users/me/settings/pop"},
		{"settings_update_pop", "PUT", "/gmail/v1/users/me/settings/pop"},
		{"settings_get_auto_forwarding", "GET", "/gmail/v1/users/me/settings/autoForwarding"},
		{"settings_update_auto_forwarding", "PUT", "/gmail/v1/users/me/settings/autoForwarding"},
		{"settings_get_language", "GET", "/gmail/v1/users/me/settings/language"},
		{"settings_update_language", "PUT", "/gmail/v1/users/me/settings/language"},
		// users.messages.attachments
		{"get_attachment", "GET", "/gmail/v1/users/me/messages/m1/attachments/at1"},
		// users.settings.delegates
		{"settings_list_delegates", "GET", "/gmail/v1/users/me/settings/delegates"},
		{"settings_create_delegate", "POST", "/gmail/v1/users/me/settings/delegates"},
		{"settings_get_delegate", "GET", "/gmail/v1/users/me/settings/delegates/d%40x.com"},
		{"settings_delete_delegate", "DELETE", "/gmail/v1/users/me/settings/delegates/d%40x.com"},
		// users.settings.sendAs.smimeInfo
		{"settings_list_smime_info", "GET", "/gmail/v1/users/me/settings/sendAs/a%40x.com/smimeInfo"},
		{"settings_insert_smime_info", "POST", "/gmail/v1/users/me/settings/sendAs/a%40x.com/smimeInfo"},
		{"settings_get_smime_info", "GET", "/gmail/v1/users/me/settings/sendAs/a%40x.com/smimeInfo/i1"},
		{"settings_delete_smime_info", "DELETE", "/gmail/v1/users/me/settings/sendAs/a%40x.com/smimeInfo/i1"},
		{"settings_set_default_smime_info", "POST", "/gmail/v1/users/me/settings/sendAs/a%40x.com/smimeInfo/i1/setDefault"},
		// users.settings.cse.identities
		{"settings_list_cse_identities", "GET", "/gmail/v1/users/me/settings/cse/identities"},
		{"settings_create_cse_identity", "POST", "/gmail/v1/users/me/settings/cse/identities"},
		{"settings_get_cse_identity", "GET", "/gmail/v1/users/me/settings/cse/identities/u%40x.com"},
		{"settings_patch_cse_identity", "PATCH", "/gmail/v1/users/me/settings/cse/identities/u%40x.com"},
		{"settings_delete_cse_identity", "DELETE", "/gmail/v1/users/me/settings/cse/identities/u%40x.com"},
		// users.settings.cse.keypairs
		{"settings_list_cse_keypairs", "GET", "/gmail/v1/users/me/settings/cse/keypairs"},
		{"settings_create_cse_keypair", "POST", "/gmail/v1/users/me/settings/cse/keypairs"},
		{"settings_get_cse_keypair", "GET", "/gmail/v1/users/me/settings/cse/keypairs/kp1"},
		{"settings_enable_cse_keypair", "POST", "/gmail/v1/users/me/settings/cse/keypairs/kp1:enable"},
		{"settings_disable_cse_keypair", "POST", "/gmail/v1/users/me/settings/cse/keypairs/kp1:disable"},
		{"settings_obliterate_cse_keypair", "POST", "/gmail/v1/users/me/settings/cse/keypairs/kp1:obliterate"},
	}
}

func driveSamples() []sample {
	return []sample{
		{"get_about", "GET", "/drive/v3/about"},
		{"list_changes", "GET", "/drive/v3/changes"},
		{"get_start_page_token", "GET", "/drive/v3/changes/startPageToken"},
		{"watch_changes", "POST", "/drive/v3/changes/watch"},
		{"stop_channel", "POST", "/drive/v3/channels/stop"},
		{"list_files", "GET", "/drive/v3/files"},
		{"generate_file_ids", "GET", "/drive/v3/files/generateIds"},
		{"empty_trash", "DELETE", "/drive/v3/files/trash"},
		{"create_file", "POST", "/drive/v3/files"},
		{"upload_file", "POST", "/upload/drive/v3/files"},
		{"get_file", "GET", "/drive/v3/files/f1"},
		{"update_file", "PATCH", "/drive/v3/files/f1"},
		{"upload_file_update", "PATCH", "/upload/drive/v3/files/f1"},
		{"delete_file", "DELETE", "/drive/v3/files/f1"},
		{"copy_file", "POST", "/drive/v3/files/f1/copy"},
		{"export_file", "GET", "/drive/v3/files/f1/export"},
		{"watch_file", "POST", "/drive/v3/files/f1/watch"},
		{"list_file_labels", "GET", "/drive/v3/files/f1/listLabels"},
		{"modify_file_labels", "POST", "/drive/v3/files/f1/modifyLabels"},
		{"list_permissions", "GET", "/drive/v3/files/f1/permissions"},
		{"create_permission", "POST", "/drive/v3/files/f1/permissions"},
		{"get_permission", "GET", "/drive/v3/files/f1/permissions/p1"},
		{"update_permission", "PATCH", "/drive/v3/files/f1/permissions/p1"},
		{"delete_permission", "DELETE", "/drive/v3/files/f1/permissions/p1"},
		{"list_comments", "GET", "/drive/v3/files/f1/comments"},
		{"create_comment", "POST", "/drive/v3/files/f1/comments"},
		{"get_comment", "GET", "/drive/v3/files/f1/comments/c1"},
		{"update_comment", "PATCH", "/drive/v3/files/f1/comments/c1"},
		{"delete_comment", "DELETE", "/drive/v3/files/f1/comments/c1"},
		{"list_replies", "GET", "/drive/v3/files/f1/comments/c1/replies"},
		{"create_reply", "POST", "/drive/v3/files/f1/comments/c1/replies"},
		{"get_reply", "GET", "/drive/v3/files/f1/comments/c1/replies/r1"},
		{"update_reply", "PATCH", "/drive/v3/files/f1/comments/c1/replies/r1"},
		{"delete_reply", "DELETE", "/drive/v3/files/f1/comments/c1/replies/r1"},
		{"list_revisions", "GET", "/drive/v3/files/f1/revisions"},
		{"get_revision", "GET", "/drive/v3/files/f1/revisions/v1"},
		{"update_revision", "PATCH", "/drive/v3/files/f1/revisions/v1"},
		{"delete_revision", "DELETE", "/drive/v3/files/f1/revisions/v1"},
		{"list_drives", "GET", "/drive/v3/drives"},
		{"create_drive", "POST", "/drive/v3/drives"},
		{"get_drive", "GET", "/drive/v3/drives/d1"},
		{"update_drive", "PATCH", "/drive/v3/drives/d1"},
		{"delete_drive", "DELETE", "/drive/v3/drives/d1"},
		{"hide_drive", "POST", "/drive/v3/drives/d1/hide"},
		{"unhide_drive", "POST", "/drive/v3/drives/d1/unhide"},
	}
}

func calendarSamples() []sample {
	return []sample{
		{"create_calendar", "POST", "/calendar/v3/calendars"},
		{"get_calendar", "GET", "/calendar/v3/calendars/primary"},
		{"update_calendar", "PUT", "/calendar/v3/calendars/primary"},
		{"patch_calendar", "PATCH", "/calendar/v3/calendars/primary"},
		{"delete_calendar", "DELETE", "/calendar/v3/calendars/primary"},
		{"clear_calendar", "POST", "/calendar/v3/calendars/primary/clear"},
		{"list_calendar_list", "GET", "/calendar/v3/users/me/calendarList"},
		{"watch_calendar_list", "POST", "/calendar/v3/users/me/calendarList/watch"},
		{"insert_calendar_list", "POST", "/calendar/v3/users/me/calendarList"},
		{"get_calendar_list_entry", "GET", "/calendar/v3/users/me/calendarList/c1"},
		{"update_calendar_list_entry", "PUT", "/calendar/v3/users/me/calendarList/c1"},
		{"patch_calendar_list_entry", "PATCH", "/calendar/v3/users/me/calendarList/c1"},
		{"delete_calendar_list_entry", "DELETE", "/calendar/v3/users/me/calendarList/c1"},
		{"list_events", "GET", "/calendar/v3/calendars/primary/events"},
		{"watch_events", "POST", "/calendar/v3/calendars/primary/events/watch"},
		{"insert_event", "POST", "/calendar/v3/calendars/primary/events"},
		{"import_event", "POST", "/calendar/v3/calendars/primary/events/import"},
		{"quick_add_event", "POST", "/calendar/v3/calendars/primary/events/quickAdd"},
		{"get_event", "GET", "/calendar/v3/calendars/primary/events/e1"},
		{"update_event", "PUT", "/calendar/v3/calendars/primary/events/e1"},
		{"patch_event", "PATCH", "/calendar/v3/calendars/primary/events/e1"},
		{"delete_event", "DELETE", "/calendar/v3/calendars/primary/events/e1"},
		{"move_event", "POST", "/calendar/v3/calendars/primary/events/e1/move"},
		{"get_event_instances", "GET", "/calendar/v3/calendars/primary/events/e1/instances"},
		{"list_acl", "GET", "/calendar/v3/calendars/primary/acl"},
		{"watch_acl", "POST", "/calendar/v3/calendars/primary/acl/watch"},
		{"insert_acl_rule", "POST", "/calendar/v3/calendars/primary/acl"},
		{"get_acl_rule", "GET", "/calendar/v3/calendars/primary/acl/r1"},
		{"update_acl_rule", "PUT", "/calendar/v3/calendars/primary/acl/r1"},
		{"patch_acl_rule", "PATCH", "/calendar/v3/calendars/primary/acl/r1"},
		{"delete_acl_rule", "DELETE", "/calendar/v3/calendars/primary/acl/r1"},
		{"query_freebusy", "POST", "/calendar/v3/freeBusy"},
		{"get_colors", "GET", "/calendar/v3/colors"},
		{"list_settings", "GET", "/calendar/v3/users/me/settings"},
		{"watch_settings", "POST", "/calendar/v3/users/me/settings/watch"},
		{"get_setting", "GET", "/calendar/v3/users/me/settings/s1"},
		{"stop_channel", "POST", "/calendar/v3/channels/stop"},
	}
}

func sheetsSamples() []sample {
	return []sample{
		{"create_spreadsheet", "POST", "/v4/spreadsheets"},
		{"get_spreadsheet", "GET", "/v4/spreadsheets/s1"},
		{"get_spreadsheet_by_data_filter", "POST", "/v4/spreadsheets/s1/getByDataFilter"},
		{"batch_update_spreadsheet", "POST", "/v4/spreadsheets/s1/batchUpdate"},
		{"get_values", "GET", "/v4/spreadsheets/s1/values/A1"},
		{"update_values", "PUT", "/v4/spreadsheets/s1/values/A1"},
		{"append_values", "POST", "/v4/spreadsheets/s1/values/A1:append"},
		{"clear_values", "POST", "/v4/spreadsheets/s1/values/A1:clear"},
		{"batch_get_values", "GET", "/v4/spreadsheets/s1/values:batchGet"},
		{"batch_update_values", "POST", "/v4/spreadsheets/s1/values:batchUpdate"},
		{"batch_clear_values", "POST", "/v4/spreadsheets/s1/values:batchClear"},
		{"batch_get_values_by_data_filter", "POST", "/v4/spreadsheets/s1/values:batchGetByDataFilter"},
		{"batch_update_values_by_data_filter", "POST", "/v4/spreadsheets/s1/values:batchUpdateByDataFilter"},
		{"batch_clear_values_by_data_filter", "POST", "/v4/spreadsheets/s1/values:batchClearByDataFilter"},
		{"copy_sheet_to", "POST", "/v4/spreadsheets/s1/sheets/sh1/copyTo"},
		{"get_developer_metadata", "GET", "/v4/spreadsheets/s1/developerMetadata/m1"},
		{"search_developer_metadata", "POST", "/v4/spreadsheets/s1/developerMetadata:search"},
	}
}

func docsSamples() []sample {
	return []sample{
		{"create_document", "POST", "/v1/documents"},
		{"get_document", "GET", "/v1/documents/d1"},
		{"batch_update_document", "POST", "/v1/documents/d1/batchUpdate"},
	}
}

func allSamples() []struct {
	api     string
	samples []sample
} {
	return []struct {
		api     string
		samples []sample
	}{
		{"google.gmail", gmailSamples()},
		{"google.drive", driveSamples()},
		{"google.calendar", calendarSamples()},
		{"google.sheets", sheetsSamples()},
		{"google.docs", docsSamples()},
	}
}

func TestEveryDeclaredActionHasASample(t *testing.T) {
	for _, group := range allSamples() {
		api := loadAPIByName(t, group.api)
		declared := map[string]bool{}
		for _, a := range api.Actions {
			declared[a.Name] = true
		}
		tested := map[string]bool{}
		for _, s := range group.samples {
			tested[s.action] = true
		}
		for name := range declared {
			if !tested[name] {
				t.Errorf("%s: declared action %q has no coverage sample", group.api, name)
			}
		}
		for name := range tested {
			if !declared[name] {
				t.Errorf("%s: sample for action %q not declared in config", group.api, name)
			}
		}
	}
}

func TestEverySampleRoutesAndPermits(t *testing.T) {
	// One shared runtime for every sample; the per-sample state is
	// the single permit policy, added and removed through the public
	// hot-reload API. Rebuilding the full five-API CEL runtime per
	// sample (~200×) used to dominate the unit suite's wall clock.
	rt := buildCrossApiRuntime(t)
	for _, group := range allSamples() {
		api := rt.API(group.api)
		if api == nil {
			t.Fatalf("api %q not found", group.api)
		}
		for _, s := range group.samples {
			t.Run(group.api+"/"+s.action, func(t *testing.T) {
				p := permitAll(group.api, s.action)
				if err := rt.AddPolicy(&p); err != nil {
					t.Fatalf("AddPolicy %q: %v", p.Name, err)
				}
				defer func() {
					if _, err := rt.RemovePolicy(group.api, p.Name); err != nil {
						t.Fatalf("RemovePolicy %q: %v", p.Name, err)
					}
				}()
				got, err := api.Evaluate(t.Context(), constantResolver(unusedAPI{}), sampleRequest(s), stubPrincipal())
				if err != nil {
					t.Fatalf("evaluate %s::%s (%s %s): %v", group.api, s.action, s.method, s.path, err)
				}
				if got != models.Permit {
					t.Fatalf("%s::%s did not permit %s %s — filter mismatch or bind failure", group.api, s.action, s.method, s.path)
				}
			})
		}
	}
}

func TestEverySampleDeniesWhenNoPolicy(t *testing.T) {
	// Policy-less evaluation is read-only, so a single runtime
	// serves every sample.
	rt := buildCrossApiRuntime(t)
	for _, group := range allSamples() {
		api := rt.API(group.api)
		if api == nil {
			t.Fatalf("api %q not found", group.api)
		}
		for _, s := range group.samples {
			got, err := api.Evaluate(t.Context(), constantResolver(unusedAPI{}), sampleRequest(s), stubPrincipal())
			if err != nil {
				t.Fatalf("evaluate %s::%s (%s %s): %v", group.api, s.action, s.method, s.path, err)
			}
			if got != models.Deny {
				t.Errorf("%s::%s: expected Deny with no policies, got %v", group.api, s.action, got)
			}
		}
	}
}

func TestDenyPolicyBeatsPermitPolicy(t *testing.T) {
	policies := []models.Policy{
		permitAll("google.gmail", "get_message"),
		{
			API:       "google.gmail",
			Name:      "deny_get_message",
			Action:    `action.name == "get_message"`,
			Condition: "true",
			Result:    models.Deny,
		},
	}
	rt := loadCrossApiRuntime(t, "google.gmail", policies)
	got, err := rt.Evaluate(t.Context(), constantResolver(unusedAPI{}), sampleRequest(sample{method: "GET", path: "/gmail/v1/users/me/messages/m1"}), stubPrincipal())
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if got != models.Deny {
		t.Fatalf("expected Deny, got %v", got)
	}
}
