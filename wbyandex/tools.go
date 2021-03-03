package wbyandex

import (
	"bytes"
	"fmt"
	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/hashicorp/terraform-plugin-sdk/helper/hashcode"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/yandex-cloud/go-genproto/yandex/cloud/mdb/postgresql/v1"
	"strconv"
	"strings"
	"time"
)

func getIdAndName(id string) (string, string) {
	v := strings.SplitN(id, "-", 2)
	return v[0], v[1]
}

func flattenPGUserPermissions(ps []*postgresql.Permission) (*schema.Set, error) {
	out := schema.NewSet(pgUserPermissionHash, nil)

	for _, p := range ps {
		op := map[string]interface{}{
			"database_name": p.DatabaseName,
		}

		out.Add(op)
	}

	return out, nil
}

func expandPGUserGrants(gs []interface{}) ([]string, error) {
	out := []string{}

	if gs == nil {
		return out, nil
	}

	for _, v := range gs {
		out = append(out, v.(string))
	}

	return out, nil
}

func expandPGUserPermissions(ps *schema.Set) ([]*postgresql.Permission, error) {
	out := []*postgresql.Permission{}

	for _, p := range ps.List() {
		m := p.(map[string]interface{})
		permission := &postgresql.Permission{}

		if v, ok := m["database_name"]; ok {
			permission.DatabaseName = v.(string)
		}

		out = append(out, permission)
	}

	return out, nil
}

func pgUserPermissionHash(v interface{}) int {
	m := v.(map[string]interface{})

	if n, ok := m["database_name"]; ok {
		return hashcode.String(n.(string))
	}
	return 0
}

func pgExtensionHash(v interface{}) int {
	var buf bytes.Buffer

	m := v.(map[string]interface{})
	if v, ok := m["name"]; ok {
		buf.WriteString(fmt.Sprintf("%s-", v.(string)))
	}
	if v, ok := m["version"]; ok {
		buf.WriteString(fmt.Sprintf("%s-", v.(string)))
	}

	return hashcode.String(buf.String())
}

func expandPGExtensions(es []interface{}) ([]*postgresql.Extension, error) {
	out := []*postgresql.Extension{}

	for _, e := range es {
		m := e.(map[string]interface{})
		extension := &postgresql.Extension{}

		if v, ok := m["name"]; ok {
			extension.Name = v.(string)
		}

		if v, ok := m["version"]; ok {
			extension.Version = v.(string)
		}

		out = append(out, extension)
	}

	return out, nil
}

func flattenPGExtensions(es []*postgresql.Extension) *schema.Set {
	out := schema.NewSet(pgExtensionHash, nil)

	for _, e := range es {
		m := make(map[string]interface{})
		m["name"] = e.Name
		m["version"] = e.Version

		out.Add(m)
	}

	return out
}

func expandPGUser(d *schema.ResourceData, user *postgresql.UserSpec) (*postgresql.UserSpec, error) {

	if v, ok := d.GetOkExists("name"); ok {
		user.Name = v.(string)
	}

	if v, ok := d.GetOkExists("password"); ok {
		user.Password = v.(string)
	}

	if v, ok := d.GetOkExists("login"); ok {
		user.Login = &wrappers.BoolValue{Value: v.(bool)}
	}

	if v, ok := d.GetOkExists("conn_limit"); ok {
		user.ConnLimit = &wrappers.Int64Value{Value: int64(v.(int))}
	}

	if v, ok := d.GetOkExists("permission"); ok {
		permissions, err := expandPGUserPermissions(v.(*schema.Set))
		if err != nil {
			return nil, err
		}
		user.Permissions = permissions
	}

	if v, ok := d.GetOkExists("grants"); ok {
		gs, err := expandPGUserGrants(v.([]interface{}))
		if err != nil {
			return nil, err
		}
		user.Grants = gs
	}

	return user, nil
}


func expandPGDatabase(d *schema.ResourceData) (*postgresql.DatabaseSpec, error) {
	out := &postgresql.DatabaseSpec{}

	if v, ok := d.GetOkExists("name"); ok {
		out.Name = v.(string)
	}

	if v, ok := d.GetOkExists("owner"); ok {
		out.Owner = v.(string)
	}

	if v, ok := d.GetOkExists("lc_collate"); ok {
		out.LcCollate = v.(string)
	}

	if v, ok := d.GetOkExists("lc_type"); ok {
		out.LcCtype = v.(string)
	}

	if v, ok := d.GetOkExists("extension"); ok {
		es := v.(*schema.Set).List()
		extensions, err := expandPGExtensions(es)
		if err != nil {
			return nil, err
		}

		out.Extensions = extensions
	}

	return out, nil
}

func stringToTimeValidateFunc(value interface{}, key string) (fields []string, errors []error) {
	if strTime, ok := value.(string); ok {
		_, err := parseStringToTime(strTime)
		if err != nil {
			errors = append(errors, err)
		}
	} else {
		errors = append(errors, fmt.Errorf("value %v is not string", value))
	}

	return fields, errors
}

func parseStringToTime(s string) (t time.Time, err error) {
	if s == "" {
		return time.Now(), nil
	}
	if s == "0" {
		return time.Now(), nil
	}

	if timeInt, err := strconv.Atoi(s); err == nil {
		return time.Unix(int64(timeInt), 0), nil
	}

	return time.Parse("2006-01-02T15:04:05", s)

}
