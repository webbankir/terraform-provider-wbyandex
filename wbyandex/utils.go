package wbyandex

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net"
	"sort"
	"strings"
	"text/template"
	"time"

	"github.com/c2h5oh/datasize"
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/yandex-cloud/go-genproto/yandex/cloud/access"
	"github.com/yandex-cloud/go-genproto/yandex/cloud/compute/v1"
	ycsdk "github.com/yandex-cloud/go-sdk"
	"github.com/yandex-cloud/go-sdk/sdkresolvers"
)

type instanceAction int

const (
	instanceActionStop instanceAction = iota
	instanceActionStart
	instanceActionRestart
)

const defaultTimeFormat = time.RFC3339
const defaultListSize = 1000

type Policy struct {
	Bindings []*access.AccessBinding
}

func handleNotFoundError(err error, d *schema.ResourceData, resourceName string) error {
	if isStatusWithCode(err, codes.NotFound) {
		log.Printf("[WARN] Removing %s because resource doesn't exist anymore", resourceName)
		d.SetId("")
		return nil
	}
	return fmt.Errorf("error reading %s: %s", resourceName, err)
}

func isStatusWithCode(err error, code codes.Code) bool {
	grpcStatus, ok := status.FromError(err)
	return ok && grpcStatus.Code() == code
}

func isRequestIDPresent(err error) (string, bool) {
	st, ok := status.FromError(err)
	if ok {
		for _, d := range st.Details() {
			if reqInfo, ok := d.(*errdetails.RequestInfo); ok {
				return reqInfo.RequestId, true
			}
		}
	}
	return "", false
}

func convertStringArrToInterface(sslice []string) []interface{} {
	islice := make([]interface{}, len(sslice))
	for i, str := range sslice {
		islice[i] = str
	}
	return islice
}

func mergeSchemas(a, b map[string]*schema.Schema) map[string]*schema.Schema {
	merged := make(map[string]*schema.Schema, len(a)+len(b))

	for k, v := range a {
		merged[k] = v
	}

	for k, v := range b {
		merged[k] = v
	}

	return merged
}

func roleMemberToAccessBinding(role, member string) *access.AccessBinding {
	chunks := strings.SplitN(member, ":", 2)
	return &access.AccessBinding{
		RoleId: role,
		Subject: &access.Subject{
			Type: chunks[0],
			Id:   chunks[1],
		},
	}
}

//func mergeBindings(bindings []*access.AccessBinding) []*access.AccessBinding {
//	bm := rolesToMembersMap(bindings)
//	var rb []*access.AccessBinding
//
//	for role, members := range bm {
//		for member := range members {
//			rb = append(rb, roleMemberToAccessBinding(role, member))
//		}
//	}
//
//	return rb
//}

// Map a role to a map of members, allowing easy merging of multiple bindings.
//func rolesToMembersMap(bindings []*access.AccessBinding) map[string]map[string]bool {
//	bm := make(map[string]map[string]bool)
//	// Get each binding
//	for _, b := range bindings {
//		// Initialize members map
//		if _, ok := bm[b.RoleId]; !ok {
//			bm[b.RoleId] = make(map[string]bool)
//		}
//		// Get each member (user/principal) for the binding
//		m := canonicalMember(b)
//		bm[b.RoleId][m] = true
//	}
//	return bm
//}

//func roleToMembersList(role string, bindings []*access.AccessBinding) []string {
//	var members []string
//
//	for _, b := range bindings {
//		if b.RoleId != role {
//			continue
//		}
//		m := canonicalMember(b)
//		members = append(members, m)
//	}
//	return members
//}
//
//func removeRoleFromBindings(roleForRemove string, bindings []*access.AccessBinding) []*access.AccessBinding {
//	bm := rolesToMembersMap(bindings)
//	var rb []*access.AccessBinding
//
//	for role, members := range bm {
//		if role == roleForRemove {
//			continue
//		}
//		for member := range members {
//			rb = append(rb, roleMemberToAccessBinding(role, member))
//		}
//	}
//
//	return rb
//}

func (p Policy) String() string {
	result := ""
	for i, binding := range p.Bindings {
		result = result + fmt.Sprintf("\n#:%d role:%-27s\taccount:%-24s\ttype:%s",
			i, binding.RoleId, binding.Subject.Id, binding.Subject.Type)
	}
	return result + "\n"
}

func convertStringSet(set *schema.Set) []string {
	s := make([]string, set.Len())
	for i, v := range set.List() {
		s[i] = v.(string)
	}
	return s
}

func convertStringMap(v map[string]interface{}) map[string]string {
	m := make(map[string]string)
	if v == nil {
		return m
	}
	for k, val := range v {
		m[k] = val.(string)
	}
	return m
}


type sortableBindings []*access.AccessBinding

func (b sortableBindings) Len() int {
	return len(b)
}
func (b sortableBindings) Swap(i, j int) {
	b[i], b[j] = b[j], b[i]
}
func (b sortableBindings) Less(i, j int) bool {
	return b.String(i) < b.String(j)
}

func (b sortableBindings) String(i int) string {
	return fmt.Sprintf("%s\x00%s\x00%s", b[i].RoleId, b[i].Subject.Type, b[i].Subject.Id)
}

func validateIPV4CidrBlocks(v interface{}, k string) (warnings []string, errors []error) {
	_, _, err := net.ParseCIDR(v.(string))
	if err != nil {
		errors = append(errors, fmt.Errorf("%q is not a valid IP CIDR range: %s", k, err))
	}
	return
}

// Primary use to store value from API in state file as Gigabytes
func toGigabytes(bytesCount int64) int {
	return int((datasize.ByteSize(bytesCount) * datasize.B).GBytes())
}

func toGigabytesInFloat(bytesCount int64) float64 {
	return (datasize.ByteSize(bytesCount) * datasize.B).GBytes()
}

// Primary use to send byte value to API
func toBytes(gigabytesCount int) int64 {
	return int64((datasize.ByteSize(gigabytesCount) * datasize.GB).Bytes())
}

func toBytesFromFloat(gigabytesCountF float64) int64 {
	return int64(gigabytesCountF * float64(datasize.GB))
}

func (action instanceAction) String() string {
	switch action {
	case instanceActionStop:
		return "Stop"
	case instanceActionStart:
		return "Start"
	case instanceActionRestart:
		return "Restart"
	default:
		return "Unknown"
	}
}

func getTimestamp(protots *timestamp.Timestamp) (string, error) {
	if protots == nil {
		return "", nil
	}
	ts, err := ptypes.Timestamp(protots)
	if err != nil {
		return "", fmt.Errorf("failed to convert protobuf timestamp: %s", err)
	}

	return ts.Format(defaultTimeFormat), nil
}

func stringSliceToLower(s []string) []string {
	var ret []string
	for _, v := range s {
		ret = append(ret, strings.ToLower(v))
	}
	return ret
}

func getEnumValueMapKeys(m map[string]int32) []string {
	return getEnumValueMapKeysExt(m, false)
}

func getEnumValueMapKeysExt(m map[string]int32, skipDefault bool) []string {
	keys := make([]string, 0, len(m))
	for k, v := range m {
		if v == 0 && skipDefault {
			continue
		}

		keys = append(keys, k)
	}
	return keys
}

func getJoinedKeys(keys []string) string {
	return "`" + strings.Join(keys, "`, `") + "`"
}

func checkOneOf(d *schema.ResourceData, keys ...string) error {
	var gotKey bool
	for _, key := range keys {
		_, ok := d.GetOk(key)

		if ok {
			if gotKey {
				return fmt.Errorf("only one of %s can be provided", getJoinedKeys(keys))
			}

			gotKey = true
		}
	}

	if !gotKey {
		return fmt.Errorf("one of %s should be provided", getJoinedKeys(keys))
	}

	return nil
}

type objectResolverFunc func(name string, opts ...sdkresolvers.ResolveOption) ycsdk.Resolver

// this function can be only used to resolve objects that belong to some folder (have folder_id attribute)
// do not use this function to resolve cloud (or similar objects) ID by name.

func resolveObjectIDByNameAndFolderID(ctx context.Context, config *Config, name, folderID string, resolverFunc objectResolverFunc) (string, error) {
	if name == "" {
		return "", fmt.Errorf("non empty name should be provided")
	}

	var objectID string
	resolver := resolverFunc(name, sdkresolvers.Out(&objectID), sdkresolvers.FolderID(folderID))

	err := config.sdk.Resolve(ctx, resolver)

	if err != nil {
		return "", err
	}

	return objectID, nil
}

func getSnapshotMinStorageSize(snapshotID string, config *Config) (size int64, err error) {
	ctx := config.Context()

	snapshot, err := config.sdk.Compute().Snapshot().Get(ctx, &compute.GetSnapshotRequest{
		SnapshotId: snapshotID,
	})

	if err != nil {
		return 0, fmt.Errorf("Error on retrieve snapshot properties: %s", err)
	}

	return snapshot.DiskSize, nil
}

func getImageMinStorageSize(imageID string, config *Config) (size int64, err error) {
	ctx := config.Context()

	image, err := config.sdk.Compute().Image().Get(ctx, &compute.GetImageRequest{
		ImageId: imageID,
	})

	if err != nil {
		return 0, fmt.Errorf("Error on retrieve image properties: %s", err)
	}

	return image.MinDiskSize, nil
}

func templateConfig(tmpl string, ctx ...map[string]interface{}) string {
	p := make(map[string]interface{})
	for _, c := range ctx {
		for k, v := range c {
			p[k] = v
		}
	}
	b := &bytes.Buffer{}
	err := template.Must(template.New("").Parse(tmpl)).Execute(b, p)
	if err != nil {
		panic(fmt.Errorf("failed to execute config template: %v", err))
	}
	return b.String()
}

func getResourceID(n string, s *terraform.State) (string, error) {
	rs, ok := s.RootModule().Resources[n]
	if !ok {
		return "", fmt.Errorf("terraform resource '%s' not found", n)
	}

	if rs.Primary.ID == "" {
		return "", fmt.Errorf("no ID is set for terraform resource '%s'", n)
	}

	return rs.Primary.ID, nil
}

type schemaGetHelper struct {
	pathPrefix string
	d          *schema.ResourceData
}

func schemaHelper(d *schema.ResourceData, path string) *schemaGetHelper {
	return &schemaGetHelper{
		pathPrefix: path,
		d:          d,
	}
}

func (h *schemaGetHelper) AppendPath(path string) *schemaGetHelper {
	return &schemaGetHelper{
		pathPrefix: h.pathPrefix + path,
		d:          h.d,
	}
}

func (h *schemaGetHelper) Get(key string) interface{} {
	return h.d.Get(h.pathPrefix + key)
}

func (h *schemaGetHelper) GetOk(key string) (interface{}, bool) {
	return h.d.GetOk(h.pathPrefix + key)
}

func (h *schemaGetHelper) GetString(key string) string {
	return h.d.Get(h.pathPrefix + key).(string)
}

func (h *schemaGetHelper) GetInt(key string) int {
	return h.d.Get(h.pathPrefix + key).(int)
}

func convertResourceToDataSource(resource *schema.Resource) *schema.Resource {
	return recursivelyUpdateResource(resource, func(schema *schema.Schema) {
		schema.Computed = true
		schema.Required = false
		schema.Optional = false
		schema.ForceNew = false
		schema.Default = nil
		schema.ValidateFunc = nil
	})
}

func recursivelyUpdateResource(resource *schema.Resource, callback func(*schema.Schema)) *schema.Resource {
	attributes := make(map[string]*schema.Schema)
	for key, attributeSchema := range resource.Schema {
		copyOfAttributeSchema := *attributeSchema
		callback(&copyOfAttributeSchema)
		if copyOfAttributeSchema.Elem != nil {
			switch elem := copyOfAttributeSchema.Elem.(type) {
			case *schema.Schema:
				elementCopy := *elem
				copyOfAttributeSchema.Elem = &elementCopy
			case *schema.Resource:
				copyOfAttributeSchema.Elem = recursivelyUpdateResource(elem, callback)
			default:
				log.Printf("[ERROR] Unexpected Elem type %T for attribute %s!\n", elem, key)
			}
		}

		attributes[key] = &copyOfAttributeSchema
	}

	return &schema.Resource{Schema: attributes}
}

func sortInterfaceListByResourceData(listToSort []interface{}, d *schema.ResourceData, entityName string, cmpFieldName string) {
	templateList, ok := d.GetOk(entityName)
	if !ok || templateList == nil {
		return
	}
	sortInterfaceListByTemplate(listToSort, templateList.([]interface{}), cmpFieldName)
}

func sortInterfaceListByTemplate(listToSort []interface{}, templateList []interface{}, cmpFieldName string) {
	if len(templateList) == 0 || len(listToSort) == 0 {
		return
	}

	sortRule := map[string]int{}

	for i := range templateList {
		sortRule[getField(templateList[i], cmpFieldName)] = i
	}

	sort.Slice(listToSort, func(i int, j int) bool {
		return lessInterfaceList(listToSort, cmpFieldName, i, j, sortRule)
	})
}

func lessInterfaceList(list []interface{}, name string, i int, j int, sortRule map[string]int) bool {
	nameI := getField(list[i], name)
	nameJ := getField(list[j], name)

	posI, okI := sortRule[nameI]
	posJ, okJ := sortRule[nameJ]

	if okI && okJ {
		return posI < posJ
	}

	if okI {
		return true
	}

	if okJ {
		return false
	}

	return nameI < nameJ
}

func getField(value interface{}, field string) string {
	return (value.(map[string]interface{}))[field].(string)
}

func expandLabels(v interface{}) (map[string]string, error) {
	m := make(map[string]string)
	if v == nil {
		return m, nil
	}
	for k, val := range v.(map[string]interface{}) {
		m[k] = val.(string)
	}
	return m, nil
}

func getFolderID(d *schema.ResourceData, config *Config) (string, error) {
	res, ok := d.GetOk("folder_id")
	if !ok {
		if config.FolderID != "" {
			return config.FolderID, nil
		}
		return "", fmt.Errorf("cannot determine folder_id: please set 'folder_id' key in this resource or at provider level")
	}
	return res.(string), nil
}

func expandSecurityGroupIds(v interface{}) []string {
	if v == nil {
		return nil
	}
	var m []string
	sgIdsSet := v.(*schema.Set)
	for _, val := range sgIdsSet.List() {
		m = append(m, val.(string))
	}
	return m
}