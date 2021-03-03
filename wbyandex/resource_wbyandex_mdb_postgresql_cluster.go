package wbyandex

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/helper/validation"
	"google.golang.org/genproto/protobuf/field_mask"

	"github.com/yandex-cloud/go-genproto/yandex/cloud/mdb/postgresql/v1"
)

const (
	yandexMDBPostgreSQLClusterCreateTimeout = 30 * time.Minute
	yandexMDBPostgreSQLClusterDeleteTimeout = 15 * time.Minute
	yandexMDBPostgreSQLClusterUpdateTimeout = 60 * time.Minute
)

func resourceYandexMDBPostgreSQLCluster() *schema.Resource {
	return &schema.Resource{
		Create: resourceYandexMDBPostgreSQLClusterCreate,
		Read:   resourceYandexMDBPostgreSQLClusterRead,
		Update: resourceYandexMDBPostgreSQLClusterUpdate,
		Delete: resourceYandexMDBPostgreSQLClusterDelete,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(yandexMDBPostgreSQLClusterCreateTimeout),
			Update: schema.DefaultTimeout(yandexMDBPostgreSQLClusterUpdateTimeout),
			Delete: schema.DefaultTimeout(yandexMDBPostgreSQLClusterDeleteTimeout),
		},

		SchemaVersion: 0,

		Schema: map[string]*schema.Schema{
			"name": {
				Type:     schema.TypeString,
				Required: true,
			},
			"environment": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"network_id": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"config": {
				Type:     schema.TypeList,
				Required: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"version": {
							Type:     schema.TypeString,
							Required: true,
						},
						"resources": {
							Type:     schema.TypeList,
							Required: true,
							MaxItems: 1,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"resource_preset_id": {
										Type:     schema.TypeString,
										Required: true,
									},
									"disk_size": {
										Type:     schema.TypeInt,
										Required: true,
									},
									"disk_type_id": {
										Type:     schema.TypeString,
										Optional: true,
									},
								},
							},
						},
						"autofailover": {
							Type:     schema.TypeBool,
							Optional: true,
							Computed: true,
						},
						"pooler_config": {
							Type:     schema.TypeList,
							Optional: true,
							MaxItems: 1,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"pooling_mode": {
										Type:     schema.TypeString,
										Optional: true,
									},
									"pool_discard": {
										Type:     schema.TypeBool,
										Optional: true,
									},
								},
							},
						},
						"backup_window_start": {
							Type:     schema.TypeList,
							MaxItems: 1,
							Optional: true,
							Computed: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"hours": {
										Type:         schema.TypeInt,
										Optional:     true,
										Default:      0,
										ValidateFunc: validation.IntBetween(0, 23),
									},
									"minutes": {
										Type:         schema.TypeInt,
										Optional:     true,
										Default:      0,
										ValidateFunc: validation.IntBetween(0, 59),
									},
								},
							},
						},
						"performance_diagnostics": {
							Type:     schema.TypeList,
							MaxItems: 1,
							Optional: true,
							Computed: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"enabled": {
										Type:     schema.TypeBool,
										Optional: true,
										Computed: true,
									},
									"sessions_sampling_interval": {
										Type:     schema.TypeInt,
										Required: true,
									},
									"statements_sampling_interval": {
										Type:     schema.TypeInt,
										Required: true,
									},
								},
							},
						},
						"access": {
							Type:     schema.TypeList,
							MaxItems: 1,
							Optional: true,
							Computed: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"data_lens": {
										Type:     schema.TypeBool,
										Optional: true,
										Default:  false,
									},
									"web_sql": {
										Type:     schema.TypeBool,
										Optional: true,
										Computed: true,
									},
								},
							},
						},
						"postgresql_config": {
							Type:             schema.TypeMap,
							Optional:         true,
							Computed:         true,
							DiffSuppressFunc: generateMapSchemaDiffSuppressFunc(mdbPGSettingsFieldsInfo),
							ValidateFunc:     generateMapSchemaValidateFunc(mdbPGSettingsFieldsInfo),
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
					},
				},
			},


			"host": {
				Type:     schema.TypeList,
				MinItems: 1,
				Required: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"zone": {
							Type:     schema.TypeString,
							Required: true,
						},
						"subnet_id": {
							Type:     schema.TypeString,
							Optional: true,
							Computed: true,
						},
						"assign_public_ip": {
							Type:     schema.TypeBool,
							Optional: true,
							Default:  false,
						},
						"fqdn": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"role": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"name": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"replication_source": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"priority": {
							Type:     schema.TypeInt,
							Optional: true,
						},
						"replication_source_name": {
							Type:     schema.TypeString,
							Optional: true,
						},
					},
				},
			},
			"folder_id": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"description": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"labels": {
				Type:     schema.TypeMap,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
				Set:      schema.HashString,
			},
			"created_at": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"health": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"status": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"security_group_ids": {
				Type:     schema.TypeSet,
				Elem:     &schema.Schema{Type: schema.TypeString},
				Set:      schema.HashString,
				Optional: true,
			},
			"host_master_name": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"restore": {
				Type:     schema.TypeList,
				MaxItems: 1,
				Optional: true,
				ForceNew: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"backup_id": {
							Type:     schema.TypeString,
							Required: true,
							ForceNew: true,
						},
						"time_inclusive": {
							Type:     schema.TypeBool,
							Optional: true,
							ForceNew: true,
						},
						"time": {
							Type:         schema.TypeString,
							Optional:     true,
							ForceNew:     true,
							ValidateFunc: stringToTimeValidateFunc,
						},
					},
				},
			},
		},
	}
}

func resourceYandexMDBPostgreSQLClusterRead(d *schema.ResourceData, meta interface{}) error {
	config := meta.(*Config)

	ctx, cancel := config.ContextWithTimeout(d.Timeout(schema.TimeoutRead))
	defer cancel()

	cluster, err := config.sdk.MDB().PostgreSQL().Cluster().Get(ctx, &postgresql.GetClusterRequest{
		ClusterId: d.Id(),
	})
	if err != nil {
		return handleNotFoundError(err, d, fmt.Sprintf("Cluster %q", d.Id()))
	}

	createdAt, err := getTimestamp(cluster.CreatedAt)
	if err != nil {
		return err
	}

	d.Set("created_at", createdAt)
	d.Set("health", cluster.GetHealth().String())
	d.Set("status", cluster.GetStatus().String())
	d.Set("folder_id", cluster.GetFolderId())
	d.Set("name", cluster.GetName())
	d.Set("description", cluster.GetDescription())
	d.Set("environment", cluster.GetEnvironment().String())
	d.Set("network_id", cluster.GetNetworkId())

	if err := d.Set("labels", cluster.GetLabels()); err != nil {
		return err
	}

	pgClusterConf, err := flattenPGClusterConfig(cluster.Config, d)
	if err != nil {
		return err
	}

	if err := d.Set("config", pgClusterConf); err != nil {
		return err
	}


	hosts, err := listPGHosts(ctx, config, d.Id())
	if err != nil {
		return err
	}

	fHosts, hostMasterName, err := flattenPGHosts(d, hosts, false)
	if err != nil {
		return err
	}

	if err := d.Set("host", fHosts); err != nil {
		return err
	}
	if err := d.Set("host_master_name", hostMasterName); err != nil {
		return err
	}

	if err := d.Set("security_group_ids", cluster.SecurityGroupIds); err != nil {
		return err
	}

	return nil
}


func resourceYandexMDBPostgreSQLClusterCreate(d *schema.ResourceData, meta interface{}) error {
	config := meta.(*Config)

	req, err := prepareCreatePostgreSQLRequest(d, config)

	if err != nil {
		return err
	}

	if backupID, ok := d.GetOk("restore.0.backup_id"); ok && backupID != "" {
		return resourceYandexMDBPostgreSQLClusterRestore(d, meta, req, backupID.(string))
	}

	ctx, cancel := config.ContextWithTimeout(d.Timeout(schema.TimeoutCreate))
	defer cancel()

	op, err := config.sdk.WrapOperation(config.sdk.MDB().PostgreSQL().Cluster().Create(ctx, req))
	if err != nil {
		return fmt.Errorf("Error while requesting API to create PostgreSQL Cluster: %s", err)
	}

	protoMetadata, err := op.Metadata()
	if err != nil {
		return fmt.Errorf("Error while get PostgreSQL Cluster create operation metadata: %s", err)
	}

	md, ok := protoMetadata.(*postgresql.CreateClusterMetadata)
	if !ok {
		return fmt.Errorf("Could not get PostgreSQL Cluster ID from create operation metadata")
	}

	d.SetId(md.ClusterId)

	err = op.Wait(ctx)
	if err != nil {
		return fmt.Errorf("Error while waiting for operation to create PostgreSQL Cluster: %s", err)
	}

	if _, err := op.Response(); err != nil {
		return fmt.Errorf("PostgreSQL Cluster creation failed: %s", err)
	}

	if err := createPGClusterHosts(ctx, config, d); err != nil {
		return fmt.Errorf("PostgreSQL Cluster %v hosts creation failed: %s", d.Id(), err)
	}

	if err := updateMasterPGClusterHosts(d, meta); err != nil {
		return fmt.Errorf("PostgreSQL Cluster %v hosts set master failed: %s", d.Id(), err)
	}

	return resourceYandexMDBPostgreSQLClusterRead(d, meta)
}

func resourceYandexMDBPostgreSQLClusterRestore(d *schema.ResourceData, meta interface{}, createClusterRequest *postgresql.CreateClusterRequest, backupID string) error {
	config := meta.(*Config)

	timeBackup := time.Now()
	timeInclusive := false

	if backupTime, ok := d.GetOk("restore.0.time"); ok {
		var err error
		timeBackup, err = parseStringToTime(backupTime.(string))
		if err != nil {
			return fmt.Errorf("Error while parsing restore.0.time to create PostgreSQL Cluster from backup %v, value: %v error: %s", backupID, backupTime, err)
		}
	}

	if timeInclusiveData, ok := d.GetOk("restore.0.time_inclusive"); ok {
		timeInclusive = timeInclusiveData.(bool)
	}

	ctx, cancel := config.ContextWithTimeout(d.Timeout(schema.TimeoutCreate))
	defer cancel()

	op, err := config.sdk.WrapOperation(config.sdk.MDB().PostgreSQL().Cluster().Restore(ctx, &postgresql.RestoreClusterRequest{
		BackupId: backupID,
		Time: &timestamp.Timestamp{
			Seconds: timeBackup.Unix(),
		},
		TimeInclusive:    timeInclusive,
		Name:             createClusterRequest.Name,
		Description:      createClusterRequest.Description,
		Labels:           createClusterRequest.Labels,
		Environment:      createClusterRequest.Environment,
		ConfigSpec:       createClusterRequest.ConfigSpec,
		HostSpecs:        createClusterRequest.HostSpecs,
		NetworkId:        createClusterRequest.NetworkId,
		FolderId:         createClusterRequest.FolderId,
		SecurityGroupIds: createClusterRequest.SecurityGroupIds,
	}))
	if err != nil {
		return fmt.Errorf("Error while requesting API to create PostgreSQL Cluster from backup %v: %s", backupID, err)
	}

	protoMetadata, err := op.Metadata()
	if err != nil {
		return fmt.Errorf("Error while get PostgreSQL Cluster create from backup %v operation metadata: %s", backupID, err)
	}

	md, ok := protoMetadata.(*postgresql.RestoreClusterMetadata)
	if !ok {
		return fmt.Errorf("Could not get PostgreSQL Cluster ID from create from backup %v operation metadata", backupID)
	}

	d.SetId(md.ClusterId)

	err = op.Wait(ctx)
	if err != nil {
		return fmt.Errorf("Error while waiting for operation to create PostgreSQL Cluster from backup %v: %s", backupID, err)
	}

	if _, err := op.Response(); err != nil {
		return fmt.Errorf("PostgreSQL Cluster creation from backup %v failed: %s", backupID, err)
	}

	if err := createPGClusterHosts(ctx, config, d); err != nil {
		return fmt.Errorf("PostgreSQL Cluster %v hosts creation from backup %v failed: %s", d.Id(), backupID, err)
	}

	if err := updateMasterPGClusterHosts(d, meta); err != nil {
		return fmt.Errorf("PostgreSQL Cluster %v hosts set master failed: %s", d.Id(), err)
	}

	return resourceYandexMDBPostgreSQLClusterRead(d, meta)
}

func prepareCreatePostgreSQLRequest(d *schema.ResourceData, meta *Config) (*postgresql.CreateClusterRequest, error) {
	labels, err := expandLabels(d.Get("labels"))
	if err != nil {
		return nil, fmt.Errorf("error while expanding labels on PostgreSQL Cluster create: %s", err)
	}

	folderID, err := getFolderID(d, meta)
	if err != nil {
		return nil, fmt.Errorf("Error getting folder ID while creating PostgreSQL Cluster: %s", err)
	}

	hostsFromScheme, err := expandPGHosts(d)
	if err != nil {
		return nil, fmt.Errorf("Error while expanding host specs on PostgreSQL Cluster create: %s", err)
	}

	e := d.Get("environment").(string)
	env, err := parsePostgreSQLEnv(e)
	if err != nil {
		return nil, fmt.Errorf("Error resolving environment while creating PostgreSQL Cluster: %s", err)
	}

	confSpec, _, err := expandPGConfigSpec(d)
	if err != nil {
		return nil, fmt.Errorf("Error while expanding cluster config on PostgreSQL Cluster create: %s", err)
	}

	hostSpecs := make([]*postgresql.HostSpec, 0)
	for _, host := range hostsFromScheme {
		if host.HostSpec.ReplicationSource == "" {
			hostSpecs = append(hostSpecs, host.HostSpec)
		}
	}

	securityGroupIds := expandSecurityGroupIds(d.Get("security_group_ids"))

	req := &postgresql.CreateClusterRequest{
		FolderId:         folderID,
		Name:             d.Get("name").(string),
		Description:      d.Get("description").(string),
		NetworkId:        d.Get("network_id").(string),
		Labels:           labels,
		Environment:      env,
		ConfigSpec:       confSpec,
		HostSpecs:        hostSpecs,
		SecurityGroupIds: securityGroupIds,
	}

	return req, nil
}

func resourceYandexMDBPostgreSQLClusterUpdate(d *schema.ResourceData, meta interface{}) error {

	d.Partial(true)

	if err := setPGFolderID(d, meta); err != nil {
		return err
	}

	if err := updatePGClusterParams(d, meta); err != nil {
		return err
	}

	if d.HasChange("host") {
		if err := updatePGClusterHosts(d, meta); err != nil {
			return err
		}
	}

	if d.HasChange("host_master_name") {

		if err := updateMasterPGClusterHosts(d, meta); err != nil {
			return err
		}
	}

	d.Partial(false)

	return resourceYandexMDBPostgreSQLClusterRead(d, meta)
}

func updatePGClusterParams(d *schema.ResourceData, meta interface{}) error {
	req, updateFieldConfigName, err := getPGClusterUpdateRequest(d)
	if err != nil {
		return err
	}

	mdbPGUpdateFieldsMap := map[string]string{
		"name":                             "name",
		"description":                      "description",
		"labels":                           "labels",
		"config.0.version":                 "config_spec.version",
		"config.0.autofailover":            "config_spec.autofailover",
		"config.0.pooler_config":           "config_spec.pooler_config",
		"config.0.access":                  "config_spec.access",
		"config.0.performance_diagnostics": "config_spec.performance_diagnostics",
		"config.0.backup_window_start":     "config_spec.backup_window_start",
		"config.0.resources":               "config_spec.resources",
		"security_group_ids":               "security_group_ids",
	}

	if updateFieldConfigName != "" {
		mdbPGUpdateFieldsMap["config.0.postgresql_config"] = "config_spec." + updateFieldConfigName
	}

	onDone := []func(){}
	updatePath := []string{}
	for field, path := range mdbPGUpdateFieldsMap {
		if d.HasChange(field) {
			updatePath = append(updatePath, path)
			onDone = append(onDone, func() {
				d.SetPartial(field)
			})
		}
	}

	if len(updatePath) == 0 {
		return nil
	}

	req.UpdateMask = &field_mask.FieldMask{Paths: updatePath}

	config := meta.(*Config)
	ctx, cancel := config.ContextWithTimeout(d.Timeout(schema.TimeoutUpdate))
	defer cancel()

	op, err := config.sdk.WrapOperation(config.sdk.MDB().PostgreSQL().Cluster().Update(ctx, req))
	if err != nil {
		return fmt.Errorf("error while requesting API to update PostgreSQL Cluster %q: %s", d.Id(), err)
	}

	err = op.Wait(ctx)
	if err != nil {
		return fmt.Errorf("error while waiting for operation to update PostgreSQL Cluster %q: %s", d.Id(), err)
	}

	for _, f := range onDone {
		f()
	}

	return nil
}

func getPGClusterUpdateRequest(d *schema.ResourceData) (ucr *postgresql.UpdateClusterRequest, updateFieldConfigName string, err error) {
	labels, err := expandLabels(d.Get("labels"))
	if err != nil {
		return nil, updateFieldConfigName, fmt.Errorf("error expanding labels while updating PostgreSQL Cluster: %s", err)
	}

	configSpec, updateFieldConfigName, err := expandPGConfigSpec(d)
	if err != nil {
		return nil, updateFieldConfigName, fmt.Errorf("error expanding config while updating PostgreSQL Cluster: %s", err)
	}

	securityGroupIds := expandSecurityGroupIds(d.Get("security_group_ids"))

	req := &postgresql.UpdateClusterRequest{
		ClusterId:        d.Id(),
		Name:             d.Get("name").(string),
		Description:      d.Get("description").(string),
		Labels:           labels,
		ConfigSpec:       configSpec,
		SecurityGroupIds: securityGroupIds,
	}

	return req, updateFieldConfigName, nil
}







func validatePGAssignPublicIP(currentHosts []*postgresql.Host, targetHosts []*PostgreSQLHostSpec) error {
	for _, currentHost := range currentHosts {
		for _, targetHost := range targetHosts {
			if currentHost.Name == targetHost.Fqdn &&
				(currentHost.AssignPublicIp != targetHost.HostSpec.AssignPublicIp) {
				return fmt.Errorf("forbidden to change assign_public_ip setting for existing host %s in resource_yandex_mdb_postgresql_cluster, "+
					"if you really need it you should delete one host and add another", currentHost.Name)
			}
		}
	}
	return nil
}

func updatePGClusterHosts(d *schema.ResourceData, meta interface{}) error {
	config := meta.(*Config)
	ctx, cancel := config.ContextWithTimeout(d.Timeout(schema.TimeoutUpdate))
	defer cancel()

	currHosts, err := listPGHosts(ctx, config, d.Id())
	if err != nil {
		return err
	}

	targetHosts, err := expandPGHosts(d)
	if err != nil {
		return err
	}

	err = validatePGAssignPublicIP(currHosts, targetHosts)
	if err != nil {
		return err
	}

	err = createPGClusterHosts(ctx, config, d)
	if err != nil {
		return err
	}

	currHosts, err = listPGHosts(ctx, config, d.Id())
	if err != nil {
		return err
	}

	compareHostsInfo, err := comparePGHostsInfo(d, currHosts, true)
	if err != nil {
		return err
	}

	hostsToDelete := []string{}

	for _, hostInfo := range compareHostsInfo.hostsInfo {
		if !hostInfo.isNew {
			hostsToDelete = append(hostsToDelete, hostInfo.fqdn)
		} else if compareHostsInfo.haveHostWithName && (hostInfo.oldPriority != hostInfo.newPriority || hostInfo.oldReplicationSource != hostInfo.newReplicationSource) {

			if err := updatePGHost(ctx, config, d, &postgresql.UpdateHostSpec{
				HostName:          hostInfo.fqdn,
				ReplicationSource: hostInfo.newReplicationSource,
				Priority:          &wrappers.Int64Value{Value: int64(hostInfo.newPriority)},
			}); err != nil {
				return err
			}
		}
	}

	if err := deletePGHosts(ctx, config, d, hostsToDelete); err != nil {
		return err
	}

	d.SetPartial("host")
	return nil
}

func createPGClusterHosts(ctx context.Context, config *Config, d *schema.ResourceData) error {

	currHosts, err := listPGHosts(ctx, config, d.Id())
	if err != nil {
		return err
	}

	compareHostsInfo, err := comparePGHostsInfo(d, currHosts, true)

	if err != nil {
		return err
	}

	if compareHostsInfo.hierarhyExists && len(compareHostsInfo.createHostsInfo) == 0 {
		return fmt.Errorf("Create cluster hosts error. Exists host with replication source, which can't be created. Possibly there is a loop")
	}

	if compareHostsInfo.haveHostWithName {
		for _, newHostInfo := range compareHostsInfo.createHostsInfo {
			err := addPGHost(ctx, config, d, &postgresql.HostSpec{
				ZoneId:            newHostInfo.zone,
				SubnetId:          newHostInfo.subnetID,
				AssignPublicIp:    newHostInfo.assignPublicIP,
				ReplicationSource: newHostInfo.newReplicationSource,
				Priority:          &wrappers.Int64Value{Value: int64(newHostInfo.newPriority)},
			})
			if err != nil {
				return err
			}
		}
	} else {
		for _, newHostInfo := range compareHostsInfo.createHostsInfo {
			err := addPGHost(ctx, config, d, &postgresql.HostSpec{
				ZoneId:         newHostInfo.zone,
				SubnetId:       newHostInfo.subnetID,
				AssignPublicIp: newHostInfo.assignPublicIP,
			})
			if err != nil {
				return err
			}
		}
	}

	if compareHostsInfo.hierarhyExists {
		return createPGClusterHosts(ctx, config, d)
	}

	return nil
}

func updateMasterPGClusterHosts(d *schema.ResourceData, meta interface{}) error {
	config := meta.(*Config)
	ctx, cancel := config.ContextWithTimeout(d.Timeout(schema.TimeoutUpdate))
	defer cancel()

	currHosts, err := listPGHosts(ctx, config, d.Id())
	if err != nil {
		return err
	}
	compareHostsInfo, err := comparePGHostsInfo(d, currHosts, true)
	if err != nil {
		return err
	}

	if !compareHostsInfo.haveHostWithName {
		return nil
	}

	for _, hostInfo := range compareHostsInfo.hostsInfo {
		if compareHostsInfo.hostMasterName == hostInfo.name && hostInfo.role != postgresql.Host_MASTER {
			err = startPGFailover(ctx, config, d, hostInfo.fqdn)
			if err != nil {
				return err
			}
			break
		}
	}

	return nil
}

func resourceYandexMDBPostgreSQLClusterDelete(d *schema.ResourceData, meta interface{}) error {
	config := meta.(*Config)

	log.Printf("[DEBUG] Deleting PostgreSQL Cluster %q", d.Id())

	req := &postgresql.DeleteClusterRequest{
		ClusterId: d.Id(),
	}

	ctx, cancel := config.ContextWithTimeout(d.Timeout(schema.TimeoutDelete))
	defer cancel()

	op, err := config.sdk.WrapOperation(config.sdk.MDB().PostgreSQL().Cluster().Delete(ctx, req))
	if err != nil {
		return handleNotFoundError(err, d, fmt.Sprintf("PostgreSQL Cluster %q", d.Id()))
	}

	err = op.Wait(ctx)
	if err != nil {
		return err
	}

	_, err = op.Response()
	if err != nil {
		return err
	}

	log.Printf("[DEBUG] Finished deleting PostgreSQL Cluster %q", d.Id())

	return nil
}

func createPGUser(ctx context.Context, config *Config, d *schema.ResourceData, user *postgresql.UserSpec) error {
	op, err := config.sdk.WrapOperation(
		config.sdk.MDB().PostgreSQL().User().Create(ctx, &postgresql.CreateUserRequest{
			ClusterId: d.Id(),
			UserSpec:  user,
		}),
	)
	if err != nil {
		return fmt.Errorf("error while requesting API to create user for PostgreSQL Cluster %q: %s", d.Id(), err)
	}

	err = op.Wait(ctx)
	if err != nil {
		return fmt.Errorf("error while creating user for PostgreSQL Cluster %q: %s", d.Id(), err)
	}

	if _, err := op.Response(); err != nil {
		return fmt.Errorf("creating user for PostgreSQL Cluster %q failed: %s", d.Id(), err)
	}

	return nil
}



func addPGHost(ctx context.Context, config *Config, d *schema.ResourceData, host *postgresql.HostSpec) error {
	op, err := config.sdk.WrapOperation(
		config.sdk.MDB().PostgreSQL().Cluster().AddHosts(ctx, &postgresql.AddClusterHostsRequest{
			ClusterId: d.Id(),
			HostSpecs: []*postgresql.HostSpec{host},
		}),
	)
	if err != nil {
		return fmt.Errorf("error while requesting API to create host for PostgreSQL Cluster %q: %s", d.Id(), err)
	}

	err = op.Wait(ctx)
	if err != nil {
		return fmt.Errorf("error while creating host for PostgreSQL Cluster %q: %s", d.Id(), err)
	}

	if _, err := op.Response(); err != nil {
		return fmt.Errorf("creating host for PostgreSQL Cluster %q failed: %s", d.Id(), err)
	}

	return nil
}

func deletePGHosts(ctx context.Context, config *Config, d *schema.ResourceData, hostNamesToDelete []string) error {
	if len(hostNamesToDelete) == 0 {
		return nil
	}
	for _, hostToDelete := range hostNamesToDelete {
		if err := deletePGHost(ctx, config, d, hostToDelete); err != nil {
			return err
		}
	}

	return nil
}
func deletePGHost(ctx context.Context, config *Config, d *schema.ResourceData, name string) error {
	op, err := config.sdk.WrapOperation(
		config.sdk.MDB().PostgreSQL().Cluster().DeleteHosts(ctx, &postgresql.DeleteClusterHostsRequest{
			ClusterId: d.Id(),
			HostNames: []string{name},
		}),
	)
	if err != nil {
		return fmt.Errorf("error while requesting API to delete host from PostgreSQL Cluster %q: %s", d.Id(), err)
	}

	err = op.Wait(ctx)
	if err != nil {
		return fmt.Errorf("error while deleting host from PostgreSQL Cluster %q: %s", d.Id(), err)
	}

	if _, err := op.Response(); err != nil {
		return fmt.Errorf("deleting host from PostgreSQL Cluster %q failed: %s", d.Id(), err)
	}

	return nil
}

func startPGFailover(ctx context.Context, config *Config, d *schema.ResourceData, hostName string) error {
	op, err := config.sdk.WrapOperation(
		config.sdk.MDB().PostgreSQL().Cluster().StartFailover(ctx, &postgresql.StartClusterFailoverRequest{
			ClusterId: d.Id(),
			HostName:  hostName,
		}),
	)
	if err != nil {
		return fmt.Errorf("error while requesting API to start failover host in PostgreSQL Cluster %q - host %v: %s", d.Id(), hostName, err)
	}

	err = op.Wait(ctx)
	if err != nil {
		return fmt.Errorf("error while start failover host in PostgreSQL Cluster %q - host %v: %s", d.Id(), hostName, err)
	}

	if _, err := op.Response(); err != nil {
		return fmt.Errorf("start failover host in PostgreSQL Cluster %q - host %v failed: %s", d.Id(), hostName, err)
	}

	return nil
}

func updatePGHost(ctx context.Context, config *Config, d *schema.ResourceData, host *postgresql.UpdateHostSpec) error {
	op, err := config.sdk.WrapOperation(
		config.sdk.MDB().PostgreSQL().Cluster().UpdateHosts(ctx, &postgresql.UpdateClusterHostsRequest{
			ClusterId:       d.Id(),
			UpdateHostSpecs: []*postgresql.UpdateHostSpec{host},
		}),
	)
	if err != nil {
		return fmt.Errorf("error while requesting API to update host for PostgreSQL Cluster %q - host %v: %s", d.Id(), host.HostName, err)
	}

	err = op.Wait(ctx)
	if err != nil {
		return fmt.Errorf("error while updating host for PostgreSQL Cluster %q - host %v: %s", d.Id(), host.HostName, err)
	}

	if _, err := op.Response(); err != nil {
		return fmt.Errorf("updating host for PostgreSQL Cluster %q - host %v failed: %s", d.Id(), host.HostName, err)
	}

	return nil
}

func listPGHosts(ctx context.Context, config *Config, id string) ([]*postgresql.Host, error) {
	hosts := []*postgresql.Host{}
	pageToken := ""

	for {
		resp, err := config.sdk.MDB().PostgreSQL().Cluster().ListHosts(ctx, &postgresql.ListClusterHostsRequest{
			ClusterId: id,
			PageSize:  1000,
			PageToken: pageToken,
		})
		if err != nil {
			return nil, fmt.Errorf("Error while getting list of hosts for PostgreSQL Cluster '%q': %s", id, err)
		}

		hosts = append(hosts, resp.Hosts...)

		if resp.NextPageToken == "" {
			break
		}
		pageToken = resp.NextPageToken
	}

	return hosts, nil
}

func setPGFolderID(d *schema.ResourceData, meta interface{}) error {
	config := meta.(*Config)

	ctx, cancel := config.ContextWithTimeout(d.Timeout(schema.TimeoutRead))
	defer cancel()

	cluster, err := config.sdk.MDB().PostgreSQL().Cluster().Get(ctx, &postgresql.GetClusterRequest{
		ClusterId: d.Id(),
	})
	if err != nil {
		return handleNotFoundError(err, d, fmt.Sprintf("Cluster %q", d.Id()))
	}

	folderID, ok := d.GetOk("folder_id")
	if !ok {
		return nil
	}
	if folderID == "" {
		return nil
	}

	if cluster.FolderId != folderID {

		op, err := config.sdk.WrapOperation(
			config.sdk.MDB().PostgreSQL().Cluster().Move(ctx, &postgresql.MoveClusterRequest{
				ClusterId:           d.Id(),
				DestinationFolderId: folderID.(string),
			}),
		)
		if err != nil {
			return fmt.Errorf("error while requesting API to move PostgreSQL Cluster %q to folder %v: %s", d.Id(), folderID, err)
		}

		err = op.Wait(ctx)
		if err != nil {
			return fmt.Errorf("error while moving PostgreSQL Cluster %q to folder %v: %s", d.Id(), folderID, err)
		}

		if _, err := op.Response(); err != nil {
			return fmt.Errorf("moving PostgreSQL Cluster %q to folder %v failed: %s", d.Id(), folderID, err)
		}

	}

	return nil
}