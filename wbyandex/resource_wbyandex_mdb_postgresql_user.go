package wbyandex

import (
	"fmt"
	"log"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/yandex-cloud/go-genproto/yandex/cloud/mdb/postgresql/v1"
)

const (
	wbyandexMDBPostgreSQLUserCreateTimeout = 30 * time.Minute
	wbyandexMDBPostgreSQLUserDeleteTimeout = 15 * time.Minute
	wbyandexMDBPostgreSQLUserUpdateTimeout = 60 * time.Minute
)

func resourceYandexMDBPostgreSQLUser() *schema.Resource {
	return &schema.Resource{
		Create: resourceYandexMDBPostgreSQLUserCreate,
		Read:   resourceYandexMDBPostgreSQLUserRead,
		Update: resourceYandexMDBPostgreSQLUserUpdate,
		Delete: resourceYandexMDBPostgreSQLUserDelete,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(wbyandexMDBPostgreSQLUserCreateTimeout),
			Update: schema.DefaultTimeout(wbyandexMDBPostgreSQLUserUpdateTimeout),
			Delete: schema.DefaultTimeout(wbyandexMDBPostgreSQLUserDeleteTimeout),
		},

		SchemaVersion: 0,

		Schema: map[string]*schema.Schema{
			"cluster_id": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"name": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"password": {
				Type:      schema.TypeString,
				Required:  true,
				Sensitive: true,
			},
			"login": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},
			"grants": {
				Type:     schema.TypeList,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},
			"permission": {
				Type:     schema.TypeSet,
				Optional: true,
				Computed: true,
				Set:      pgUserPermissionHash,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"database_name": {
							Type:     schema.TypeString,
							Required: true,
						},
					},
				},
			},
			"conn_limit": {
				Type:     schema.TypeInt,
				Optional: true,
				Default:  50,
			},
			//"settings": {
			//	Type:             schema.TypeMap,
			//	Optional:         true,
			//	Computed:         true,
			//	DiffSuppressFunc: generateMapSchemaDiffSuppressFunc(mdbPGUserSettingsFieldsInfo),
			//	ValidateFunc:     generateMapSchemaValidateFunc(mdbPGUserSettingsFieldsInfo),
			//	Elem: &schema.Schema{
			//		Type: schema.TypeString,
			//	},
			//},
		},
	}
}

func resourceYandexMDBPostgreSQLUserRead(d *schema.ResourceData, meta interface{}) error {
	config := meta.(*Config)

	ctx, cancel := config.ContextWithTimeout(d.Timeout(schema.TimeoutRead))
	defer cancel()
	clusterId, userName := getIdAndName(d.Id())


	user, err := config.sdk.MDB().PostgreSQL().User().Get(ctx, &postgresql.GetUserRequest{
		ClusterId: clusterId,
		UserName:  userName,
	})

	if err != nil {
		return err
	}

	permissions, err := flattenPGUserPermissions(user.Permissions)

	if err != nil {
		return err
	}

	if err := d.Set("name", user.GetName()); err != nil {
		return err
	}

	if err := d.Set("cluster_id", user.GetClusterId()); err != nil {
		return err
	}

	if err := d.Set("conn_limit", user.GetConnLimit()); err != nil {
		return err
	}

	if err := d.Set("login", user.GetLogin().Value); err != nil {
		return err
	}

	if err := d.Set("grants", user.GetGrants()); err != nil {
		return err
	}

	return d.Set("permission", permissions)
}

func resourceYandexMDBPostgreSQLUserCreate(d *schema.ResourceData, meta interface{}) error {
	config := meta.(*Config)

	ctx, cancel := config.ContextWithTimeout(d.Timeout(schema.TimeoutCreate))
	defer cancel()

	userSpec, err := expandPGUser(d, &postgresql.UserSpec{})
	if err != nil {
		return err
	}

	clusterId := d.Get("cluster_id").(string)

	op, err := config.sdk.WrapOperation(config.sdk.MDB().PostgreSQL().User().Create(ctx, &postgresql.CreateUserRequest{
		ClusterId: clusterId,
		UserSpec:  userSpec,
	}))

	if err != nil {
		return err
	}

	d.SetId(d.Get("cluster_id").(string) + "-" + userSpec.Name)

	err = op.Wait(ctx)
	if err != nil {
		return fmt.Errorf("error while waiting for operation to create PostgreSQL Cluster: %s", err)
	}

	if _, err := op.Response(); err != nil {
		return fmt.Errorf("PostgreSQL Cluster creation failed: %s", err)
	}

	return resourceYandexMDBPostgreSQLUserRead(d, meta)
}

func resourceYandexMDBPostgreSQLUserUpdate(d *schema.ResourceData, meta interface{}) error {
	config := meta.(*Config)

	clusterId, username := getIdAndName(d.Id())

	userSpec, err := expandPGUser(d, &postgresql.UserSpec{})

	if err != nil {
		return err
	}

	request := postgresql.UpdateUserRequest{
		ClusterId:   clusterId,
		UserName:    username,
		Password:    userSpec.Password,
		Grants:      userSpec.Grants,
		ConnLimit:   userSpec.ConnLimit.Value,
		Login:       userSpec.Login,
		Permissions: userSpec.Permissions,
	}

	d.Partial(true)
	if d.HasChange("conn_limit") ||
		d.HasChange("login") ||
		d.HasChange("grants") ||
		d.HasChange("permission") ||
		d.HasChange("password") {

		ctx, cancel := config.ContextWithTimeout(d.Timeout(schema.TimeoutCreate))
		defer cancel()

		op, err := config.sdk.WrapOperation(config.sdk.MDB().PostgreSQL().User().Update(ctx, &request))

		if err != nil {
			return err
		}

		err = op.Wait(ctx)
		if err != nil {
			return fmt.Errorf("error while waiting for operation to udpate PostgreSQL Cluster User %v with reason: '%s'", username, err)
		}

		if _, err := op.Response(); err != nil {
			return fmt.Errorf("PostgreSQL Cluster User update failed: %s", err)
		}

	}

	d.Partial(false)

	return resourceYandexMDBPostgreSQLUserRead(d, meta)
}

func resourceYandexMDBPostgreSQLUserDelete(d *schema.ResourceData, meta interface{}) error {
	config := meta.(*Config)

	clusterId, userName := getIdAndName(d.Id())
	log.Printf("[DEBUG] Deleting PostgreSQL Cluster User %q", userName)

	req := &postgresql.DeleteUserRequest{
		ClusterId: clusterId,
		UserName:  userName,
	}

	ctx, cancel := config.ContextWithTimeout(d.Timeout(schema.TimeoutDelete))
	defer cancel()

	op, err := config.sdk.WrapOperation(config.sdk.MDB().PostgreSQL().User().Delete(ctx, req))
	if err != nil {
		return err
	}

	err = op.Wait(ctx)
	if err != nil {
		return err
	}

	_, err = op.Response()
	if err != nil {
		return err
	}

	log.Printf("[DEBUG] Finished deleting PostgreSQL Cluster User %q", userName)

	return nil
}

