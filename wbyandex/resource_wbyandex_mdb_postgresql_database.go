package wbyandex

import (
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"

	"github.com/yandex-cloud/go-genproto/yandex/cloud/mdb/postgresql/v1"
)

func resourceYandexMDBPostgreSQLDatabase() *schema.Resource {
	return &schema.Resource{
		Create: resourceYandexMDBPostgreSQLDatabaseCreate,
		Read:   resourceYandexMDBPostgreSQLDatabaseRead,
		Update: resourceYandexMDBPostgreSQLDatabaseUpdate,
		Delete: resourceYandexMDBPostgreSQLDatabaseDelete,
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
			"owner": {
				Type:     schema.TypeString,
				Required: true,
			},
			"extension": {
				Type:     schema.TypeSet,
				Set:      pgExtensionHash,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"name": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"version": {
							Type:     schema.TypeString,
							Computed: true,
						},
					},
				},
			},
			"lc_collate": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"lc_type": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
		},
	}
}

func resourceYandexMDBPostgreSQLDatabaseRead(d *schema.ResourceData, meta interface{}) error {
	config := meta.(*Config)

	ctx, cancel := config.ContextWithTimeout(d.Timeout(schema.TimeoutRead))
	defer cancel()
	clusterId, databaseName := getIdAndName(d.Id())

	database, err := config.sdk.MDB().PostgreSQL().Database().Get(ctx, &postgresql.GetDatabaseRequest{
		ClusterId:    clusterId,
		DatabaseName: databaseName,
	})

	if err != nil {
		return err
	}

	extensions := flattenPGExtensions(database.Extensions)

	if err := d.Set("name", database.GetName()); err != nil {
		return err
	}

	if err := d.Set("cluster_id", database.GetClusterId()); err != nil {
		return err
	}

	if err := d.Set("lc_collate", database.GetLcCollate()); err != nil {
		return err
	}

	if err := d.Set("lc_type", database.GetLcCtype()); err != nil {
		return err
	}

	if err := d.Set("owner", database.GetOwner()); err != nil {
		return err
	}

	return d.Set("extension", extensions)
}

func resourceYandexMDBPostgreSQLDatabaseCreate(d *schema.ResourceData, meta interface{}) error {
	config := meta.(*Config)

	ctx, cancel := config.ContextWithTimeout(d.Timeout(schema.TimeoutCreate))
	defer cancel()

	databaseSpec, err := expandPGDatabase(d)
	if err != nil {
		return err
	}

	clusterId := d.Get("cluster_id").(string)

	op, err := config.sdk.WrapOperation(config.sdk.MDB().PostgreSQL().Database().Create(ctx, &postgresql.CreateDatabaseRequest{
		ClusterId:    clusterId,
		DatabaseSpec: databaseSpec,
	}))

	if err != nil {
		return err
	}

	d.SetId(d.Get("cluster_id").(string) + "-" + databaseSpec.Name)

	err = op.Wait(ctx)
	if err != nil {
		return fmt.Errorf("error while waiting for operation to create PostgreSQL Cluster: %s", err)
	}

	if _, err := op.Response(); err != nil {
		return fmt.Errorf("PostgreSQL Cluster creation failed: %s", err)
	}

	return resourceYandexMDBPostgreSQLDatabaseRead(d, meta)
}

func resourceYandexMDBPostgreSQLDatabaseDelete(d *schema.ResourceData, meta interface{}) error {
	config := meta.(*Config)

	clusterId, databaseName := getIdAndName(d.Id())
	log.Printf("[DEBUG] Deleting PostgreSQL Cluster Database %q", databaseName)

	req := &postgresql.DeleteDatabaseRequest{
		ClusterId:    clusterId,
		DatabaseName: databaseName,
	}

	ctx, cancel := config.ContextWithTimeout(d.Timeout(schema.TimeoutDelete))
	defer cancel()

	op, err := config.sdk.WrapOperation(config.sdk.MDB().PostgreSQL().Database().Delete(ctx, req))
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

	log.Printf("[DEBUG] Finished deleting PostgreSQL Cluster Database %q", databaseName)

	return nil
}

func resourceYandexMDBPostgreSQLDatabaseUpdate(d *schema.ResourceData, meta interface{}) error {
	config := meta.(*Config)

	clusterId, databaseName := getIdAndName(d.Id())
	databaseSpec, err := expandPGDatabase(d)

	if err != nil {
		return err
	}

	request := postgresql.UpdateDatabaseRequest{
		ClusterId:    clusterId,
		DatabaseName: databaseName,
		Extensions:   databaseSpec.Extensions,
	}

	d.Partial(true)
	if d.HasChange("extension") || d.HasChange("owner") {

		ctx, cancel := config.ContextWithTimeout(d.Timeout(schema.TimeoutCreate))
		defer cancel()

		op, err := config.sdk.WrapOperation(config.sdk.MDB().PostgreSQL().Database().Update(ctx, &request))

		if err != nil {
			return err
		}

		err = op.Wait(ctx)
		if err != nil {
			return fmt.Errorf("error while waiting for operation to udpate PostgreSQL Cluster Database %v with reason: '%s'", databaseName, err)
		}

		if _, err := op.Response(); err != nil {
			return fmt.Errorf("PostgreSQL Cluster Database update failed: %s", err)
		}

	}

	d.Partial(false)

	return resourceYandexMDBPostgreSQLDatabaseRead(d, meta)
}
