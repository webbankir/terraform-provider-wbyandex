package wbyandex

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/hashicorp/terraform-plugin-sdk/helper/mutexkv"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
)

const (
	defaultMaxRetries      = 5
	defaultEndpoint        = "api.cloud.yandex.net:443"
	defaultStorageEndpoint = "storage.yandexcloud.net"
	defaultYMQEndpoint     = "message-queue.api.cloud.yandex.net"
)

// Global MutexKV
var mutexKV = mutexkv.NewMutexKV()

func Provider() terraform.ResourceProvider {
	return provider(false)
}

func emptyFolderProvider() terraform.ResourceProvider {
	return provider(true)
}

func provider(emptyFolder bool) terraform.ResourceProvider {
	provider := &schema.Provider{
		Schema: map[string]*schema.Schema{
			"endpoint": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("YC_ENDPOINT", defaultEndpoint),
				Description: descriptions["endpoint"],
			},
			"folder_id": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("YC_FOLDER_ID", nil),
				Description: descriptions["folder_id"],
			},
			"cloud_id": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("YC_CLOUD_ID", nil),
				Description: descriptions["cloud_id"],
			},
			"zone": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("YC_ZONE", nil),
				Description: descriptions["zone"],
			},
			"token": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("YC_TOKEN", nil),
				Description: descriptions["token"],
			},
			"service_account_key_file": {
				Type:          schema.TypeString,
				Optional:      true,
				DefaultFunc:   schema.EnvDefaultFunc("YC_SERVICE_ACCOUNT_KEY_FILE", nil),
				Description:   descriptions["service_account_key_file"],
				ConflictsWith: []string{"token"},
				ValidateFunc:  validateSAKey,
			},
			"storage_endpoint": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("YC_STORAGE_ENDPOINT_URL", defaultStorageEndpoint),
				Description: descriptions["storage_endpoint"],
			},
			"storage_access_key": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("YC_STORAGE_ACCESS_KEY", nil),
				Description: descriptions["storage_access_key"],
			},
			"storage_secret_key": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("YC_STORAGE_SECRET_KEY", nil),
				Description: descriptions["storage_secret_key"],
			},
			"insecure": {
				Type:        schema.TypeBool,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("YC_INSECURE", false),
				Description: descriptions["insecure"],
			},
			"plaintext": {
				Type:        schema.TypeBool,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("YC_PLAINTEXT", false),
				Description: descriptions["plaintext"],
			},
			"max_retries": {
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     defaultMaxRetries,
				Description: descriptions["max_retries"],
			},
			"ymq_endpoint": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("YC_MESSAGE_QUEUE_ENDPOINT", defaultYMQEndpoint),
				Description: descriptions["ymq_endpoint"],
			},
			"ymq_access_key": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("YC_MESSAGE_QUEUE_ACCESS_KEY", nil),
				Description: descriptions["ymq_access_key"],
			},
			"ymq_secret_key": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				DefaultFunc: schema.EnvDefaultFunc("YC_MESSAGE_QUEUE_SECRET_KEY", nil),
				Description: descriptions["ymq_secret_key"],
			},
		},

		DataSourcesMap: map[string]*schema.Resource{

		},

		ResourcesMap: map[string]*schema.Resource{
			"wbyandex_mdb_postgresql_user":     resourceYandexMDBPostgreSQLUser(),
			"wbyandex_mdb_postgresql_database": resourceYandexMDBPostgreSQLDatabase(),
			"wbyandex_mdb_postgresql_cluster":  resourceYandexMDBPostgreSQLCluster(),
		},
	}
	provider.ConfigureFunc = providerConfigure(provider, emptyFolder)

	return provider
}

var descriptions = map[string]string{
	"endpoint": "The API endpoint for Yandex.Cloud SDK client.",

	"folder_id": "The default folder ID where resources will be placed.",

	"cloud_id": "ID of Yandex.Cloud tenant.",

	"zone": "The zone where operations will take place. Examples\n" +
		"are ru-central1-a, ru-central2-c, etc.",

	"token": "The access token for API operations.",

	"service_account_key_file": "Either the path to or the contents of a Service Account key file in JSON format.",

	"insecure": "Explicitly allow the provider to perform \"insecure\" SSL requests. If omitted," +
		"default value is `false`.",

	"plaintext": "Disable use of TLS. Default value is `false`.",

	"max_retries": "The maximum number of times an API request is being executed. \n" +
		"If the API request still fails, an error is thrown.",

	"storage_endpoint": "Yandex.Cloud storage service endpoint. Default is \n" + defaultStorageEndpoint,

	"storage_access_key": "Yandex.Cloud storage service access key. \n" +
		"Used when a storage data/resource doesn't have an access key explicitly specified.",

	"storage_secret_key": "Yandex.Cloud storage service secret key. \n" +
		"Used when a storage data/resource doesn't have a secret key explicitly specified.",

	"ymq_endpoint": "Yandex.Cloud Message Queue service endpoint. Default is \n" + defaultYMQEndpoint,

	"ymq_access_key": "Yandex.Cloud Message Queue service access key. \n" +
		"Used when a message queue resource doesn't have an access key explicitly specified.",

	"ymq_secret_key": "Yandex.Cloud Message Queue service secret key. \n" +
		"Used when a message queue resource doesn't have a secret key explicitly specified.",
}

func providerConfigure(provider *schema.Provider, emptyFolder bool) schema.ConfigureFunc {
	return func(d *schema.ResourceData) (interface{}, error) {
		config := Config{
			Token:                          d.Get("token").(string),
			ServiceAccountKeyFileOrContent: d.Get("service_account_key_file").(string),
			Zone:                           d.Get("zone").(string),
			FolderID:                       d.Get("folder_id").(string),
			CloudID:                        d.Get("cloud_id").(string),
			Endpoint:                       d.Get("endpoint").(string),
			Plaintext:                      d.Get("plaintext").(bool),
			Insecure:                       d.Get("insecure").(bool),
			MaxRetries:                     d.Get("max_retries").(int),
			StorageEndpoint:                d.Get("storage_endpoint").(string),
			StorageAccessKey:               d.Get("storage_access_key").(string),
			StorageSecretKey:               d.Get("storage_secret_key").(string),
			YMQEndpoint:                    d.Get("ymq_endpoint").(string),
			YMQAccessKey:                   d.Get("ymq_access_key").(string),
			YMQSecretKey:                   d.Get("ymq_secret_key").(string),
		}

		if emptyFolder {
			config.FolderID = ""
		}

		terraformVersion := provider.TerraformVersion
		if terraformVersion == "" {
			// Terraform 0.12 introduced this field to the protocol
			// We can therefore assume that if it's missing it's 0.10 or 0.11
			terraformVersion = "0.11+compatible"
		}

		if err := config.initAndValidate(provider.StopContext(), terraformVersion, false); err != nil {
			return nil, err
		}

		return &config, nil
	}
}

func validateSAKey(v interface{}, k string) (warnings []string, errors []error) {
	if v == nil || v.(string) == "" {
		return
	}

	saKey := v.(string)
	// if this is a path to file and we can stat it, assume it's ok
	if _, err := os.Stat(saKey); err == nil {
		return
	}

	// else check for a valid json data value
	var f map[string]interface{}
	if err := json.Unmarshal([]byte(saKey), &f); err != nil {
		errors = append(errors, fmt.Errorf("JSON in %q are not valid: %s", saKey, err))
	}

	return
}
