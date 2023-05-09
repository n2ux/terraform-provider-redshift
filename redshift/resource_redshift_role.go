package redshift

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/lib/pq"
)

const (
	roleNameAttr           = "name"
	roleOwnerAttr          = "owner"
)

func redshiftRole() *schema.Resource {
	return &schema.Resource{
		Description: `Amazon Redshift roles can be created and dropped by a database superuser or a user with CREATE ROLE privilege.`,
		Create: RedshiftResourceFunc(resourceRedshiftRoleCreate),
		Read:   RedshiftResourceFunc(resourceRedshiftRoleRead),
		Update: RedshiftResourceFunc(resourceRedshiftRoleUpdate),
		Delete: RedshiftResourceFunc(
			RedshiftResourceRetryOnPQErrors(resourceRedshiftRoleDelete),
		),
		Exists: RedshiftResourceExistsFunc(resourceRedshiftRoleExists),
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			roleNameAttr: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The name of the role to create.",
			},
			roleOwnerAttr: {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "postgres",
				Sensitive:   true,
				Description: "Sets the role's owner.",
			},
			roleExternalIDAttr: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The identifier for the role, which is associated with an identity provider.",
			},
			roleRolesAttr: {
				Type:		 schema.TypeList,
				Optional:	 true,
				Description: "Roles assigned to this role",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						role: {
						  Type:     schema.TypeString,
						  Required: true,
						},
						admin: {
							Type:	schema.TypeBool,
							Optional: true,
						},
					},
				},
			},
			roleGrantssAttr: {
				Type:		 schema.TypeList,
				Optional:	 true,
				Description: "Direct grants to this role",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						objectType: &schema.Schema{
						  Type:     schema.TypeString,
						  Required: true,
						},
						objects: &schema.Schema{
							Type:	schema.TypeList,
							Required: true,
							Elem: &schema.Schema{
								Type: schema.TypeString,
								},
							},
						privileges: &schema.Schema{
							Type: schema.TypeList,
							Required: false,
							Elem &schema.Schema{
								Type: schema.TypeString,
								},
						   },
						},
					},
				},
			},
		}
    }


func resourceRedshiftRoleExists(db *DBConnection, d *schema.ResourceData) (bool, error) {
	var name string
	err := db.QueryRow("SELECT role_name FROM svv_roles WHERE role_name = $1", d.Id()).Scan(&name)

	switch {
	case err == sql.ErrNoRows:
		return false, nil
	case err != nil:
		return false, err
	}

	return true, nil
}

func resourceRedshiftRoleCreate(db *DBConnection, d *schema.ResourceData) error {
	tx, err := startTransaction(db.client, "")
	if err != nil {
		return err
	}
	defer deferredRollback(tx)

	stringOpts := []struct {
		hclKey string
		sqlKey string
	}{
		{roleOwnerAttr, "role"},
	}

	roleName := d.Get(roleNameAttr).(string)
	ownerName := d.Get(roleOwnerAttr).(string)

	sql := fmt.Sprintf("CREATE ROLE %s", pq.QuoteIdentifier(roleName))

	if _, err := tx.Exec(sql); err != nil {
		return fmt.Errorf("error creating role %s: %w", roleName, err)
	}

	var role_id string
	if err := tx.QueryRow("SELECT role-id FROM svv_roles WHERE role_name = $1", roleName).Scan(&role_id); err != nil {
		return fmt.Errorf("role does not exist in svv_roles table: %w", err)
	}

	d.SetId(role_id)

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("could not commit transaction: %w", err)
	}

	return resourceRedshiftRoleReadImpl(db, d)
}

func resourceRedshiftRoleRead(db *DBConnection, d *schema.ResourceData) error {
	return resourceRedshiftRoleReadImpl(db, d)
}

func resourceRedshiftRoleReadImpl(db *DBConnection, d *schema.ResourceData) error {
	var roleName, roleOwner, roleExternalID string

	columns := []string{
		"role_id",
		"role_name",
		"role_owner",
		"external_id",
	}
	values := []interface{}{
		&roleID,
		&roleName,
		&roleOwner,
		&roleExternalID
	}

	roleID := d.Id()

	roleSQL := fmt.Sprintf("SELECT %s FROM svv_roles WHERE role_id = $1", strings.Join(columns, ","))
	err := db.QueryRow(roleSQL, roleID).Scan(values...)
	switch {
	case err == sql.ErrNoRows:
		log.Printf("[WARN] Redshift Role (%s) not found", useSysID)
		d.SetId("")
		return nil
	case err != nil:
		return fmt.Errorf("Error reading Role: %w", err)
	}

	d.Set(roleNameAttr, roleName)
	d.Set(roleOwnerAttr, roleOwner)
	d.Set(roleExternalIDAttr, roleExternalID)

	return nil
}

func resourceRedshiftRoleDelete(db *DBConnection, d *schema.ResourceData) error {
	roleID := d.Id()
	roleName := d.Get(roleNameAttr).(string)

	tx, err := startTransaction(db.client, "")
	if err != nil {
		return err
	}
	defer deferredRollback(tx)

	// Based on https://github.com/awslabs/amazon-redshift-utils/blob/master/src/AdminViews/v_find_dropuser_objs.sql
	var revokePrivilegesGenerator = `SELECT revoke.ddl
			FROM (
			      -- Users having the role
			      select 'revoke role ' || QUOTE_IDENT(role_name) || ' from ' || QUOTE_IDENT(user_name) || ';'
				  from svv_user_grants where role_id  = $1
			  UNION ALL
			      -- Roles having the role
				  select 'revoke role ' || QUOTE_IDENT(granted_role_name) || ' from role ' || QUOTE_IDENT(role_name) || ';' 
				  from svv_role_grants where role_id  = $1
			  UNION ALL
			      -- Database Privileges
			      select 'revoke ' || privilege_type || ' on database ' || QUOTE_IDENT(database_name) || ' from role ' || QUOTE_IDENT(identity_name) || ';'  
				  from svv_database_privileges where identity_id = $1
			  UNION ALL
			      -- Datashare Privileges
			      select 'revoke ' || privilege_type || ' on datashare ' || QUOTE_IDENT(datashare_name) || ' from ' || identity_type || ' ' || QUOTE_IDENT(indentiy_name) || ';' 
				  FROM svv_datashare_privileges where identity_id = $1
			  UNION ALL
			      -- Default Privileges
				  select 'alter default privileges for user ' || QUOTE_IDENT(owner_name) || ' in schema ' || QUOTE_IDENT(schema_name) || '  revoke ' || privilege_type || ' on ' || replace(object_type,'RELATION','TABLES') || ' from role ' || QUOTE_IDENT(grantee_name) || ';'
				  from svv_default_privileges where grantee_id = $1
			  UNION ALL
			      -- Functions
				  select ' revoke execute on function ' || QUOTE_IDENT(function_name) || ' from ' || identity_type || ' ' ||  QUOTE_IDENT(identity_name) || ';'
				  FROM svv_function_privileges where identity_id = $1
			  UNION ALL
			      -- Tables/Views
				  select 'revoke ' || privilege_type || ' on ' || QUOTE_IDENT(namespace_name) || '.' || QUOTE_IDENT(relation_name) || ' from role ' || QUOTE_IDENT(identity_name) || ';'
				  FROM svv_relation_privileges where identity_id = $1
			  UNION ALL
			      -- Languages
				  select 'revoke ' || privilege_type || ' on ' || QUOTE_IDENT(language_name) || ' from role ' || QUOTE_IDENT(identity_name) || ';'
				  FROM svv_language_privileges where identity_id = $1
			  UNION ALL
			      -- Functions/Procedures
				  select 'revoke ' || privilege_type || ' on ' || function_name || '(' || argument_types ') from  ' || identity_type || ' ' || QUOTE_IDENT(identity_name) || ';'
				  FROM svv_function_privileges where identity_id = $1
			  UNION ALL
			      -- Column Privileges
				  select 'revoke ' || privilege_type || '(' || QUOTE_IDENT(column_name) || ') on ' || QUOTE_IDENT(namespace_name) || '.' || QUOTE_IDENT(relation_name) || ' from  ' || identity_type || ' ' || QUOTE_IDENT(identity_name) || ';'
				  FROM svv_column_privileges where identity_id = $1
			  UNION ALL
			      -- Schema Privileges
				  select 'revoke ' || privilege_type || ' on schema ' || QUOTE_IDENT(namespace_name) ||  ' from  ' || identity_type || ' ' || QUOTE_IDENT(identity_name) || ';'
				  FROM svv_schema_privileges where identity_id = $1			  
			)
		`

	rows, err := tx.Query(revokePrivilegesGenerator, roleID)
	if err != nil {
		return err
	}
	defer rows.Close()

	var reassignStatements []string
	for rows.Next() {
		var statement string
		if err := rows.Scan(&statement); err != nil {
			return err
		}

		reassignStatements = append(reassignStatements, statement)
	}

	for _, statement := range reassignStatements {
		if _, err := tx.Exec(statement); err != nil {
			log.Printf("error: %#v", err)
			return err
		}
	}

	rows, err = tx.Query("SELECT nspname FROM pg_namespace WHERE nspowner != 1 OR nspname = 'public'")
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var schemaName string
		if err := rows.Scan(&schemaName); err != nil {
			return err
		}

		if _, err := tx.Exec(fmt.Sprintf("REVOKE ALL ON ALL TABLES IN SCHEMA %s FROM %s", pq.QuoteIdentifier(schemaName), pq.QuoteIdentifier(userName))); err != nil {
			return err
		}

		if _, err := tx.Exec(fmt.Sprintf("ALTER DEFAULT PRIVILEGES IN SCHEMA %s REVOKE ALL ON TABLES FROM %s", pq.QuoteIdentifier(schemaName), pq.QuoteIdentifier(userName))); err != nil {
			return err
		}

	}

	if _, err := tx.Exec(fmt.Sprintf("DROP USER %s", pq.QuoteIdentifier(userName))); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return err
		//return fmt.Errorf("could not commit transaction: %w", err)
	}

	return nil
}

func resourceRedshiftRoleUpdate(db *DBConnection, d *schema.ResourceData) error {
	tx, err := startTransaction(db.client, "")
	if err != nil {
		return err
	}
	defer deferredRollback(tx)

	if err := setUserName(tx, d); err != nil {
		return err
	}

	if err := setUserPassword(tx, d); err != nil {
		return err
	}

	if err := setUserConnLimit(tx, d); err != nil {
		return err
	}

	if err := setUserCreateDB(tx, d); err != nil {
		return err
	}
	if err := setUserSuperuser(tx, d); err != nil {
		return err
	}

	if err := setUserValidUntil(tx, d); err != nil {
		return err
	}

	if err := setUserSyslogAccess(tx, d); err != nil {
		return err
	}

	if err := setUserSessionTimeout(tx, d); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("could not commit transaction: %w", err)
	}

	return resourceRedshiftRoleReadImpl(db, d)
}

func setUserName(tx *sql.Tx, d *schema.ResourceData) error {
	if !d.HasChange(userNameAttr) {
		return nil
	}

	oldRaw, newRaw := d.GetChange(userNameAttr)
	oldValue := oldRaw.(string)
	newValue := newRaw.(string)

	if newValue == "" {
		return fmt.Errorf("Error setting user name to an empty string")
	}

	sql := fmt.Sprintf("ALTER USER %s RENAME TO %s", pq.QuoteIdentifier(oldValue), pq.QuoteIdentifier(newValue))
	if _, err := tx.Exec(sql); err != nil {
		return fmt.Errorf("Error updating User NAME: %w", err)
	}

	return nil
}

func setUserPassword(tx *sql.Tx, d *schema.ResourceData) error {
	if !d.HasChange(userPasswordAttr) && !d.HasChange(userNameAttr) {
		return nil
	}

	userName := d.Get(userNameAttr).(string)
	password := d.Get(userPasswordAttr).(string)

	passwdTok := "PASSWORD DISABLE"
	if password != "" {
		passwdTok = fmt.Sprintf("PASSWORD '%s'", pqQuoteLiteral(password))
	}

	sql := fmt.Sprintf("ALTER USER %s %s", pq.QuoteIdentifier(userName), passwdTok)
	if _, err := tx.Exec(sql); err != nil {
		return fmt.Errorf("Error updating user password: %w", err)
	}
	return nil
}

func setUserConnLimit(tx *sql.Tx, d *schema.ResourceData) error {
	if !d.HasChange(userConnLimitAttr) {
		return nil
	}

	connLimit := d.Get(userConnLimitAttr).(int)
	userName := d.Get(userNameAttr).(string)
	sql := fmt.Sprintf("ALTER USER %s CONNECTION LIMIT %d", pq.QuoteIdentifier(userName), connLimit)
	if _, err := tx.Exec(sql); err != nil {
		return fmt.Errorf("Error updating user CONNECTION LIMIT: %w", err)
	}

	return nil
}

func setUserSessionTimeout(tx *sql.Tx, d *schema.ResourceData) error {
	if !d.HasChange(userSessionTimeoutAttr) {
		return nil
	}

	sessionTimeout := d.Get(userSessionTimeoutAttr).(int)
	userName := d.Get(userNameAttr).(string)
	sql := ""
	if sessionTimeout == 0 {
		sql = fmt.Sprintf("ALTER USER %s RESET SESSION TIMEOUT", pq.QuoteIdentifier(userName))
	} else {
		sql = fmt.Sprintf("ALTER USER %s SESSION TIMEOUT %d", pq.QuoteIdentifier(userName), sessionTimeout)
	}
	if _, err := tx.Exec(sql); err != nil {
		return fmt.Errorf("Error updating user SESSION TIMEOUT: %w", err)
	}

	return nil
}

func setUserCreateDB(tx *sql.Tx, d *schema.ResourceData) error {
	if !d.HasChange(userCreateDBAttr) {
		return nil
	}

	createDB := d.Get(userCreateDBAttr).(bool)
	tok := "NOCREATEDB"
	if createDB {
		tok = "CREATEDB"
	}
	userName := d.Get(userNameAttr).(string)
	sql := fmt.Sprintf("ALTER USER %s WITH %s", pq.QuoteIdentifier(userName), tok)
	if _, err := tx.Exec(sql); err != nil {
		return fmt.Errorf("Error updating user CREATEDB: %w", err)
	}

	return nil
}

func setUserSuperuser(tx *sql.Tx, d *schema.ResourceData) error {
	if !d.HasChange(userSuperuserAttr) {
		return nil
	}

	superuser := d.Get(userSuperuserAttr).(bool)
	tok := "NOCREATEUSER"
	if superuser {
		tok = "CREATEUSER"
	}
	userName := d.Get(userNameAttr).(string)
	sql := fmt.Sprintf("ALTER USER %s WITH %s", pq.QuoteIdentifier(userName), tok)
	if _, err := tx.Exec(sql); err != nil {
		return fmt.Errorf("Error updating user SUPERUSER: %w", err)
	}

	return nil
}

func setUserValidUntil(tx *sql.Tx, d *schema.ResourceData) error {
	if !d.HasChange(userValidUntilAttr) {
		return nil
	}

	validUntil := d.Get(userValidUntilAttr).(string)
	if validUntil == "" {
		return nil
	} else if strings.ToLower(validUntil) == "infinity" {
		validUntil = "infinity"
	}

	userName := d.Get(userNameAttr).(string)
	sql := fmt.Sprintf("ALTER USER %s VALID UNTIL '%s'", pq.QuoteIdentifier(userName), pqQuoteLiteral(validUntil))
	if _, err := tx.Exec(sql); err != nil {
		return fmt.Errorf("Error updating user VALID UNTIL: %w", err)
	}

	return nil
}

func setUserSyslogAccess(tx *sql.Tx, d *schema.ResourceData) error {
	syslogAccessCurrent := d.Get(userSyslogAccessAttr).(string)
	syslogAccessComputed := syslogAccessCurrent
	if syslogAccessComputed == "" {
		syslogAccessComputed = defaultUserSyslogAccess
	}

	if d.Get(userSuperuserAttr).(bool) {
		syslogAccessComputed = defaultUserSuperuserSyslogAccess
	}

	if syslogAccessCurrent == syslogAccessComputed && !d.HasChange(userSyslogAccessAttr) {
		return nil
	}

	userName := d.Get(userNameAttr).(string)
	sql := fmt.Sprintf("ALTER USER %s WITH SYSLOG ACCESS %s", pq.QuoteIdentifier(userName), syslogAccessComputed)
	if _, err := tx.Exec(sql); err != nil {
		return fmt.Errorf("Error updating user SYSLOG ACCESS: %w", err)
	}

	return nil
}

func getDefaultSyslogAccess(d *schema.ResourceData) string {
	if d.Get(userSuperuserAttr).(bool) {
		return defaultUserSuperuserSyslogAccess
	}

	return defaultUserSyslogAccess
}
