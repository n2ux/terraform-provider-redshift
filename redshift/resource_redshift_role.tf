resource "redshift_role" "testrole" {
    name = "testrole"
    owner = "postgres"
    external_id = "aad:myAzureGroupID"
    roles_granted = [
       {
          role: "sys.dba",
          with_admin: false
       },
       {
          role: "es.dbaa.database"
          with_admin: true
       }
    ]
    grants = [
        {
            object_type: "table"
            object_name: [
                "mytable"
            ]
            database: "rlsdemo"
            schema: "myschema"
            privileges: [
                "SELECT",
                "UPDATE"
            ]
        },
        {
            object_type: "database"
            object_name: [
                "postgres",
                "rlsdemo"
            ],
            privileges: [ 
                "CONNECT" 
            ]
        }
    ]
}