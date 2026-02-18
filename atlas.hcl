data "external_schema" "sqlalchemy" {
  program = [
    "atlas-provider-sqlalchemy",
    "--path", "./covsrv/models.py",
    "--dialect", "sqlite",
  ]
}

env "local" {
  src = data.external_schema.sqlalchemy.url
  dev = "sqlite://dev?mode=memory"
  migration {
    dir = "file://migrations"
  }
}
