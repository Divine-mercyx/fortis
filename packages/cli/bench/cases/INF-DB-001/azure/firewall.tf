resource "azurerm_postgresql_flexible_server_firewall_rule" "all0" {
  name             = "everyone-0"
  start_ip_address = "0.0.0.0" # @hit
  end_ip_address   = "255.255.255.255"
}

resource "azurerm_mysql_flexible_server_firewall_rule" "all1" {
  name             = "everyone-1"
  start_ip_address = "0.0.0.0" # @hit
  end_ip_address   = "255.255.255.255"
}

resource "azurerm_mssql_firewall_rule" "all2" {
  name             = "everyone-2"
  start_ip_address = "0.0.0.0" # @hit
  end_ip_address   = "255.255.255.255"
}

resource "azurerm_postgresql_firewall_rule" "all3" {
  name             = "everyone-3"
  start_ip_address = "0.0.0.0" # @hit
  end_ip_address   = "255.255.255.255"
}

resource "azurerm_mariadb_firewall_rule" "all4" {
  name             = "everyone-4"
  start_ip_address = "0.0.0.0" # @hit
  end_ip_address   = "255.255.255.255"
}

resource "azurerm_sql_firewall_rule" "all5" {
  name             = "everyone-5"
  start_ip_address = "0.0.0.0" # @hit
  end_ip_address   = "255.255.255.255"
}

resource "azurerm_mysql_firewall_rule" "all6" {
  name             = "everyone-6"
  start_ip_address = "0.0.0.0" # @hit
  end_ip_address   = "255.255.255.255"
}

resource "azurerm_postgresql_flexible_server_firewall_rule" "azure_services" {
  name             = "AllowAzureServices"
  start_ip_address = "0.0.0.0"
  end_ip_address   = "0.0.0.0"
}

resource "azurerm_postgresql_flexible_server_firewall_rule" "office" {
  name             = "office"
  start_ip_address = "102.89.10.1"
  end_ip_address   = "102.89.10.254"
}
