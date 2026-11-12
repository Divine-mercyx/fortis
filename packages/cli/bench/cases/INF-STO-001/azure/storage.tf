resource "azurerm_storage_container" "c0" {
  name                  = "docs-0"
  storage_account_name  = azurerm_storage_account.sa.name
  container_access_type = "blob" # @hit
}

resource "azurerm_storage_container" "c1" {
  name                  = "docs-1"
  storage_account_name  = azurerm_storage_account.sa.name
  container_access_type = "container" # @hit
}

resource "azurerm_storage_container" "c2" {
  name                  = "docs-2"
  storage_account_name  = azurerm_storage_account.sa.name
  container_access_type = "blob" # @hit
}

resource "azurerm_storage_container" "private" {
  name                  = "private"
  storage_account_name  = azurerm_storage_account.sa.name
  container_access_type = "private"
}

resource "azurerm_storage_account" "sa" {
  name                            = "noltdocs"
  resource_group_name             = azurerm_resource_group.rg.name
  location                        = "westeurope"
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  allow_nested_items_to_be_public = true # @hit
}

resource "azurerm_storage_account" "locked" {
  name                            = "noltlocked"
  resource_group_name             = azurerm_resource_group.rg.name
  location                        = "westeurope"
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  allow_nested_items_to_be_public = false
}
