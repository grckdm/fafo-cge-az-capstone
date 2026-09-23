output "cosmos_endpoint" {
  value = azurerm_cosmosdb_account.fafo.endpoint
}

output "cosmos_account_name" {
  value = azurerm_cosmosdb_account.fafo.name
}

output "cosmos_account_id" {
  value = azurerm_cosmosdb_account.fafo.id
}

output "cosmos_database_name" {
  value = azurerm_cosmosdb_sql_database.fafo.name
}

output "evidence_storage_account" {
  value = azurerm_storage_account.evidence.name
}

output "reports_container" {
  value = azurerm_storage_container.reports.name
}

output "collector_function_app" {
  value = azurerm_linux_function_app.collector.name
}

output "collector_principal_id" {
  value = azurerm_linux_function_app.collector.identity[0].principal_id
}

output "management_group_id" {
  description = "Passed through from stage 01 — stage 03's reporter identity and stage 04's enforcement both need it."
  value       = local.mg_id
}
