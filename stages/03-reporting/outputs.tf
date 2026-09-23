output "reporting_function_app" {
  value = azurerm_linux_function_app.reporter.name
}

output "reporter_principal_id" {
  value = azurerm_linux_function_app.reporter.identity[0].principal_id
}
