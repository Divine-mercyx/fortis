resource allowAll 'Microsoft.Sql/servers/firewallRules@2023-05-01' = {
  parent: sqlServer
  name: 'AllowEveryone'
  properties: {
    startIpAddress: '0.0.0.0' // @hit
    endIpAddress: '255.255.255.255'
  }
}

resource azureServices 'Microsoft.Sql/servers/firewallRules@2023-05-01' = {
  parent: sqlServer
  name: 'AllowAllWindowsAzureIps'
  properties: {
    startIpAddress: '0.0.0.0'
    endIpAddress: '0.0.0.0'
  }
}
