resource nsg 'Microsoft.Network/networkSecurityGroups@2023-04-01' = {
  name: 'payments'
  location: resourceGroup().location
  properties: {
    securityRules: [
      {
        name: 'ssh'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourcePortRange: '*'
          sourceAddressPrefix: '*' // @hit
          destinationPortRange: '22'
          destinationAddressPrefix: '*'
        }
      }
      {
        name: 'sql'
        properties: {
          priority: 110
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourcePortRange: '*'
          sourceAddressPrefix: 'Internet' // @hit
          destinationPortRanges: [
            '1433'
            '443'
          ]
          destinationAddressPrefix: '*'
        }
      }
      {
        name: 'https'
        properties: {
          priority: 120
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourcePortRange: '*'
          sourceAddressPrefix: '*'
          destinationPortRange: '443'
          destinationAddressPrefix: '*'
        }
      }
      {
        name: 'deny-rdp'
        properties: {
          priority: 130
          direction: 'Inbound'
          access: 'Deny'
          protocol: 'Tcp'
          sourcePortRange: '*'
          sourceAddressPrefix: '*'
          destinationPortRange: '3389'
          destinationAddressPrefix: '*'
        }
      }
    ]
  }
}
