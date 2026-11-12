resource sa 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'noltdocs'
  kind: 'StorageV2'
  properties: {
    allowBlobPublicAccess: true // @hit
    minimumTlsVersion: 'TLS1_2'
  }
}

resource kyc 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-01-01' = {
  name: '${sa.name}/default/kyc'
  properties: {
    publicAccess: 'Blob' // @hit
  }
}

resource private 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-01-01' = {
  name: '${sa.name}/default/private'
  properties: {
    publicAccess: 'None'
  }
}
