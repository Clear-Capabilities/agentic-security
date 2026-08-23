resource assets 'Microsoft.Storage/storageAccounts@2022-09-01' = {
  name: 'companyassets'
  location: 'westeurope'
  properties: {
    allowBlobPublicAccess: false
    supportsHttpsTrafficOnly: true
  }
}
