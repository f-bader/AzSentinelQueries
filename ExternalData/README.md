# External data sources

Some external data sources need additional modification or are not available through the `externaldata` function directly. In that case I will add them here.

| Source | Description | Modification | Reason |
| ------ | ----------- | ------------ | ------ |
| `https://mask-api.icloud.com/egress-ip-ranges.csv` | Current list of all IP addresses of the iCloud Private Relay service.<br/> https://developer.apple.com/support/prepare-your-network-for-icloud-private-relay/ | Added column to distiguish between IPv4 and IPv6 | `externaldata` cannot fetch the CSV from Apple servers |
