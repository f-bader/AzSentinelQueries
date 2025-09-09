# Set the output CSV file path
$csvFilePath = "./ExternalData/Microsoft365IPAddressRanges.csv"

# Generate a unique client request ID
$clientRequestId = [guid]::NewGuid().ToString()

# Construct the download URL with the unique client request ID
$url = "https://endpoints.office.com/endpoints/worldwide?clientrequestid=$clientRequestId"

# Download the JSON data from the URL
Write-Host "Downloading IP ranges from: $url"

try {
    # Use Invoke-RestMethod for direct JSON parsing
    $data = Invoke-RestMethod -Uri $url -Method Get
} catch {
    Write-Host "Error: Could not download the JSON file from the URL."
    Write-Host "Details: $($_.Exception.Message)"
    Exit
}

# Create an empty array to store the IP range objects
$ipRanges = @()

# Loop through each item in the JSON data
foreach ($item in $data) {
    # Check if the item has an 'ips' property and it's not null or empty
    if ($item.ips -and $item.ips.Count -gt 0) {
        # Loop through each IP address in the 'ips' array
        foreach ($ip in $item.ips) {
            # Create a custom object for each IP range with the required properties
            $ipRanges += [PSCustomObject]@{
                'IPRange'                = $ip
                'ServiceArea'            = $item.serviceArea
                'ServiceAreaDisplayName' = $item.serviceAreaDisplayName
            }
        }
    }
}

# Export the collected data to a CSV file.
# -NoTypeInformation prevents a line with the object type from being added to the CSV.
$ipRanges | Export-Csv -Path $csvFilePath -NoTypeInformation

Write-Host "Successfully exported IP ranges to '$csvFilePath'."
