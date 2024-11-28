$AllocatedFilterAltitudes = ( Invoke-RestMethod -Method Get -Uri https://raw.githubusercontent.com/MicrosoftDocs/windows-driver-docs/staging/windows-driver-docs-pr/ifs/allocated-altitudes.md ) -replace '\*' | ConvertFrom-Markdown
$mdTables = @( $AllocatedFilterAltitudes.Tokens | Where-Object { $_ -is [Markdig.Extensions.Tables.Table] -or $_ -is [Markdig.Syntax.HeadingBlock] } ) 
$AllocatedFilterAltitudesObjects = New-Object -TypeName System.Collections.ArrayList
foreach ( $mdTable in $mdTables ) {
    if ( $mdTable -is [Markdig.Syntax.HeadingBlock] ) {
        [string]$CurrentHeader = $mdTable.Inline.Content -replace '^.*: '; ''
        Write-Verbose "Header: $CurrentHeader"
    } else {
        $mdRows = @( $mdTable | Where-Object { $_ -is [Markdig.Extensions.Tables.TableRow] } )
        foreach ( $mdRow in $mdRows ) {
            if ( $mdRow.IsHeader ) {
                continue
                Write-Verbose "Skipping header row"
            }
            Write-Verbose "Processing row"
            $mdCells = @( $mdRow | Where-Object { $_ -is [Markdig.Extensions.Tables.TableCell] } )
            $CellCount = 0
            foreach ( $mdCell in $mdCells ) {
                Write-Verbose "Processing cell"
                Write-Verbose "Cell count: $CellCount"
                $mdInline = $mdCell.Inline
                Write-Verbose "$($mdInline.Content)"
                if ( $CellCount -eq 0 ) {
                    $Minifilter = $mdInline.Content
                } elseif ( $CellCount -eq 1 ) {
                    $Altitude = $mdInline.Content
                } elseif ( $CellCount -eq 2 ) {
                    $Company = $mdInline.Content
                }
                $CellCount += 1
            }
            if ( $Minifilter -ne $null -and $Altitude -ne $null -and $Company -ne $null ) {
                Write-Verbose "Creating object"
                $currentItem = [PSCustomObject]@{
                    Category   = $CurrentHeader
                    Minifilter = $Minifilter
                    Altitude   = $Altitude
                    Company    = $Company
                }
                $AllocatedFilterAltitudesObjects.Add($currentItem) | Out-Null
            }
        }
    }
}
$AllocatedFilterAltitudesObjects | Export-Csv -Path ./ExternalData/FSFilter.csv -Force
