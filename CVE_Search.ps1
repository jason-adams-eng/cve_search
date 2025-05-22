# === Config ===
$CVEsWanted = @("CVE-2024-38202") # Replace CVE number with your info. Separate multiple by commas and include quotes.

# === Headers for API ===
$headers = @{
    "Accept" = "application/json"
    "api-version" = "2023-11-01"
}

# === Step 1: Get update documents with valid CVRF URLs ===
$updateList = Invoke-RestMethod -Uri "https://api.msrc.microsoft.com/cvrf/v3.0/updates?api-version=2023-11-01"
$updates = $updateList.value

$foundAny = $false

foreach ($update in $updates) {
    $title = $update.ID
    $url = $update.CvrfUrl

    if (-not $url) {
        Write-Warning "No CVRF URL for $title — skipping"
        continue
    }

    Write-Host "Searching $title..." -ForegroundColor Yellow

    try {
        $cvrf = Invoke-RestMethod -Uri $url -Headers $headers
        $matches = $cvrf.Vulnerability | Where-Object { $CVEsWanted -contains $_.CVE }

        foreach ($match in $matches) {
            $foundAny = $true
            $cve = $match.CVE
            $titleText = if ($match.Title -is [PSCustomObject]) { $match.Title.Value } else { $match.Title }

            Write-Host "FOUND: $cve in $title" -ForegroundColor Green
            Write-Host "Title: $titleText"

            foreach ($rem in $match.Remediations) {
                $kb = $rem.ID
                $desc = if ($rem.Description -is [PSCustomObject]) { $rem.Description.Value } else { $rem.Description }
                $kbUrl = $rem.URL

                # Map the Product IDs to actual OS names
                $products = @()
                foreach ($productId in $rem.ProductID) {
                    $productName = ($cvrf.ProductTree.FullProductName | Where-Object { $_.ProductID -eq $productId }).Value
                    if ($productName) {
                        $products += $productName
                    }
                }


                if ($kb -or $desc -or $kbUrl) {
                    Write-Host "  🔹 KB:  $kb"
                    Write-Host "      Fix: $desc"
                    Write-Host "      URL: $kbUrl"
                    if ($products.Count -gt 0) {
                        Write-Host "      Applies to:"
                        $products | Sort-Object -Unique | ForEach-Object { Write-Host "        • $_" }
                    } else {
                        Write-Host "      Applies to: (Product IDs not mapped)"
                    }
                    Write-Host ""
                }
            }
        }

    } catch {
        Write-Warning "Error parsing $title — $($_.Exception.Message)"
    }
}

if (-not $foundAny) {
    Write-Warning "CVE(s) not found in any update document."
}
