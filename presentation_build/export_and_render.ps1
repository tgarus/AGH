param(
    [string]$PptxPath = "C:\Users\Microsoft Office\.gemini\antigravity\scratch\AGH\final-presentation.pptx",
    [string]$PdfPath = "C:\Users\Microsoft Office\.gemini\antigravity\scratch\AGH\final-presentation.pdf",
    [string]$RenderDir = "C:\Users\Microsoft Office\.gemini\antigravity\scratch\AGH\presentation_build\renders_v1"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $PptxPath)) {
    throw "PPTX file not found: $PptxPath"
}

if (-not (Test-Path $RenderDir)) {
    New-Item -ItemType Directory -Path $RenderDir -Force | Out-Null
}

$ppt = $null
$pres = $null

try {
    $ppt = New-Object -ComObject PowerPoint.Application
    $pres = $ppt.Presentations.Open($PptxPath, $true, $false, $false)

    $pres.SaveAs($PdfPath, 32)
    Write-Output "Exported PDF: $PdfPath"

    $count = $pres.Slides.Count
    Write-Output "Slide count: $count"
    for ($i = 1; $i -le $count; $i++) {
        $slide = $pres.Slides.Item($i)
        $outPng = Join-Path $RenderDir ("slide_{0:D2}.png" -f $i)
        $slide.Export($outPng, "PNG", 1920, 1080)
        Write-Output "Rendered: $outPng"
    }
}
finally {
    if ($pres -ne $null) {
        try { $pres.Close() } catch {}
        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($pres) | Out-Null
    }
    if ($ppt -ne $null) {
        try { $ppt.Quit() } catch {}
        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($ppt) | Out-Null
    }
    [GC]::Collect()
    [GC]::WaitForPendingFinalizers()
}
