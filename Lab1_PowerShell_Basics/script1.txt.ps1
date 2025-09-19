$hcount = 0
foreach ($process in Get-Process -Name n* -ErrorAction SilentlyContinue) {
    $hcount += $process.Handles
}
$hcount
