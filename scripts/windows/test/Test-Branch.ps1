<#
 # Runs all .NET Core test projects in the repo
 #>

param (
    [ValidateNotNullOrEmpty()]
    [ValidateScript( {Test-Path $_ -PathType Container})]
    [String] $AgentWorkFolder = $Env:AGENT_WORKFOLDER,

    [ValidateNotNullOrEmpty()]
    [ValidateScript( {Test-Path $_ -PathType Container})]
    [String] $BuildRepositoryLocalPath = $Env:BUILD_REPOSITORY_LOCALPATH,
    
    [ValidateNotNullOrEmpty()]
    [ValidateScript( {Test-Path $_ -PathType Container})]
    [String] $BuildBinariesDirectory = $Env:BUILD_BINARIESDIRECTORY,

    [ValidateNotNullOrEmpty()]
    [String] $Filter
)

Set-StrictMode -Version "Latest"
$ErrorActionPreference = "Stop"

<#
 # Prepare environment
 #>

Import-Module ([IO.Path]::Combine($PSScriptRoot, "..", "Defaults.psm1")) -Force

if (-not $AgentWorkFolder) {
    $AgentWorkFolder = DefaultAgentWorkFolder
}

if (-not $BuildRepositoryLocalPath) {
    $BuildRepositoryLocalPath = DefaultBuildRepositoryLocalPath
}

if (-not $BuildBinariesDirectory) {
    $BuildBinariesDirectory = DefaultBuildBinariesDirectory $BuildRepositoryLocalPath
}

$TEST_PROJ_PATTERN = "Microsoft.Azure*test.csproj"
$LOGGER_ARG = "trx;LogFileName=result.trx"

$DOTNET_PATH = [IO.Path]::Combine($AgentWorkFolder, "dotnet", "dotnet.exe")
$OPENCOVER = [IO.Path]::Combine($BuildRepositoryLocalPath, "OpenCover.4.6.519", "tools", "OpenCover.Console.exe")
$CODE_COVERAGE = Join-Path $BuildBinariesDirectory "code-coverage.xml"
$OPENCOVER_COBERTURA_CONVERTER = [IO.Path]::Combine(
    $BuildRepositoryLocalPath,
    "OpenCoverToCoberturaConverter.0.2.6.0",
    "tools",
    "OpenCoverToCoberturaConverter.exe")
$REPORT_GENERATOR = [IO.Path]::Combine(
    $BuildRepositoryLocalPath,
    "ReportGenerator.2.5.6",
    "tools",
    "ReportGenerator.exe"
)

if (-not (Test-Path $DOTNET_PATH -PathType Leaf)) {
    throw "$DOTNET_PATH not found."
}

<#
 # Run tests
 #>

$BaseTestCommand = if ($Filter) {
    "test --no-build --logger `"$LOGGER_ARG`" --filter `"$Filter`"" 
}
else {
    "test --no-build --logger `"$LOGGER_ARG`""
}

Write-Host "Running tests in all test projects with filter '$Filter'."
$Success = $True
$DotNetCommand = "&`"$DOTNET_PATH`""
$OpenCoverCommand = "&`"$OPENCOVER`""

foreach ($Project in (Get-ChildItem $BuildRepositoryLocalPath -Include $TEST_PROJ_PATTERN -Recurse)) {
    Write-Host "Prepare to run job for testing for $Project."

	$scriptblock = {
        param($testProject, $DOTNET_PATH, $BaseTestCommand, $BuildBinariesDirectory, $OPENCOVER, $CODE_COVERAGE) 
    
	    Write-Host "[Start running tests for '$testProject' inside a job]"
        if (test-path $opencover -pathtype "leaf") {
		    write-host "run command: $opencover -register:user -target:$dotnet_path -targetargs:'$basetestcommand $project' -skipautoprops -hideskipped:all -oldstyle -output:$code_coverage -mergeoutput:$code_coverage -returntargetcode ..."
            
			Invoke-Expression "$using:OpenCoverCommand -register:user -target:$dotnet_path -targetargs:`"$basetestcommand $project`" -skipautoprops -hideskipped:all -oldstyle -output:$code_coverage -mergeoutput:$code_coverage -returntargetcode -filter:`"+[*]* -[moq*]* -[app.metrics.reporting*]*`""
	    }
	    else {
		    Write-Host "Run command: '" + $DOTNET_PATH + "' " + $BaseTestCommand " -o " + $BuildBinariesDirectory + " " + $Project
            Invoke-Expression "$using:DotNetCommand $BaseTestCommand -o $BuildBinariesDirectory $Project"
        }
        Write-Host "[Complete running tests for '$testProject' inside a job]"
		
        $testResult = "$testProject project test passed."
        if ($LASTEXITCODE -ne 0)
        {
            $testResult = "$testProject project test failed."
        }
	
        return $testResult + [Environment]::NewLine
    }
	
    Write-Host "Start a job to run tests for $Project."
    Start-Job $scriptBlock -ArgumentList $Project $DOTNET_PATH $BaseTestCommand $BuildBinariesDirectory $OPENCOVER $CODE_COVERAGE
	
    $Success = $Success -and $LASTEXITCODE -eq 0
}

$results = Get-Job | Receive-Job
Write-Host $results

if ($results -like '*project test failed*')
{
  $Success = $False
}

<#
 # Process results
 #>

if (Test-Path $OPENCOVER_COBERTURA_CONVERTER -PathType "Leaf") {
    &$OPENCOVER_COBERTURA_CONVERTER -sources:. -input:$CODE_COVERAGE -output:(Join-Path $BuildBinariesDirectory "CoberturaCoverage.xml")
}

if (Test-Path $REPORT_GENERATOR -PathType "Leaf") {
    &$REPORT_GENERATOR -reporttypes:MHtml -reports:$CODE_COVERAGE -targetdir:(Join-Path $BuildBinariesDirectory "report")
}

if (-not $Success) {
    throw "Failed tests."
}

Write-Host "Done!"