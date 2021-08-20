<#
.SYNOPSIS
    Displays a PowerShell prompt for multiple fields or multiple choices.
.DESCRIPTION
    Displays a PowerShell prompt for multiple fields or multiple choices.
.EXAMPLE
    PS C:\>Write-HostPrompt "Prompt Caption" "Prompt Message" -Fields @(
        New-Object System.Management.Automation.Host.FieldDescription -ArgumentList "Field 1"
        New-Object System.Management.Automation.Host.FieldDescription -ArgumentList "Field 2"
    )
    Display prompt for 2 fields.
.EXAMPLE
    PS C:\>Write-HostPrompt "Prompt Caption" "Prompt Message" -DefaultChoice 0 -Choices @(
        New-Object System.Management.Automation.Host.ChoiceDescription -ArgumentList "Choice &1 Label","Choice 1 Help Message"
        New-Object System.Management.Automation.Host.ChoiceDescription -ArgumentList "&Yes","Yes Help Message"
        New-Object System.Management.Automation.Host.ChoiceDescription -ArgumentList "&No","No Help Message"
    )
    Display prompt with 3 choices.
.INPUTS
    System.Management.Automation.Host.FieldDescription
    System.Management.Automation.Host.ChoiceDescription
.OUTPUTS
    System.Collections.Generic.Dictionary[System.String,System.Management.Automation.PSObject]
    System.Int32
#>
function Write-HostPrompt {
    [CmdletBinding()]
    param
    (
        # Caption to preceed or title the prompt.
        [Parameter(Mandatory = $true, Position = 1)]
        [string] $Caption,
        # A message that describes the prompt.
        [Parameter(Mandatory = $false, Position = 2)]
        [string] $Message,
        # The fields in the prompt.
        [Parameter(Mandatory = $true, ParameterSetName = 'Fields', Position = 3, ValueFromPipeline = $true)]
        [System.Management.Automation.Host.FieldDescription[]] $Fields,
        # The choices the shown in the prompt.
        [Parameter(Mandatory = $true, ParameterSetName = 'Choices', Position = 3, ValueFromPipeline = $true)]
        [System.Management.Automation.Host.ChoiceDescription[]] $Choices,
        # The index of the label in the choices to make default.
        [Parameter(Mandatory = $false, ParameterSetName = 'Choices', Position = 4)]
        [int] $DefaultChoice = -1
    )

    begin {
        ## Create list to capture multiple fields or multiple choices.
        [System.Collections.Generic.List[System.Management.Automation.Host.FieldDescription]] $listFields = New-Object System.Collections.Generic.List[System.Management.Automation.Host.FieldDescription]
        [System.Collections.Generic.List[System.Management.Automation.Host.ChoiceDescription]] $listChoices = New-Object System.Collections.Generic.List[System.Management.Automation.Host.ChoiceDescription]
    }

    process {
        switch ($PSCmdlet.ParameterSetName) {
            'Fields' {
                foreach ($Field in $Fields) { $listFields.Add($Field) }
            }
            'Choices' {
                foreach ($Choice in $Choices) { $listChoices.Add($Choice) }
            }
        }
    }

    end {
        try {
            switch ($PSCmdlet.ParameterSetName) {
                'Fields' { return $Host.UI.Prompt($Caption, $Message, $listFields.ToArray()) }
                'Choices' { return $Host.UI.PromptForChoice($Caption, $Message, $listChoices.ToArray(), $DefaultChoice) }
            }
        }
        catch [System.Management.Automation.MethodInvocationException] {
            Write-Error $_
            #if ($PSCmdlet.ParameterSetName -eq 'Choices') { return $DefaultChoice }
        }
    }
}
