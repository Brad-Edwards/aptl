/*
 * DBK64.sys Detection Rules
 * Based on verified static analysis of actual DBK64.sys binary
 * Generated from dry run analysis on 2025-09-03
 */

import "hash"

rule DBK64_Exact_Hash {
    meta:
        description = "Detects exact DBK64.sys by hash"
        author = "AI Agent Analysis"
        date = "2025-09-03"
        hash_sha256 = "645727716d94cfbccd9324072e6d95305363c398666feafae3419eaef6fb1a05"
        hash_md5 = "86facb58ebaf1a4f1b500eb5ebf323cf"
        
    condition:
        hash.sha256(0, filesize) == "645727716d94cfbccd9324072e6d95305363c398666feafae3419eaef6fb1a05"
}

rule DBK64_PDB_Path {
    meta:
        description = "Detects DBK64.sys by embedded PDB path"
        author = "AI Agent Analysis"
        reference = "Found in strings analysis"
        
    strings:
        $pdb_path = "C:\\Users\\Administrator\\Downloads\\cheat-engine-7.5\\cheat-engine-7.5\\Cheat Engine\\bin\\DBK64.pdb" ascii
        $pdb_name = "DBK64.pdb" ascii nocase
        
    condition:
        uint16(0) == 0x5A4D and  // MZ header
        any of them
}

rule DBK64_Critical_APIs {
    meta:
        description = "Detects DBK64.sys by critical API import combination"
        author = "AI Agent Analysis"
        reference = "Verified through rabin2 -i analysis"
        
    strings:
        // Process manipulation APIs
        $api1 = "PsLookupProcessByProcessId" ascii
        $api2 = "KeAttachProcess" ascii
        $api3 = "KeDetachProcess" ascii
        
        // Memory manipulation APIs  
        $api4 = "MmGetPhysicalMemoryRanges" ascii
        $api5 = "MmMapIoSpace" ascii
        $api6 = "ZwAllocateVirtualMemory" ascii
        
        // APC manipulation
        $api7 = "KeInitializeApc" ascii
        $api8 = "KeInsertQueueApc" ascii
        $api9 = "PsWrapApcWow64Thread" ascii
        
        // Device creation
        $api10 = "IoCreateDevice" ascii
        $api11 = "IoCreateSymbolicLink" ascii
        
    condition:
        uint16(0) == 0x5A4D and  // MZ header
        filesize > 90KB and filesize < 100KB and
        6 of them  // Must have at least 6 of these critical APIs
}

rule DBK64_IOCTL_Patterns {
    meta:
        description = "Detects DBK64.sys by specific IOCTL code patterns"
        author = "AI Agent Analysis"
        reference = "Found through static analysis of IOCTL dispatcher"
        
    strings:
        // Specific IOCTL codes found in static analysis
        $ioctl1 = { 34 20 22 00 }  // IOCTL_CE_INITIALIZE (0x00222034)
        $ioctl2 = { 58 20 22 00 }  // IOCTL_CE_... (0x00222058)
        $ioctl3 = { 10 20 22 00 }  // IOCTL_CE_... (0x00222010)
        
        // More specific pattern: multiple CE IOCTL codes in sequence
        $ce_ioctl_sequence = { 34 20 22 00 [0-20] 58 20 22 00 }
        
    condition:
        uint16(0) == 0x5A4D and  // MZ header
        (2 of ($ioctl*) or $ce_ioctl_sequence)
}

rule DBK64_Device_Names {
    meta:
        description = "Detects DBK64.sys by device name patterns"
        author = "AI Agent Analysis"
        reference = "Found in Cheat Engine source analysis"
        
    strings:
        $device1 = "\\Device\\DBK64" ascii wide
        $device2 = "\\DosDevices\\DBK64" ascii wide
        $device3 = "\\Device\\CEDRIVER73" ascii wide
        $device4 = "\\DosDevices\\CEDRIVER73" ascii wide
        $event1 = "DBKProcList60" ascii wide
        $event2 = "DBKThreadList60" ascii wide
        $event3 = "DBK64ProcessEvent" ascii wide
        $event4 = "DBK64ThreadEvent" ascii wide
        
    condition:
        uint16(0) == 0x5A4D and  // MZ header
        any of them
}

rule DBK64_PE_Characteristics {
    meta:
        description = "Detects DBK64.sys by PE structure characteristics"
        author = "AI Agent Analysis"
        reference = "Verified through r2 PE analysis"
        
    condition:
        uint16(0) == 0x5A4D and  // MZ header
        uint32(uint32(0x3C)) == 0x00004550 and  // PE signature
        uint16(uint32(0x3C) + 0x18) == 0x020b and  // PE32+
        uint16(uint32(0x3C) + 0x5C) == 0x01 and  // Subsystem: Native
        filesize == 94136  // Exact file size
}

rule DBK64_Comprehensive {
    meta:
        description = "Comprehensive DBK64.sys detection rule"
        author = "AI Agent Analysis"
        reference = "Combined indicators from complete analysis"
        confidence = "high"
        
    strings:
        // High-confidence strings
        $pdb = "DBK64.pdb" ascii nocase
        $cheat_engine = "cheat-engine" ascii nocase
        
        // Critical API combination (subset for performance)
        $api1 = "PsLookupProcessByProcessId" ascii
        $api2 = "KeAttachProcess" ascii
        $api3 = "MmGetPhysicalMemoryRanges" ascii
        $api4 = "KeInitializeApc" ascii
        
        // Device/service names
        $device = "DBK64" ascii wide
        
    condition:
        uint16(0) == 0x5A4D and  // MZ header
        uint16(uint32(0x3C) + 0x5C) == 0x01 and  // Native subsystem (kernel driver)
        filesize > 90KB and filesize < 100KB and
        (
            $pdb or
            $cheat_engine or
            (3 of ($api*)) or
            $device
        )
}

rule DBK64_Registry_IOCs {
    meta:
        description = "Registry artifacts for DBK64.sys deployment"
        author = "AI Agent Analysis"
        reference = "Observed during dynamic testing"
        
    strings:
        $reg1 = "SYSTEM\\CurrentControlSet\\Services\\DBK64" ascii wide nocase
        $reg2 = "SYSTEM\\CurrentControlSet\\Services\\CEDRIVER73" ascii wide nocase
        $reg3 = "DBK64.sys" ascii wide nocase
        $reg4 = "CEDRIVER73" ascii wide nocase
        
    condition:
        any of them
}
