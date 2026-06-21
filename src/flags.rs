pub fn machine_name(m: u16) -> &'static str {
    match m {
        0x014c => "i386",
        0x0200 => "ia64",
        0x8664 => "x64",
        0xaa64 => "arm64",
        0x01c0 => "arm",
        0x01c4 => "armnt",
        0x5032 => "riscv32",
        0x5064 => "riscv64",
        _ => "unknown",
    }
}

pub fn subsystem_name(s: u16) -> &'static str {
    match s {
        1 => "Native",
        2 => "Windows GUI",
        3 => "Windows CUI",
        5 => "OS/2 CUI",
        7 => "POSIX CUI",
        9 => "Windows CE GUI",
        10 => "EFI Application",
        11 => "EFI Boot Service Driver",
        12 => "EFI Runtime Driver",
        13 => "EFI ROM",
        14 => "XBOX",
        16 => "Windows Boot Application",
        _ => "unknown",
    }
}

pub fn characteristics(c: u16) -> Vec<&'static str> {
    let mut v = Vec::new();
    if c & 0x0001 != 0 { v.push("RELOCS_STRIPPED"); }
    if c & 0x0002 != 0 { v.push("EXECUTABLE_IMAGE"); }
    if c & 0x0004 != 0 { v.push("LINE_NUMS_STRIPPED"); }
    if c & 0x0008 != 0 { v.push("LOCAL_SYMS_STRIPPED"); }
    if c & 0x0010 != 0 { v.push("AGGRESSIVE_WS_TRIM"); }
    if c & 0x0020 != 0 { v.push("LARGE_ADDRESS_AWARE"); }
    if c & 0x0080 != 0 { v.push("BYTES_REVERSED_LO"); }
    if c & 0x0100 != 0 { v.push("32BIT_MACHINE"); }
    if c & 0x0200 != 0 { v.push("DEBUG_STRIPPED"); }
    if c & 0x0400 != 0 { v.push("REMOVABLE_RUN_FROM_SWAP"); }
    if c & 0x0800 != 0 { v.push("NET_RUN_FROM_SWAP"); }
    if c & 0x1000 != 0 { v.push("SYSTEM"); }
    if c & 0x2000 != 0 { v.push("DLL"); }
    if c & 0x4000 != 0 { v.push("UP_SYSTEM_ONLY"); }
    if c & 0x8000 != 0 { v.push("BYTES_REVERSED_HI"); }
    v
}

pub fn dll_characteristics(c: u16) -> Vec<&'static str> {
    let mut v = Vec::new();
    if c & 0x0020 != 0 { v.push("HIGH_ENTROPY_VA"); }
    if c & 0x0040 != 0 { v.push("DYNAMIC_BASE"); }
    if c & 0x0080 != 0 { v.push("FORCE_INTEGRITY"); }
    if c & 0x0100 != 0 { v.push("NX_COMPAT"); }
    if c & 0x0200 != 0 { v.push("NO_ISOLATION"); }
    if c & 0x0400 != 0 { v.push("NO_SEH"); }
    if c & 0x0800 != 0 { v.push("NO_BIND"); }
    if c & 0x1000 != 0 { v.push("APPCONTAINER"); }
    if c & 0x2000 != 0 { v.push("WDM_DRIVER"); }
    if c & 0x4000 != 0 { v.push("GUARD_CF"); }
    if c & 0x8000 != 0 { v.push("TERMINAL_SERVER_AWARE"); }
    v
}

pub fn section_characteristics(c: u32) -> Vec<&'static str> {
    let mut v = Vec::new();
    if c & 0x0000_0020 != 0 { v.push("CODE"); }
    if c & 0x0000_0040 != 0 { v.push("INITIALIZED_DATA"); }
    if c & 0x0000_0080 != 0 { v.push("UNINITIALIZED_DATA"); }
    if c & 0x0200_0000 != 0 { v.push("DISCARDABLE"); }
    if c & 0x0400_0000 != 0 { v.push("NOT_CACHED"); }
    if c & 0x0800_0000 != 0 { v.push("NOT_PAGED"); }
    if c & 0x1000_0000 != 0 { v.push("SHARED"); }
    if c & 0x2000_0000 != 0 { v.push("EXECUTE"); }
    if c & 0x4000_0000 != 0 { v.push("READ"); }
    if c & 0x8000_0000 != 0 { v.push("WRITE"); }
    v
}
