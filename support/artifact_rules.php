<?php
	// PE File artifact rules.
	// (C) 2019 CubicleSoft.  All Rights Reserved.

	if (!class_exists("WinPEFile", false))  require_once str_replace("\\", "/", dirname(__FILE__)) . "/win_pe_file.php";

	// Define interesting files for a core artifact library for testing and analysis.
	$g_artifact_rules = array(
		// Don't attempt to integrate broken PE files into the artifact library (other than this one entry).
		array("path" => "dos_header.pe_offset_valid", "op" => "==", "val" => false, "name" => "pe_invalid_offset", "break" => true, "rare" => "64_pe"),

		// Basic MZ header signature.
		array("path" => "dos_header.signature", "op" => "==", "val" => "MZ", "name" => "dos/dos_signature_mz", "prefix" => false),

		// Some rare MS-DOS program headers.
		array("path" => "dos_header.signature", "op" => "==", "val" => "ZM", "name" => "dos/dos_zm", "prefix" => false, "rare" => true),
		array("path" => "dos_header.checksum", "op" => "==", "val" => 0, "name" => "dos/dos_checksum_zero", "prefix" => false),
		array("path" => "dos_header.checksum", "op" => "!=", "val" => 0, "name" => "dos/dos_checksum_non_zero", "prefix" => false),
		array("path" => "dos_header.overlay_num", "op" => "!=", "val" => 0, "name" => "dos/dos_overlay_num", "prefix" => false),

		array("if" => array(
			array("path" => "dos_header.reserved_1", "op" => "==", "val" => "\x00\x00\x00\x00\x00\x00\x00\x00"),
			array("path" => "dos_header.reserved_2", "op" => "==", "val" => "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
			array("path" => "dos_header.oem_identifier", "op" => "!=", "val" => 0),
		), "name" => "dos/dos_oem_identifier", "prefix" => false),

		array("if" => array(
			array("path" => "dos_header.reserved_1", "op" => "==", "val" => "\x00\x00\x00\x00\x00\x00\x00\x00"),
			array("path" => "dos_header.reserved_2", "op" => "==", "val" => "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
			array("path" => "dos_header.oem_info", "op" => "!=", "val" => 0),
		), "name" => "dos/dos_oem_info", "prefix" => false),

		array("path" => "dos_header.pe_offset", "op" => "==", "val" => 0, "name" => "dos/dos_only", "prefix" => false, "rare" => true),

		// Win16 NE files.
		array("path" => "ne_header.signature", "op" => "==", "val" => "NE", "name" => "16_ne/16_ne_sigature_ne", "prefix" => false),

		array("path" => "ne_header.program_flags", "op" => "&=", "mask" => 0x03, "val" => WinPEFile::WIN16_NE_PROGRAM_FLAGS_DGROUP_NONE, "name" => "16_ne/16_ne_program_flags_dgroup_none", "prefix" => false),
		array("path" => "ne_header.program_flags", "op" => "&=", "mask" => 0x03, "val" => WinPEFile::WIN16_NE_PROGRAM_FLAGS_DGROUP_SINSHARED, "name" => "16_ne/16_ne_program_flags_dgroup_sinshared", "prefix" => false),
		array("path" => "ne_header.program_flags", "op" => "&=", "mask" => 0x03, "val" => WinPEFile::WIN16_NE_PROGRAM_FLAGS_DGROUP_MULTIPLE, "name" => "16_ne/16_ne_program_flags_dgroup_multiple", "prefix" => false),
		array("path" => "ne_header.program_flags", "op" => "&=", "mask" => 0x03, "val" => WinPEFile::WIN16_NE_PROGRAM_FLAGS_DGROUP_NULL, "name" => "16_ne/16_ne_program_flags_dgroup_null", "prefix" => false, "rare" => true),
		array("path" => "ne_header.program_flags", "op" => "&", "val" => WinPEFile::WIN16_NE_PROGRAM_FLAGS_GLOBAL_INIT, "name" => "16_ne/16_ne_program_flags_global_init", "prefix" => false, "rare" => true),
		array("path" => "ne_header.program_flags", "op" => "&", "val" => WinPEFile::WIN16_NE_PROGRAM_FLAGS_PROTECTED_MODE_ONLY, "name" => "16_ne/16_ne_program_flags_prot_mode_only", "prefix" => false),
		array("path" => "ne_header.program_flags", "op" => "&", "val" => WinPEFile::WIN16_NE_PROGRAM_FLAGS_8086, "name" => "16_ne/16_ne_program_flags_8086", "prefix" => false, "rare" => true),
		array("path" => "ne_header.program_flags", "op" => "&", "val" => WinPEFile::WIN16_NE_PROGRAM_FLAGS_80286, "name" => "16_ne/16_ne_program_flags_80286", "prefix" => false, "rare" => true),
		array("path" => "ne_header.program_flags", "op" => "&", "val" => WinPEFile::WIN16_NE_PROGRAM_FLAGS_80386, "name" => "16_ne/16_ne_program_flags_80386", "prefix" => false, "rare" => true),
		array("path" => "ne_header.program_flags", "op" => "&", "val" => WinPEFile::WIN16_NE_PROGRAM_FLAGS_8087, "name" => "16_ne/16_ne_program_flags_8087", "prefix" => false, "rare" => true),

		array("path" => "ne_header.app_flags", "op" => "&=", "mask" => 0x03, "val" => WinPEFile::WIN16_NE_APP_FLAGS_TYPE_NONE, "name" => "16_ne/16_ne_app_flags_type_none", "prefix" => false),
		array("path" => "ne_header.app_flags", "op" => "&=", "mask" => 0x03, "val" => WinPEFile::WIN16_NE_APP_FLAGS_TYPE_FULLSCREEN, "name" => "16_ne/16_ne_app_flags_type_fullscreen", "prefix" => false, "rare" => true),
		array("path" => "ne_header.app_flags", "op" => "&=", "mask" => 0x03, "val" => WinPEFile::WIN16_NE_APP_FLAGS_TYPE_WINPMCOMPAT, "name" => "16_ne/16_ne_app_flags_type_winpmcompat", "prefix" => false, "rare" => true),
		array("path" => "ne_header.app_flags", "op" => "&=", "mask" => 0x03, "val" => WinPEFile::WIN16_NE_APP_FLAGS_TYPE_WINPMUSES, "name" => "16_ne/16_ne_app_flags_type_winpmuses", "prefix" => false),
		array("path" => "ne_header.app_flags", "op" => "&", "val" => 0x04, "name" => "16_ne/16_ne_app_flags_unknown_0x04", "prefix" => false, "rare" => true),
		array("path" => "ne_header.app_flags", "op" => "&", "val" => WinPEFile::WIN16_NE_APP_FLAGS_OS2_APP, "name" => "16_ne/16_ne_app_flags_os2_app", "prefix" => false),
		array("path" => "ne_header.app_flags", "op" => "&", "val" => 0x10, "name" => "16_ne/16_ne_app_flags_reserved_0x10", "prefix" => false, "rare" => true),
		array("path" => "ne_header.app_flags", "op" => "&", "val" => WinPEFile::WIN16_NE_APP_FLAGS_IMAGE_ERROR, "name" => "16_ne/16_ne_app_flags_image_error", "prefix" => false, "rare" => true),
		array("path" => "ne_header.app_flags", "op" => "&", "val" => WinPEFile::WIN16_NE_APP_FLAGS_NON_CONFORM, "name" => "16_ne/16_ne_app_flags_non_conform", "prefix" => false, "rare" => true),
		array("path" => "ne_header.app_flags", "op" => "&", "val" => WinPEFile::WIN16_NE_APP_FLAGS_DLL, "name" => "16_ne/16_ne_app_flags_dll", "prefix" => false),

		array("path" => "ne_header.target_os", "op" => "==", "val" => WinPEFile::WIN16_NE_TARGET_OS_UNKNOWN, "name" => "16_ne/16_ne_target_os_unknown", "prefix" => false, "rare" => true),
		array("path" => "ne_header.target_os", "op" => "==", "val" => WinPEFile::WIN16_NE_TARGET_OS_OS2, "name" => "16_ne/16_ne_target_os_os2", "prefix" => false),
		array("path" => "ne_header.target_os", "op" => "==", "val" => WinPEFile::WIN16_NE_TARGET_OS_WIN, "name" => "16_ne/16_ne_target_os_win", "prefix" => false),
		array("path" => "ne_header.target_os", "op" => "==", "val" => WinPEFile::WIN16_NE_TARGET_OS_DOS4, "name" => "16_ne/16_ne_target_os_dos4", "prefix" => false, "rare" => true),
		array("path" => "ne_header.target_os", "op" => "==", "val" => WinPEFile::WIN16_NE_TARGET_OS_WIN386, "name" => "16_ne/16_ne_target_os_win386", "prefix" => false, "rare" => true),
		array("path" => "ne_header.target_os", "op" => "==", "val" => WinPEFile::WIN16_NE_TARGET_OS_BOSS, "name" => "16_ne/16_ne_target_os_boss", "prefix" => false),
		array("path" => "ne_header.target_os", "op" => ">=", "val" => 6, "name" => "16_ne/16_ne_target_os_over_5", "prefix" => false, "rare" => true),

		array("path" => "ne_header.os2_exe_flags", "op" => "&", "val" => WinPEFile::WIN16_NE_OS2_EXE_FLAGS_LFN, "name" => "16_ne/16_ne_os2_exe_flags_lfn", "prefix" => false, "rare" => true),
		array("path" => "ne_header.os2_exe_flags", "op" => "&", "val" => WinPEFile::WIN16_NE_OS2_EXE_FLAGS_PROTECTED_MODE, "name" => "16_ne/16_ne_os2_exe_flags_protected_mode", "prefix" => false, "rare" => true),
		array("path" => "ne_header.os2_exe_flags", "op" => "&", "val" => WinPEFile::WIN16_NE_OS2_EXE_FLAGS_PROPORTIONAL_FONTS, "name" => "16_ne/16_ne_os2_exe_flags_proportional_fonts", "prefix" => false, "rare" => true),
		array("path" => "ne_header.os2_exe_flags", "op" => "&", "val" => WinPEFile::WIN16_NE_OS2_EXE_FLAGS_GANGLOAD_AREA, "name" => "16_ne/16_ne_os2_exe_flags_gangload_area", "prefix" => false),
		array("path" => "ne_header.os2_exe_flags", "op" => ">=", "val" => 0xF0, "name" => "16_ne/16_ne_os2_exe_flags_unknown", "prefix" => false, "rare" => true),

		// PE machine types.
		array("path" => "pe_header.machine_type", "op" => "==", "val" => WinPEFile::IMAGE_FILE_MACHINE_UNKNOWN, "name" => "pe_machine_unknown", "rare" => true),
		array("path" => "pe_header.machine_type", "op" => "==", "val" => WinPEFile::IMAGE_FILE_MACHINE_I386, "name" => "pe_machine_i386", "rare" => "64_pe"),
		array("path" => "pe_header.machine_type", "op" => "==", "val" => WinPEFile::IMAGE_FILE_MACHINE_AMD64, "name" => "pe_machine_x64", "rare" => "32_pe"),
		array("path" => "pe_header.machine_type", "op" => "==", "val" => WinPEFile::IMAGE_FILE_MACHINE_DOT_NET_CLR, "name" => "pe_machine_dot_net_clr", "rare" => true),

		// Some rare machine types.
		array("path" => "pe_header.machine_type", "op" => "==", "val" => WinPEFile::IMAGE_FILE_MACHINE_R3000_BE, "name" => "pe_machine_mips_r3000_big", "rare" => true),
		array("path" => "pe_header.machine_type", "op" => "==", "val" => WinPEFile::IMAGE_FILE_MACHINE_R3000_LE, "name" => "pe_machine_mips_r3000_little", "rare" => true),
		array("path" => "pe_header.machine_type", "op" => "==", "val" => WinPEFile::IMAGE_FILE_MACHINE_R4000, "name" => "pe_machine_mips_r4000", "rare" => "64_pe"),
		array("path" => "pe_header.machine_type", "op" => "==", "val" => WinPEFile::IMAGE_FILE_MACHINE_R10000, "name" => "pe_machine_mips_r10000", "rare" => true),
		array("path" => "pe_header.machine_type", "op" => "==", "val" => WinPEFile::IMAGE_FILE_MACHINE_WCEMIPSV2, "name" => "pe_machine_mips_wce_v2", "rare" => true),
		array("path" => "pe_header.machine_type", "op" => "==", "val" => WinPEFile::IMAGE_FILE_MACHINE_OLD_DECALPHAAXP, "name" => "pe_machine_old_dec_alpha_axp", "rare" => true),
		array("path" => "pe_header.machine_type", "op" => "==", "val" => WinPEFile::IMAGE_FILE_MACHINE_DECALPHAAXP, "name" => "pe_machine_dec_alpha_axp", "rare" => "64_pe"),
		array("path" => "pe_header.machine_type", "op" => "==", "val" => WinPEFile::IMAGE_FILE_MACHINE_SH3, "name" => "pe_machine_hitachi_sh3", "rare" => true),
		array("path" => "pe_header.machine_type", "op" => "==", "val" => WinPEFile::IMAGE_FILE_MACHINE_SH3DSP, "name" => "pe_machine_hitachi_sh3_dsp", "rare" => true),
		array("path" => "pe_header.machine_type", "op" => "==", "val" => WinPEFile::IMAGE_FILE_MACHINE_SH3E, "name" => "pe_machine_hitachi_sh3e", "rare" => true),
		array("path" => "pe_header.machine_type", "op" => "==", "val" => WinPEFile::IMAGE_FILE_MACHINE_SH4, "name" => "pe_machine_hitachi_sh4", "rare" => true),
		array("path" => "pe_header.machine_type", "op" => "==", "val" => WinPEFile::IMAGE_FILE_MACHINE_SH5, "name" => "pe_machine_hitachi_sh5", "rare" => true),
		array("path" => "pe_header.machine_type", "op" => "==", "val" => WinPEFile::IMAGE_FILE_MACHINE_ARM, "name" => "pe_machine_arm_little", "rare" => true),
		array("path" => "pe_header.machine_type", "op" => "==", "val" => WinPEFile::IMAGE_FILE_MACHINE_THUMB, "name" => "pe_machine_arm_thumb", "rare" => true),
		array("path" => "pe_header.machine_type", "op" => "==", "val" => WinPEFile::IMAGE_FILE_MACHINE_ARMNT, "name" => "pe_machine_arm_thumb2_armv7", "rare" => "64_pe"),
		array("path" => "pe_header.machine_type", "op" => "==", "val" => WinPEFile::IMAGE_FILE_MACHINE_AM33, "name" => "pe_machine_matsushita_am33", "rare" => true),
		array("path" => "pe_header.machine_type", "op" => "==", "val" => WinPEFile::IMAGE_FILE_MACHINE_POWERPC, "name" => "pe_machine_ibm_powerpc_little", "rare" => true),
		array("path" => "pe_header.machine_type", "op" => "==", "val" => WinPEFile::IMAGE_FILE_MACHINE_POWERPCFP, "name" => "pe_machine_ibm_powerpc_w_floating", "rare" => true),
		array("path" => "pe_header.machine_type", "op" => "==", "val" => WinPEFile::IMAGE_FILE_MACHINE_IA64, "name" => "pe_machine_itanium", "rare" => "32_pe"),
		array("path" => "pe_header.machine_type", "op" => "==", "val" => WinPEFile::IMAGE_FILE_MACHINE_MIPS16, "name" => "pe_machine_mips16", "rare" => true),
		array("path" => "pe_header.machine_type", "op" => "==", "val" => WinPEFile::IMAGE_FILE_MACHINE_MOTOROLA68000, "name" => "pe_machine_motorola_68000", "rare" => true),
		array("path" => "pe_header.machine_type", "op" => "==", "val" => WinPEFile::IMAGE_FILE_MACHINE_DECALPHAAXP64, "name" => "pe_machine_dec_alpha_axp64", "rare" => true),
		array("path" => "pe_header.machine_type", "op" => "==", "val" => WinPEFile::IMAGE_FILE_MACHINE_MIPSFPU, "name" => "pe_machine_mips_w_fpu", "rare" => true),
		array("path" => "pe_header.machine_type", "op" => "==", "val" => WinPEFile::IMAGE_FILE_MACHINE_MIPSFPU16, "name" => "pe_machine_mips16_w_fpu", "rare" => true),
		array("path" => "pe_header.machine_type", "op" => "==", "val" => WinPEFile::IMAGE_FILE_MACHINE_INFINEONTRICORE, "name" => "pe_machine_infineon_tricore_yikes", "rare" => true),
		array("path" => "pe_header.machine_type", "op" => "==", "val" => WinPEFile::IMAGE_FILE_MACHINE_CEF, "name" => "pe_machine_cef", "rare" => true),
		array("path" => "pe_header.machine_type", "op" => "==", "val" => WinPEFile::IMAGE_FILE_MACHINE_EBC, "name" => "pe_machine_efi_byte_code", "rare" => true),
		array("path" => "pe_header.machine_type", "op" => "==", "val" => WinPEFile::IMAGE_FILE_MACHINE_RISCV32, "name" => "pe_machine_risc_v_32", "rare" => true),
		array("path" => "pe_header.machine_type", "op" => "==", "val" => WinPEFile::IMAGE_FILE_MACHINE_RISCV64, "name" => "pe_machine_risc_v_64", "rare" => true),
		array("path" => "pe_header.machine_type", "op" => "==", "val" => WinPEFile::IMAGE_FILE_MACHINE_RISCV128, "name" => "pe_machine_risc_v_128", "rare" => true),
		array("path" => "pe_header.machine_type", "op" => "==", "val" => WinPEFile::IMAGE_FILE_MACHINE_M32R, "name" => "pe_machine_mitsubishi_m32r", "rare" => true),
		array("path" => "pe_header.machine_type", "op" => "==", "val" => WinPEFile::IMAGE_FILE_MACHINE_ARM64, "name" => "pe_machine_arm64_little", "rare" => "32_pe"),
		array("path" => "pe_header.machine_type", "op" => "!=", "val" => array_keys(WinPEFile::$machine_types), "name" => "pe_machine_missing_in_action", "rare" => true),

		// Is this even possible?
		array("path" => "pe_header.num_sections", "op" => "==", "val" => 0, "name" => "pe_num_sections_zero", "rare" => true),

		// Obsolete COFF.  A now endangered species.
		array("path" => "pe_header.symbol_table_ptr", "op" => "!=", "val" => 0, "name" => "pe_symbol_table_ptr_obsolete"),
		array("path" => "pe_header.num_symbols", "op" => "!=", "val" => 0, "name" => "pe_num_symbols_obsolete"),

		// Is this even possible?
		array("path" => "pe_header.signature|pe_header.optional_header_size", "op" => "==", "val" => "PE\x00\x00|0", "name" => "pe_optional_header_size_zero", "rare" => true),

		array("path" => "pe_header.flags", "op" => "&", "val" => WinPEFile::IMAGE_FILE_RELOCS_STRIPPED, "name" => "pe_flags_relocs_stripped"),
		array("path" => "pe_header.flags", "op" => "&", "val" => WinPEFile::IMAGE_FILE_EXECUTABLE_IMAGE, "name" => "pe_flags_executable"),
		array("path" => "pe_header.flags", "op" => "&", "val" => WinPEFile::IMAGE_FILE_LINE_NUMS_STRIPPED, "name" => "pe_flags_line_nums_stripped"),
		array("path" => "pe_header.flags", "op" => "&", "val" => WinPEFile::IMAGE_FILE_LOCAL_SYMS_STRIPPED, "name" => "pe_flags_local_syms_stripped"),
		array("path" => "pe_header.flags", "op" => "&", "val" => WinPEFile::IMAGE_FILE_AGGRESSIVE_WS_TRIM, "name" => "pe_flags_aggressive_ws_trim", "rare" => "64_pe"),
		array("path" => "pe_header.flags", "op" => "&", "val" => WinPEFile::IMAGE_FILE_LARGE_ADDRESS_AWARE, "name" => "pe_flags_large_address_aware"),

		// Probably nothing out there.  But let's see if anything turns up that uses this.
		array("path" => "pe_header.flags", "op" => "&", "val" => 0x0040, "name" => "pe_flags_reserved_0x0040", "rare" => true),

		array("path" => "pe_header.flags", "op" => "&", "val" => WinPEFile::IMAGE_FILE_BYTES_REVERSED_LO, "name" => "pe_flags_bytes_reversed_lo", "rare" => "64_pe"),
		array("path" => "pe_header.flags", "op" => "&", "val" => WinPEFile::IMAGE_FILE_32BIT_MACHINE, "name" => "pe_flags_32bit_machine"),
		array("path" => "pe_header.flags", "op" => "&", "val" => WinPEFile::IMAGE_FILE_DEBUG_STRIPPED, "name" => "pe_flags_debug_stripped"),
		array("path" => "pe_header.flags", "op" => "&", "val" => WinPEFile::IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP, "name" => "pe_flags_removable_run_from_swap"),
		array("path" => "pe_header.flags", "op" => "&", "val" => WinPEFile::IMAGE_FILE_NET_RUN_FROM_SWAP, "name" => "pe_flags_net_run_from_swap"),
		array("path" => "pe_header.flags", "op" => "&", "val" => WinPEFile::IMAGE_FILE_SYSTEM, "name" => "pe_flags_system", "rare" => true),
		array("path" => "pe_header.flags", "op" => "&", "val" => WinPEFile::IMAGE_FILE_DLL, "name" => "pe_flags_dll"),
		array("path" => "pe_header.flags", "op" => "&", "val" => WinPEFile::IMAGE_FILE_UP_SYSTEM_ONLY, "name" => "pe_flags_up_system_only", "rare" => true),
		array("path" => "pe_header.flags", "op" => "&", "val" => WinPEFile::IMAGE_FILE_BYTES_REVERSED_HI, "name" => "pe_flags_bytes_reversed_hi", "rare" => "64_pe"),

		array("path" => "pe_header.flags", "op" => "&", "val" => WinPEFile::IMAGE_FILE_EXECUTABLE_IMAGE | WinPEFile::IMAGE_FILE_DLL, "name" => "pe_flags_executable_dll"),

		array("path" => "pe_opt_header.signature", "op" => "==", "val" => WinPEFile::OPT_HEADER_SIGNATURE_PE32, "name" => "pe_signature_pe32", "rare" => "64_pe"),
		array("path" => "pe_opt_header.signature", "op" => "==", "val" => WinPEFile::OPT_HEADER_SIGNATURE_PE32_PLUS, "name" => "pe_signature_pe32_plus", "rare" => "32_pe"),

		// The mysterious ROM image and an impossible/corrupt signature.
		array("path" => "pe_opt_header.signature", "op" => "==", "val" => WinPEFile::OPT_HEADER_SIGNATURE_ROM_IMAGE, "name" => "pe_signature_rom_image", "rare" => true),
		array("path" => "pe_opt_header.signature", "op" => "!=", "val" => array(WinPEFile::OPT_HEADER_SIGNATURE_PE32, WinPEFile::OPT_HEADER_SIGNATURE_PE32_PLUS, WinPEFile::OPT_HEADER_SIGNATURE_ROM_IMAGE), "name" => "pe_signature_unknown_corrupt", "rare" => true),

		array("path" => "pe_opt_header.entry_point_addr", "op" => "==", "val" => 0, "name" => "pe_entry_point_addr_zero"),

		array("path" => "pe_opt_header.image_base", "op" => "==", "val" => WinPEFile::IMAGE_BASE_DLL_DEFAULT, "name" => "pe_image_base_dll"),
		array("path" => "pe_opt_header.image_base", "op" => "==", "val" => WinPEFile::IMAGE_BASE_EXE_DEFAULT, "name" => "pe_image_base_exe"),
		array("path" => "pe_opt_header.image_base", "op" => "!=", "val" => array(WinPEFile::IMAGE_BASE_DLL_DEFAULT, WinPEFile::IMAGE_BASE_EXE_DEFAULT, WinPEFile::IMAGE_BASE_CE_EXE_DEFAULT), "name" => "pe_image_base_non_default"),

		// Never played with Windows CE but always saw references to it.
		array("path" => "pe_opt_header.image_base", "op" => "==", "val" => WinPEFile::IMAGE_BASE_CE_EXE_DEFAULT, "name" => "pe_image_base_win_ce", "rare" => "64_pe"),

		// Possibly Win32s.
		array("path" => "pe_opt_header.win32_version", "op" => "!=", "val" => 0, "name" => "pe_win32_version_non_zero", "rare" => true),

		array("path" => "pe_opt_header.section_alignment", "op" => "!=", "val" => 4096, "name" => "pe_section_alignment_non_standard"),
		array("path" => "pe_opt_header.file_alignment", "op" => "!=", "val" => 4096, "name" => "pe_file_alignment_non_standard"),

		array("path" => "pe_opt_header.major_os_ver|pe_opt_header.minor_os_ver", "op" => "hash", "name" => "pe_os_ver_"),
		array("path" => "pe_opt_header.major_subsystem_ver|pe_opt_header.minor_subsystem_ver", "op" => "hash", "name" => "pe_subsystem_ver_"),
		array("path" => "pe_opt_header.major_os_ver|pe_opt_header.minor_os_ver|pe_opt_header.major_subsystem_ver|pe_opt_header.minor_subsystem_ver", "op" => "hash", "name" => "pe_os_and_subsystem_ver_"),

		array("path" => "pe_opt_header.checksum", "op" => "==", "val" => 0, "name" => "pe_checksum_zero"),
		array("path" => "pe_opt_header.checksum", "op" => "!=", "val" => 0, "name" => "pe_checksum_non_zero"),

		array("path" => "pe_opt_header.subsystem", "op" => "==", "val" => 0, "name" => "pe_subsystem_unknown", "rare" => true),
		array("path" => "pe_opt_header.subsystem", "op" => "==", "val" => 1, "name" => "pe_subsystem_native"),
		array("path" => "pe_opt_header.subsystem", "op" => "==", "val" => 2, "name" => "pe_subsystem_win_gui"),
		array("path" => "pe_opt_header.subsystem", "op" => "==", "val" => 3, "name" => "pe_subsystem_win_console"),
		array("path" => "pe_opt_header.subsystem", "op" => "==", "val" => 4, "name" => "pe_subsystem_unknown_4", "rare" => true),
		array("path" => "pe_opt_header.subsystem", "op" => "==", "val" => 5, "name" => "pe_subsystem_os2_console", "rare" => true),
		array("path" => "pe_opt_header.subsystem", "op" => "==", "val" => 6, "name" => "pe_subsystem_unknown_6", "rare" => true),
		array("path" => "pe_opt_header.subsystem", "op" => "==", "val" => 7, "name" => "pe_subsystem_posix_console", "rare" => true),
		array("path" => "pe_opt_header.subsystem", "op" => "==", "val" => 8, "name" => "pe_subsystem_unknown_8", "rare" => true),
		array("path" => "pe_opt_header.subsystem", "op" => "==", "val" => 9, "name" => "pe_subsystem_win_ce_gui", "rare" => "64_pe"),
		array("path" => "pe_opt_header.subsystem", "op" => "==", "val" => 10, "name" => "pe_subsystem_efi_application", "rare" => true),
		array("path" => "pe_opt_header.subsystem", "op" => "==", "val" => 11, "name" => "pe_subsystem_efi_boot_service_driver", "rare" => true),
		array("path" => "pe_opt_header.subsystem", "op" => "==", "val" => 12, "name" => "pe_subsystem_efi_run_time_driver", "rare" => true),
		array("path" => "pe_opt_header.subsystem", "op" => "==", "val" => 13, "name" => "pe_subsystem_efi_rom_image", "rare" => true),
		array("path" => "pe_opt_header.subsystem", "op" => "==", "val" => 14, "name" => "pe_subsystem_xbox", "rare" => true),
		array("path" => "pe_opt_header.subsystem", "op" => "==", "val" => 15, "name" => "pe_subsystem_unknown_15", "rare" => true),
		array("path" => "pe_opt_header.subsystem", "op" => "==", "val" => 16, "name" => "pe_subsystem_boot_application"),
		array("path" => "pe_opt_header.subsystem", "op" => ">=", "val" => 17, "name" => "pe_subsystem_unknown_17_plus", "rare" => true),

		array("path" => "pe_opt_header.dll_characteristics", "op" => "&", "val" => 0x0001, "name" => "pe_dll_characteristics_reserved_0x0001", "rare" => "64_pe"),
		array("path" => "pe_opt_header.dll_characteristics", "op" => "&", "val" => 0x0002, "name" => "pe_dll_characteristics_reserved_0x0002", "rare" => true),
		array("path" => "pe_opt_header.dll_characteristics", "op" => "&", "val" => 0x0004, "name" => "pe_dll_characteristics_reserved_0x0004", "rare" => true),
		array("path" => "pe_opt_header.dll_characteristics", "op" => "&", "val" => 0x0008, "name" => "pe_dll_characteristics_reserved_0x0008", "rare" => true),
		array("path" => "pe_opt_header.dll_characteristics", "op" => "&", "val" => 0x0010, "name" => "pe_dll_characteristics_unknown_0x0010", "rare" => true),
		array("path" => "pe_opt_header.dll_characteristics", "op" => "&", "val" => 0x0020, "name" => "pe_dll_characteristics_unknown_0x0020"),
		array("path" => "pe_opt_header.dll_characteristics", "op" => "&", "val" => WinPEFile::IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE, "name" => "pe_dll_characteristics_dynamic_base"),
		array("path" => "pe_opt_header.dll_characteristics", "op" => "&", "val" => WinPEFile::IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY, "name" => "pe_dll_characteristics_force_integrity"),
		array("path" => "pe_opt_header.dll_characteristics", "op" => "&", "val" => WinPEFile::IMAGE_DLL_CHARACTERISTICS_NX_COMPAT, "name" => "pe_dll_characteristics_nx_compat"),
		array("path" => "pe_opt_header.dll_characteristics", "op" => "&", "val" => WinPEFile::IMAGE_DLL_CHARACTERISTICS_NO_ISOLATION, "name" => "pe_dll_characteristics_no_isolation"),
		array("path" => "pe_opt_header.dll_characteristics", "op" => "&", "val" => WinPEFile::IMAGE_DLL_CHARACTERISTICS_NO_SEH, "name" => "pe_dll_characteristics_no_seh"),
		array("path" => "pe_opt_header.dll_characteristics", "op" => "&", "val" => WinPEFile::IMAGE_DLL_CHARACTERISTICS_NO_BIND, "name" => "pe_dll_characteristics_no_bind", "rare" => true),
		array("path" => "pe_opt_header.dll_characteristics", "op" => "&", "val" => 0x1000, "name" => "pe_dll_characteristics_reserved_0x1000"),
		array("path" => "pe_opt_header.dll_characteristics", "op" => "&", "val" => WinPEFile::IMAGE_DLL_CHARACTERISTICS_WDM_DRIVER, "name" => "pe_dll_characteristics_no_isolation"),
		array("path" => "pe_opt_header.dll_characteristics", "op" => "&", "val" => 0x4000, "name" => "pe_dll_characteristics_unknown_0x4000"),
		array("path" => "pe_opt_header.dll_characteristics", "op" => "&", "val" => WinPEFile::IMAGE_DLL_CHARACTERISTICS_TERMINAL_SERVER_AWARE, "name" => "pe_dll_characteristics_terminal_server_aware"),

		array("path" => "pe_opt_header.stack_reserve_size", "op" => "<", "val" => 0x00100000, "name" => "pe_stack_reserve_size_under_1mb"),
		array("path" => "pe_opt_header.stack_reserve_size", "op" => "==", "val" => 0x00100000, "name" => "pe_stack_reserve_size_equal_1mb"),
		array("path" => "pe_opt_header.stack_reserve_size", "op" => ">", "val" => 0x00100000, "name" => "pe_stack_reserve_size_over_1mb"),

		array("path" => "pe_opt_header.stack_commit_size", "op" => "<", "val" => 0x00001000, "name" => "pe_stack_commit_size_under_4096"),
		array("path" => "pe_opt_header.stack_commit_size", "op" => "==", "val" => 0x00001000, "name" => "pe_stack_commit_size_equal_4096"),
		array("path" => "pe_opt_header.stack_commit_size", "op" => ">", "val" => 0x00001000, "name" => "pe_stack_commit_size_over_4096"),

		array("path" => "pe_opt_header.heap_reserve_size", "op" => "<", "val" => 0x00100000, "name" => "pe_heap_reserve_size_under_1mb"),
		array("path" => "pe_opt_header.heap_reserve_size", "op" => "==", "val" => 0x00100000, "name" => "pe_heap_reserve_size_equal_1mb"),
		array("path" => "pe_opt_header.heap_reserve_size", "op" => ">", "val" => 0x00100000, "name" => "pe_heap_reserve_size_over_1mb"),

		array("path" => "pe_opt_header.heap_commit_size", "op" => "<", "val" => 0x00001000, "name" => "pe_heap_commit_size_under_4096"),
		array("path" => "pe_opt_header.heap_commit_size", "op" => "==", "val" => 0x00001000, "name" => "pe_heap_commit_size_equal_4096"),
		array("path" => "pe_opt_header.heap_commit_size", "op" => ">", "val" => 0x00001000, "name" => "pe_heap_commit_size_over_4096"),

		// Loader flags are supposed to always be zero.
		array("path" => "pe_opt_header.loader_flags", "op" => "!=", "val" => 0, "name" => "pe_loader_flags_non_zero", "rare" => true),

		array("path" => "pe_opt_header.num_data_directories", "op" => "<", "val" => 16, "name" => "pe_num_data_directories_under_16", "rare" => "64_pe"),
		array("path" => "pe_opt_header.num_data_directories", "op" => "==", "val" => 16, "name" => "pe_num_data_directories_equal_16"),

		// Any weird directory EXE/DLLs out there.
		array("path" => "pe_opt_header.num_data_directories", "op" => "==", "val" => 0, "name" => "pe_num_data_directories_zero", "rare" => true),
		array("path" => "pe_opt_header.num_data_directories", "op" => ">", "val" => 16, "name" => "pe_num_data_directories_over_16", "rare" => true),

		array("path" => "pe_data_dir.exports.rva", "op" => "!=", "val" => 0, "name" => "pe_data_dir_exports"),
		array("path" => "pe_data_dir.imports.rva", "op" => "!=", "val" => 0, "name" => "pe_data_dir_imports"),
		array("path" => "pe_data_dir.resources.rva", "op" => "!=", "val" => 0, "name" => "pe_data_dir_resources"),
		array("path" => "pe_data_dir.exceptions.rva", "op" => "!=", "val" => 0, "name" => "pe_data_dir_exceptions"),
		array("path" => "pe_data_dir.certificates.pos", "op" => "!=", "val" => 0, "name" => "pe_data_dir_certificates"),
		array("path" => "pe_data_dir.base_relocations.rva", "op" => "!=", "val" => 0, "name" => "pe_data_dir_base_relocations"),
		array("path" => "pe_data_dir.debug.rva", "op" => "!=", "val" => 0, "name" => "pe_data_dir_debug"),

		// Architecture data directory is supposed to always be zero since it is reserved.
		array("path" => "pe_data_dir.architecture.rva", "op" => "!=", "val" => 0, "name" => "pe_data_dir_architecture", "rare" => "64_pe"),

		array("path" => "pe_data_dir.global_ptr.rva", "op" => "!=", "val" => 0, "name" => "pe_data_dir_global_ptr", "rare" => "32_pe"),
		array("path" => "pe_data_dir.tls.rva", "op" => "!=", "val" => 0, "name" => "pe_data_dir_tls"),
		array("path" => "pe_data_dir.load_config.rva", "op" => "!=", "val" => 0, "name" => "pe_data_dir_load_config"),
		array("path" => "pe_data_dir.bound_imports.pos", "op" => "!=", "val" => 0, "name" => "pe_data_dir_bound_imports"),
		array("path" => "pe_data_dir.iat.rva", "op" => "!=", "val" => 0, "name" => "pe_data_dir_iat"),
		array("path" => "pe_data_dir.delay_imports.rva", "op" => "!=", "val" => 0, "name" => "pe_data_dir_delay_imports"),
		array("path" => "pe_data_dir.clr_runtime_header.rva", "op" => "!=", "val" => 0, "name" => "pe_data_dir_clr_runtime_header"),

		// Find overlapping sections using RVA calculations.  That is, RVA to RVA + max(raw data size, virtual size).
		array("path" => "pe_header.num_sections", "op" => "custom", "cmp" => "HasOverlappingSectionRVA", "name" => "pe_sections_overlapping_rva", "rare" => true),

		"pe_sections" => array(
			array("path" => "name", "op" => "==", "val" => "\x00\x00\x00\x00\x00\x00\x00\x00", "name" => "pe_sections_name_empty", "rare" => "64_pe"),
			array("path" => "name", "op" => "==", "val" => "UPX0\x00\x00\x00\x00", "name" => "pe_sections_name_UPX0", "rare" => "64_pe"),
			array("path" => "name", "op" => "==", "val" => "UPX1\x00\x00\x00\x00", "name" => "pe_sections_name_UPX1", "rare" => "64_pe", "break" => true),
			array("path" => "virtual_size", "op" => "==", "val" => 0, "name" => "pe_sections_virtual_size_zero", "rare" => "64_pe"),
			array("path" => "raw_data_size", "op" => "==", "val" => 0, "name" => "pe_sections_raw_data_size_zero"),
			array("path" => "raw_data_ptr", "op" => "==", "val" => 0, "name" => "pe_sections_raw_data_ptr_zero"),
			array("path" => "relocations_ptr", "op" => "!=", "val" => 0, "name" => "pe_sections_relocations_ptr_non_zero", "rare" => "64_pe"),
			array("path" => "line_nums_ptr", "op" => "!=", "val" => 0, "name" => "pe_sections_line_nums_ptr_non_zero", "rare" => "64_pe"),
			array("path" => "num_relocations", "op" => "!=", "val" => 0, "name" => "pe_sections_num_relocations_non_zero", "rare" => true),
			array("path" => "num_line_nums", "op" => "!=", "val" => 0, "name" => "pe_sections_num_line_nums_non_zero", "rare" => "64_pe"),

			array("path" => "flags", "op" => "==", "val" => 0x00000000, "name" => "pe_sections_flags_reserved_0x00000000"),
			array("path" => "flags", "op" => "&", "val" => 0x00000001, "name" => "pe_sections_flags_reserved_0x00000001", "rare" => true),
			array("path" => "flags", "op" => "&", "val" => 0x00000002, "name" => "pe_sections_flags_reserved_0x00000002", "rare" => "64_pe"),
			array("path" => "flags", "op" => "&", "val" => 0x00000004, "name" => "pe_sections_flags_reserved_0x00000004", "rare" => true),
			array("path" => "flags", "op" => "&", "val" => WinPEFile::IMAGE_SCN_TYPE_NO_PAD, "name" => "pe_sections_flags_type_no_pad", "rare" => true),
			array("path" => "flags", "op" => "&", "val" => 0x00000010, "name" => "pe_sections_flags_reserved_0x00000010", "rare" => true),
			array("path" => "flags", "op" => "&", "val" => WinPEFile::IMAGE_SCN_CNT_CODE, "name" => "pe_sections_flags_cnt_code"),
			array("path" => "flags", "op" => "&", "val" => WinPEFile::IMAGE_SCN_CNT_INITIALIZED_DATA, "name" => "pe_sections_flags_cnt_init_data"),
			array("path" => "flags", "op" => "&", "val" => WinPEFile::IMAGE_SCN_CNT_UNINITIALIZED_DATA, "name" => "pe_sections_flags_cnt_uninit_data"),
			array("path" => "flags", "op" => "&", "val" => WinPEFile::IMAGE_SCN_LNK_OTHER, "name" => "pe_sections_flags_reserved_lnk_other", "rare" => true),
			array("path" => "flags", "op" => "&", "val" => WinPEFile::IMAGE_SCN_LNK_INFO, "name" => "pe_sections_flags_lnk_info", "rare" => "64_pe"),
			array("path" => "flags", "op" => "&", "val" => 0x00000400, "name" => "pe_sections_flags_reserved_0x00000400", "rare" => true),
			array("path" => "flags", "op" => "&", "val" => WinPEFile::IMAGE_SCN_LNK_REMOVE, "name" => "pe_sections_flags_lnk_remove", "rare" => "64_pe"),
			array("path" => "flags", "op" => "&", "val" => WinPEFile::IMAGE_SCN_LNK_COMDAT, "name" => "pe_sections_flags_lnk_comdat", "rare" => true),
			array("path" => "flags", "op" => "&", "val" => 0x00002000, "name" => "pe_sections_flags_reserved_0x00002000", "rare" => true),
			array("path" => "flags", "op" => "&", "val" => WinPEFile::IMAGE_SCN_NO_DEFER_SPEC_EXC, "name" => "pe_sections_flags_no_defer_spec_exec", "rare" => true),
			array("path" => "flags", "op" => "&", "val" => WinPEFile::IMAGE_SCN_GPREL, "name" => "pe_sections_flags_gprel", "rare" => true),
			array("path" => "flags", "op" => "&", "val" => 0x00010000, "name" => "pe_sections_flags_reserved_0x00010000", "rare" => true),
			array("path" => "flags", "op" => "&", "val" => WinPEFile::IMAGE_SCN_MEM_PURGEABLE, "name" => "pe_sections_flags_mem_puregeable", "rare" => true),
			array("path" => "flags", "op" => "&", "val" => WinPEFile::IMAGE_SCN_MEM_16BIT, "name" => "pe_sections_flags_mem_16bit", "rare" => true),
			array("path" => "flags", "op" => "&", "val" => WinPEFile::IMAGE_SCN_MEM_LOCKED, "name" => "pe_sections_flags_mem_locked", "rare" => true),
			array("path" => "flags", "op" => "&", "val" => WinPEFile::IMAGE_SCN_MEM_PRELOAD, "name" => "pe_sections_flags_mem_preload", "rare" => true),

			array("path" => "flags", "op" => "&=", "mask" => 0x00F00000, "val" => WinPEFile::IMAGE_SCN_ALIGN_1BYTES, "name" => "pe_sections_flags_align_1"),
			array("path" => "flags", "op" => "&=", "mask" => 0x00F00000, "val" => WinPEFile::IMAGE_SCN_ALIGN_2BYTES, "name" => "pe_sections_flags_align_2", "rare" => true),
			array("path" => "flags", "op" => "&=", "mask" => 0x00F00000, "val" => WinPEFile::IMAGE_SCN_ALIGN_4BYTES, "name" => "pe_sections_flags_align_4"),
			array("path" => "flags", "op" => "&=", "mask" => 0x00F00000, "val" => WinPEFile::IMAGE_SCN_ALIGN_8BYTES, "name" => "pe_sections_flags_align_8"),
			array("path" => "flags", "op" => "&=", "mask" => 0x00F00000, "val" => WinPEFile::IMAGE_SCN_ALIGN_16BYTES, "name" => "pe_sections_flags_align_16"),
			array("path" => "flags", "op" => "&=", "mask" => 0x00F00000, "val" => WinPEFile::IMAGE_SCN_ALIGN_32BYTES, "name" => "pe_sections_flags_align_32"),
			array("path" => "flags", "op" => "&=", "mask" => 0x00F00000, "val" => WinPEFile::IMAGE_SCN_ALIGN_64BYTES, "name" => "pe_sections_flags_align_64"),
			array("path" => "flags", "op" => "&=", "mask" => 0x00F00000, "val" => WinPEFile::IMAGE_SCN_ALIGN_128BYTES, "name" => "pe_sections_flags_align_128", "rare" => true),
			array("path" => "flags", "op" => "&=", "mask" => 0x00F00000, "val" => WinPEFile::IMAGE_SCN_ALIGN_256BYTES, "name" => "pe_sections_flags_align_256"),
			array("path" => "flags", "op" => "&=", "mask" => 0x00F00000, "val" => WinPEFile::IMAGE_SCN_ALIGN_512BYTES, "name" => "pe_sections_flags_align_512", "rare" => true),
			array("path" => "flags", "op" => "&=", "mask" => 0x00F00000, "val" => WinPEFile::IMAGE_SCN_ALIGN_1024BYTES, "name" => "pe_sections_flags_align_1024", "rare" => true),
			array("path" => "flags", "op" => "&=", "mask" => 0x00F00000, "val" => WinPEFile::IMAGE_SCN_ALIGN_2048BYTES, "name" => "pe_sections_flags_align_2048", "rare" => true),
			array("path" => "flags", "op" => "&=", "mask" => 0x00F00000, "val" => WinPEFile::IMAGE_SCN_ALIGN_4096BYTES, "name" => "pe_sections_flags_align_4096", "rare" => "32_pe"),
			array("path" => "flags", "op" => "&=", "mask" => 0x00F00000, "val" => WinPEFile::IMAGE_SCN_ALIGN_8192BYTES, "name" => "pe_sections_flags_align_8192", "rare" => true),
			array("path" => "flags", "op" => "&=", "mask" => 0x00F00000, "val" => 0x00F00000, "name" => "pe_sections_flags_reserved_0x00F00000", "rare" => true),

			array("path" => "flags", "op" => "&", "val" => WinPEFile::IMAGE_SCN_LNK_NRELOC_OVFL, "name" => "pe_sections_flags_lnk_nreloc_ovfl", "rare" => true),

			array("path" => "flags", "op" => "&", "val" => WinPEFile::IMAGE_SCN_MEM_DISCARDABLE, "name" => "pe_sections_flags_mem_discardable"),
			array("path" => "flags", "op" => "&", "val" => WinPEFile::IMAGE_SCN_MEM_NOT_CACHED, "name" => "pe_sections_flags_mem_not_cached", "rare" => true),
			array("path" => "flags", "op" => "&", "val" => WinPEFile::IMAGE_SCN_MEM_NOT_PAGED, "name" => "pe_sections_flags_mem_not_paged"),
			array("path" => "flags", "op" => "&", "val" => WinPEFile::IMAGE_SCN_MEM_SHARED, "name" => "pe_sections_flags_mem_shared"),
			array("path" => "flags", "op" => "&", "val" => WinPEFile::IMAGE_SCN_MEM_EXECUTE, "name" => "pe_sections_flags_mem_execute"),
			array("path" => "flags", "op" => "&", "val" => WinPEFile::IMAGE_SCN_MEM_READ, "name" => "pe_sections_flags_mem_read"),
			array("path" => "flags", "op" => "&", "val" => (int)WinPEFile::IMAGE_SCN_MEM_WRITE, "name" => "pe_sections_flags_mem_write"),
		),

		// Supposedly always zero.
		array("path" => "pe_data_dir.exports.dir.flags", "op" => "!=", "val" => 0, "name" => "pe_data_dir_exports_flags_non_zero", "rare" => true),

		"pe_data_dir.exports.addresses" => array(
			array("path" => "type", "op" => "==", "val" => "forward", "name" => "pe_data_dir_exports_forward_rva"),
		),

		"pe_data_dir.imports.dir_entries" => array(
			array("path" => "forward_chain", "op" => "==", "val" => 0, "name" => "pe_data_dir_imports_dir_entries_forward_chain_zero"),
			array("path" => "forward_chain", "op" => "==", "val" => (int)0xFFFFFFFF, "name" => "pe_data_dir_imports_dir_entries_forward_chain_0xFFFFFFFF"),
			array("path" => "forward_chain", "op" => "!=", "val" => array(0, (int)0xFFFFFFFF), "name" => "pe_data_dir_imports_dir_entries_forward_chain_other"),

			"imports" => array(
				array("path" => "type", "op" => "==", "val" => "ord", "name" => "pe_data_dir_imports_dir_entries_imports_ordinal"),
				array("path" => "type", "op" => "==", "val" => "named", "name" => "pe_data_dir_imports_dir_entries_imports_named"),
			)
		),

		"pe_data_dir.resources.dir_entries" => array(
			// Rare/non-existent.  Monkeying with offsets allows for creating an infinite recursion loop to prevent flexible resource directory readers from reading the resource directory.
			array("path" => "loops", "op" => "!=", "val" => 0, "name" => "pe_data_dir_resources_dir_entries_loops_non_zero", "rare" => true),

			array("path" => "type|parent|id", "op" => "==", "val" => "node|0|0", "name" => "pe_data_dir_resources_dir_entries_rt_unknown_0", "rare" => true),
			array("path" => "type|parent|id", "op" => "==", "val" => "node|0|1", "name" => "pe_data_dir_resources_dir_entries_rt_cursor"),
			array("path" => "type|parent|id", "op" => "==", "val" => "node|0|2", "name" => "pe_data_dir_resources_dir_entries_rt_bitmap"),
			array("path" => "type|parent|id", "op" => "==", "val" => "node|0|3", "name" => "pe_data_dir_resources_dir_entries_rt_icon"),
			array("path" => "type|parent|id", "op" => "==", "val" => "node|0|4", "name" => "pe_data_dir_resources_dir_entries_rt_menu"),
			array("path" => "type|parent|id", "op" => "==", "val" => "node|0|5", "name" => "pe_data_dir_resources_dir_entries_rt_dialog"),
			array("path" => "type|parent|id", "op" => "==", "val" => "node|0|6", "name" => "pe_data_dir_resources_dir_entries_rt_string"),
			array("path" => "type|parent|id", "op" => "==", "val" => "node|0|7", "name" => "pe_data_dir_resources_dir_entries_rt_fontdir"),
			array("path" => "type|parent|id", "op" => "==", "val" => "node|0|8", "name" => "pe_data_dir_resources_dir_entries_rt_font"),
			array("path" => "type|parent|id", "op" => "==", "val" => "node|0|9", "name" => "pe_data_dir_resources_dir_entries_rt_accelerator"),
			array("path" => "type|parent|id", "op" => "==", "val" => "node|0|10", "name" => "pe_data_dir_resources_dir_entries_rt_rcdata"),
			array("path" => "type|parent|id", "op" => "==", "val" => "node|0|11", "name" => "pe_data_dir_resources_dir_entries_rt_messagetable"),
			array("path" => "type|parent|id", "op" => "==", "val" => "node|0|12", "name" => "pe_data_dir_resources_dir_entries_rt_group_cursor"),
			array("path" => "type|parent|id", "op" => "==", "val" => "node|0|13", "name" => "pe_data_dir_resources_dir_entries_rt_unknown_13", "rare" => true),
			array("path" => "type|parent|id", "op" => "==", "val" => "node|0|14", "name" => "pe_data_dir_resources_dir_entries_rt_group_icon"),
			array("path" => "type|parent|id", "op" => "==", "val" => "node|0|15", "name" => "pe_data_dir_resources_dir_entries_rt_unknown_15", "rare" => true),
			array("path" => "type|parent|id", "op" => "==", "val" => "node|0|16", "name" => "pe_data_dir_resources_dir_entries_rt_version"),
			array("path" => "type|parent|id", "op" => "==", "val" => "node|0|17", "name" => "pe_data_dir_resources_dir_entries_rt_dlginclude", "rare" => true),
			array("path" => "type|parent|id", "op" => "==", "val" => "node|0|18", "name" => "pe_data_dir_resources_dir_entries_rt_unknown_18", "rare" => true),
			array("path" => "type|parent|id", "op" => "==", "val" => "node|0|19", "name" => "pe_data_dir_resources_dir_entries_rt_plugplay", "rare" => true),
			array("path" => "type|parent|id", "op" => "==", "val" => "node|0|20", "name" => "pe_data_dir_resources_dir_entries_rt_vxd"),
			array("path" => "type|parent|id", "op" => "==", "val" => "node|0|21", "name" => "pe_data_dir_resources_dir_entries_rt_anicursor"),
			array("path" => "type|parent|id", "op" => "==", "val" => "node|0|22", "name" => "pe_data_dir_resources_dir_entries_rt_aniicon"),
			array("path" => "type|parent|id", "op" => "==", "val" => "node|0|23", "name" => "pe_data_dir_resources_dir_entries_rt_html"),
			array("path" => "type|parent|id", "op" => "==", "val" => "node|0|24", "name" => "pe_data_dir_resources_dir_entries_rt_manifest"),
			array("path" => "type|parent|id", "op" => "==", "val" => "node|0|25", "name" => "pe_data_dir_resources_dir_entries_rt_unknown_25", "rare" => true),

			// Find a resource RVA that resolves outside of the resource directory.
			array("path" => "rva", "op" => "custom", "cmp" => "IsRVAOutsideResourceDir", "name" => "pe_data_dir_resources_external_rva"),
		),

		// Find data that follows a Certificates table.
		array("path" => "pe_data_dir.certificates.pos", "op" => "custom", "cmp" => "HasDataAfterCertificatesTable", "name" => "pe_data_dir_certificates_not_last", "rare" => true),

		"pe_data_dir.certificates.certs" => array(
			array("path" => "revision", "op" => "==", "val" => 0, "name" => "pe_data_dir_certificates_rev_0_0", "rare" => "64_pe"),
			array("path" => "revision", "op" => "==", "val" => WinPEFile::WIN_CERT_REVISION_1_0, "name" => "pe_data_dir_certificates_rev_1_0", "rare" => true),
			array("path" => "revision", "op" => "==", "val" => WinPEFile::WIN_CERT_REVISION_2_0, "name" => "pe_data_dir_certificates_rev_2_0"),
			array("path" => "revision", "op" => "!=", "val" => array(0, WinPEFile::WIN_CERT_REVISION_1_0, WinPEFile::WIN_CERT_REVISION_2_0), "name" => "pe_data_dir_certificates_rev_unknown", "rare" => true),

			array("path" => "cert_type", "op" => "==", "val" => WinPEFile::WIN_CERT_TYPE_X509, "name" => "pe_data_dir_certificates_type_x509", "rare" => true),
			array("path" => "cert_type", "op" => "==", "val" => WinPEFile::WIN_CERT_TYPE_PKCS_SIGNED_DATA, "name" => "pe_data_dir_certificates_type_pkcs7"),
			array("path" => "cert_type", "op" => "==", "val" => 0x0003, "name" => "pe_data_dir_certificates_type_reserved_0x0003", "rare" => true),
			array("path" => "cert_type", "op" => "==", "val" => WinPEFile::WIN_CERT_TYPE_TS_STACK_SIGNED, "name" => "pe_data_dir_certificates_type_ts", "rare" => true),
			array("path" => "cert_type", "op" => ">=", "val" => 5, "name" => "pe_data_dir_certificates_type_unknown_5_plus", "rare" => true),
		),

		"pe_data_dir.base_relocations.blocks" => array(
			"offsets" => array(
				array("path" => "type", "op" => "==", "val" => WinPEFile::IMAGE_REL_BASED_ABSOLUTE, "name" => "pe_data_dir_base_relocations_offset_absolute"),
				array("path" => "type", "op" => "==", "val" => WinPEFile::IMAGE_REL_BASED_HIGH, "name" => "pe_data_dir_base_relocations_offset_high", "rare" => "32_pe"),
				array("path" => "type", "op" => "==", "val" => WinPEFile::IMAGE_REL_BASED_LOW, "name" => "pe_data_dir_base_relocations_offset_low", "rare" => "32_pe"),
				array("path" => "type", "op" => "==", "val" => WinPEFile::IMAGE_REL_BASED_HIGHLOW, "name" => "pe_data_dir_base_relocations_offset_highlow"),
				array("path" => "type", "op" => "==", "val" => WinPEFile::IMAGE_REL_BASED_HIGHADJ, "name" => "pe_data_dir_base_relocations_offset_highadj", "rare" => "32_pe"),
				array("path" => "type", "op" => "==", "val" => WinPEFile::IMAGE_REL_BASED_MIPS_JMPADDR, "name" => "pe_data_dir_base_relocations_offset_5_mips_jmpaddr", "rare" => "32_pe"),
				array("path" => "type", "op" => "==", "val" => 6, "name" => "pe_data_dir_base_relocations_offset_reserved_6", "rare" => "32_pe"),
				array("path" => "type", "op" => "==", "val" => WinPEFile::IMAGE_REL_BASED_THUMB_MOV32, "name" => "pe_data_dir_base_relocations_offset_7_thumb_mov32"),
				array("path" => "type", "op" => "==", "val" => WinPEFile::IMAGE_REL_BASED_RISCV_LOW12S, "name" => "pe_data_dir_base_relocations_offset_8_riscv_low12s", "rare" => "32_pe"),
				array("path" => "type", "op" => "==", "val" => WinPEFile::IMAGE_REL_BASED_IA64_IMM64, "name" => "pe_data_dir_base_relocations_offset_9_ia64_imm64", "rare" => "32_pe"),
				array("path" => "type", "op" => "==", "val" => WinPEFile::IMAGE_REL_BASED_DIR64, "name" => "pe_data_dir_base_relocations_offset_dir64", "rare" => "32_pe"),
				array("path" => "type", "op" => "==", "val" => WinPEFile::IMAGE_REL_BASED_HIGH3ADJ, "name" => "pe_data_dir_base_relocations_offset_high3adj", "rare" => "32_pe"),
				array("path" => "type", "op" => "==", "val" => 12, "name" => "pe_data_dir_base_relocations_offset_unknown_12", "rare" => "32_pe"),
				array("path" => "type", "op" => "==", "val" => 13, "name" => "pe_data_dir_base_relocations_offset_unknown_13", "rare" => "32_pe"),
				array("path" => "type", "op" => "==", "val" => 14, "name" => "pe_data_dir_base_relocations_offset_unknown_14", "rare" => "32_pe"),
				array("path" => "type", "op" => "==", "val" => 15, "name" => "pe_data_dir_base_relocations_offset_unknown_15", "rare" => "32_pe"),
			)
		),

		"pe_data_dir.debug.dir_entries" => array(
			array("path" => "flags", "op" => "!=", "val" => 0, "name" => "pe_data_dir_debug_flags_non_zero", "rare" => true),

			array("path" => "type", "op" => "==", "val" => WinPEFile::IMAGE_DEBUG_TYPE_UNKNOWN, "name" => "pe_data_dir_debug_type_unknown_0", "rare" => "64_pe"),
			array("path" => "type", "op" => "==", "val" => WinPEFile::IMAGE_DEBUG_TYPE_COFF, "name" => "pe_data_dir_debug_type_coff", "rare" => "64_pe"),
			array("path" => "type", "op" => "==", "val" => WinPEFile::IMAGE_DEBUG_TYPE_CODEVIEW, "name" => "pe_data_dir_debug_type_codeview"),
			array("path" => "type", "op" => "==", "val" => WinPEFile::IMAGE_DEBUG_TYPE_FPO, "name" => "pe_data_dir_debug_type_fpo", "rare" => "64_pe"),
			array("path" => "type", "op" => "==", "val" => WinPEFile::IMAGE_DEBUG_TYPE_MISC, "name" => "pe_data_dir_debug_type_misc", "rare" => "64_pe"),
			array("path" => "type", "op" => "==", "val" => WinPEFile::IMAGE_DEBUG_TYPE_EXCEPTION, "name" => "pe_data_dir_debug_type_exception", "rare" => true),
			array("path" => "type", "op" => "==", "val" => WinPEFile::IMAGE_DEBUG_TYPE_FIXUP, "name" => "pe_data_dir_debug_type_fixup", "rare" => true),
			array("path" => "type", "op" => "==", "val" => WinPEFile::IMAGE_DEBUG_TYPE_OMAP_TO_SRC, "name" => "pe_data_dir_debug_type_omap_to_src", "rare" => true),
			array("path" => "type", "op" => "==", "val" => WinPEFile::IMAGE_DEBUG_TYPE_OMAP_FROM_SRC, "name" => "pe_data_dir_debug_type_omap_from_src", "rare" => true),
			array("path" => "type", "op" => "==", "val" => WinPEFile::IMAGE_DEBUG_TYPE_BORLAND, "name" => "pe_data_dir_debug_type_borland", "rare" => true),
			array("path" => "type", "op" => "==", "val" => 10, "name" => "pe_data_dir_debug_type_reserved_10"),
			array("path" => "type", "op" => "==", "val" => WinPEFile::IMAGE_DEBUG_TYPE_CLSID, "name" => "pe_data_dir_debug_type_clsid", "rare" => true),
			array("path" => "type", "op" => "==", "val" => 12, "name" => "pe_data_dir_debug_type_unknown_12"),
			array("path" => "type", "op" => "==", "val" => 13, "name" => "pe_data_dir_debug_type_unknown_13"),
			array("path" => "type", "op" => "==", "val" => 14, "name" => "pe_data_dir_debug_type_unknown_14"),
			array("path" => "type", "op" => "==", "val" => 15, "name" => "pe_data_dir_debug_type_unknown_15", "rare" => true),
			array("path" => "type", "op" => "==", "val" => WinPEFile::IMAGE_DEBUG_TYPE_REPRO, "name" => "pe_data_dir_debug_type_repro"),
			array("path" => "type", "op" => "==", "val" => 17, "name" => "pe_data_dir_debug_type_unknown_17", "rare" => "64_pe"),
			array("path" => "type", "op" => "==", "val" => 18, "name" => "pe_data_dir_debug_type_unknown_18", "rare" => true),
			array("path" => "type", "op" => "==", "val" => 19, "name" => "pe_data_dir_debug_type_unknown_19"),
			array("path" => "type", "op" => "==", "val" => WinPEFile::IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS, "name" => "pe_data_dir_debug_type_ex_dll_characteristics", "rare" => true),
			array("path" => "type", "op" => ">=", "val" => 21, "name" => "pe_data_dir_debug_type_unknown_21_plus", "rare" => true),
		),

		"pe_data_dir.bound_imports.dir_entries" => array(
			array("path" => "name", "op" => "==", "val" => "", "name" => "pe_data_dir_bound_imports_name_empty", "rare" => true),
			array("path" => "num_forward_refs", "op" => "==", "val" => 0, "name" => "pe_data_dir_bound_imports_num_forward_refs_zero"),
			array("path" => "num_forward_refs", "op" => "!=", "val" => 0, "name" => "pe_data_dir_bound_imports_num_forward_refs_non_zero"),
		),

		"pe_data_dir.delay_imports.dir_entries" => array(
			array("path" => "flags", "op" => "==", "val" => 0, "name" => "pe_data_dir_delay_imports_dir_entries_flags_zero", "rare" => "64_pe"),
			array("path" => "flags", "op" => "!=", "val" => 0, "name" => "pe_data_dir_delay_imports_dir_entries_flags_non_zero"),
			array("path" => "bound_iat_rva", "op" => "==", "val" => 0, "name" => "pe_data_dir_delay_imports_dir_entries_bound_iat_zero"),
			array("path" => "bound_iat_rva", "op" => "!=", "val" => 0, "name" => "pe_data_dir_delay_imports_dir_entries_bound_iat_non_zero"),
			array("path" => "unload_iat_rva", "op" => "==", "val" => 0, "name" => "pe_data_dir_delay_imports_dir_entries_unload_iat_zero"),
			array("path" => "unload_iat_rva", "op" => "!=", "val" => 0, "name" => "pe_data_dir_delay_imports_dir_entries_unload_iat_non_zero"),

			"imports" => array(
				array("path" => "type", "op" => "==", "val" => "ord", "name" => "pe_data_dir_delay_imports_dir_entries_imports_ordinal"),
				array("path" => "type", "op" => "==", "val" => "bad_rva", "name" => "pe_data_dir_delay_imports_dir_entries_imports_bad_rva", "rare" => true),
				array("path" => "type", "op" => "==", "val" => "bad_name", "name" => "pe_data_dir_delay_imports_dir_entries_imports_bad_name", "rare" => true),
				array("path" => "type", "op" => "==", "val" => "named", "name" => "pe_data_dir_delay_imports_dir_entries_imports_named"),
			)
		),
	);
?>