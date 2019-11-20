WinPEFile Class:  'support/win_pe_file.php'
===========================================

The self-contained WinPEFile class correctly validates, parses, creates, and modifies files stored in the Portable Executable (PE/COFF) file format in a pure PHP userland implementation.

This class tracks structural information only and does not support streaming content.  When modifying files, the data blob that the structural information is associated with will have to be tracked separately.

32-bit PHP is supported but not recommended.  Casting some of the larger constants to integers (e.g. `(int)WinPEFile::IMAGE_SCN_MEM_WRITE`) will be necessary in applications in order to properly support both 32-bit and 64-bit PHP.

Note that there are MANY constants in the WinPEFile class not shown in the documentation.

WinPEFile::$defaultDOSstub
--------------------------

Access:  public static

This static string contains a default MS-DOS stub that outputs "This program cannot be run in DOS mode." and does not contain a [Rich header](https://www.ntcore.com/files/richsign.htm).

WinPEFile::$machine_types
-------------------------

Access:  public static

This static array attempts to map a machine type integer to a human-readable string.

WinPEFile::$opt_header_signatures
---------------------------------

Access:  public static

This static array attempts to map the PE optional header signature to a human-readable string.

WinPEFile::$image_subsystems
----------------------------

Access:  public static

This static array attempts to map an image's subsystem to a human-readable string.  Values 2 (Windows GUI) and 3 (Windows Console) are the most common.

WinPEFile::$resource_types
--------------------------

Access:  public static

This static array attempts to map a resource table type to a human-readable string.

WinPEFile::$ne_target_oses
--------------------------

Access:  public static

This static array attempts to map a Win16 NE target OS to a human-readable string.

WinPEFile::GetDefaultDOSHeader()
--------------------------------

Access:  public static

Parameters:  None.

Returns:  An array containing the default DOS header.

This static function is used when creating a brand new PE file or when attempting to expand a PE header.  Returns hardcoded default values for the DOS header.

WinPEFile::GetDefaultPEHeader($optheadersig = WinPEFile::OPT_HEADER_SIGNATURE_PE32)
-----------------------------------------------------------------------------------

Access:  public static

Parameters:

* $optheadersig - An integer containing a valid PE optional header signature (Default is WinPEFile::OPT_HEADER_SIGNATURE_PE32).

Returns:  An array containing a default PE header.

This static function is used when creating a brand new PE file.  Returns hardcoded default values for the PE header based on whether or not it is PE32+.

WinPEFile::GetDefaultPEOptHeader($optheadersig = WinPEFile::OPT_HEADER_SIGNATURE_PE32)
--------------------------------------------------------------------------------------

Access:  public static

Parameters:

* $optheadersig - An integer containing a valid PE optional header signature (Default is WinPEFile::OPT_HEADER_SIGNATURE_PE32).

Returns:  An array containing a default PE header.

This static function is used when creating a brand new PE file.  Returns hardcoded default values for the PE header based on whether or not it is PE32+.

WinPEFile::InitDataDirectory()
------------------------------

Access:  public static

Parameters:  None.

Returns:  An array containing initialized PE optional header data directories.

This static function is used when parsing incoming data or when creating a brand new PE file.  Returns an initialized data directory mapping for filling out later.

WinPEFile::InitPE($optheadersig = WinPEFile::OPT_HEADER_SIGNATURE_PE32)
-----------------------------------------------------------------------

Access:  public static

Parameters:

* $optheadersig - An integer containing a valid PE optional header signature (Default is WinPEFile::OPT_HEADER_SIGNATURE_PE32).

Returns:  Nothing.

This static function is used when creating a brand new PE file.  Initializes all DOS and PE data structures for the class to their defaults.

WinPEFile::ValidateFile($filename, $readpesig = true)
-----------------------------------------------------

Access:  public static

Parameters:

* $filename - A string containing the filename to validate as a PE file.
* $readpesig - A boolean indicating whether or not to check the PE header signature (Default is true).

Returns:  A standard array of information.

This static function briefly analyzes a file and determines whether or not it is a valid PE file.  Using this function is recommended to avoid loading invalid files into RAM.  Only checks for MZ and PE file signatures.

WinPEFile::Parse($data, $options = array())
-------------------------------------------

Access:  public

Parameters:

* $data - A string containing the data of a PE file to extract structure information and data from.
* $options - An array of options (Default is array()).

Returns:  A standard array of information.

This function attempts to extract PE file format structure information, including all data directories, from the input data blob.

The $options array accepts these options:

* pe_section_data - A boolean indicating whether or not to extract data for each section from the source data (Default is false).  When true, the class instance will use significantly more RAM.
* pe_directory_data - A boolean indicating whether or not to extract directory data (Default is true).  When true, the class instance will use more RAM for tracking the additional information.
* pe_directories - A comma-separated string containing one or more of 'all', 'exports', 'imports', 'resources', 'exceptions', 'certificates', 'base_relocations', 'debug', 'tls', 'load_config', 'bound_imports', 'iat', 'delay_imports', and/or 'clr_runtime_header' (Default is "all").

Example usage:

```php
	require_once "support/win_pe_file.php";

	$srcfile = "peview.exe";

	// Validation is optional but saves loading the entire file into RAM if the file isn't valid.
	$result = WinPEFile::ValidateFile($srcfile);
	if (!$result["success"])
	{
		var_dump($result);

		exit();
	}

	// Parse the file.
	$data = file_get_contents($srcfile);

	$options = array();

	$winpe = new WinPEFile();
	$result = $winpe->Parse($data, $options);
	if (!$result["success"])
	{
		var_dump($result);

		exit();
	}

	var_dump($winpe->dos_header);
	var_dump($winpe->pe_header);
	var_dump($winpe->pe_opt_header);
?>
```

WinPEFile::InitResourcesDir()
-----------------------------

Access:  public

Parameters:  None.

Returns:  Nothing.

This function initializes a resource directory root entry if a resources directory does not exist.  An initialized or successfully parsed PE file is expected.  Prefer calling `CreateResourceLangNode()`.

WinPEFile::CreateResourceTypeNode($type)
----------------------------------------

Access:  public

Parameters:

* $type - An integer or a string containing the type of resource to create idempotently.

Returns:  An integer containing the node number of the associated type.

This function either locates and returns an existing node or creates a new node for the resource type.  An initialized or successfully parsed PE file is expected.  Prefer calling `CreateResourceLangNode()`.

The $type may also be one of the following resource type constants:

* WinPEFile::RT_CURSOR - Hardware-dependent cursor.
* WinPEFile::RT_BITMAP - Bitmap.
* WinPEFile::RT_ICON - Hardware-dependent icon.
* WinPEFile::RT_MENU - Menu.
* WinPEFile::RT_DIALOG - Dialog box.
* WinPEFile::RT_STRING - String table entry.
* WinPEFile::RT_FONTDIR - Font directory.
* WinPEFile::RT_FONT - Font.
* WinPEFile::RT_ACCELERATOR - Accelerator table.  Keyboard shortcuts for menu items.
* WinPEFile::RT_RCDATA - Application-defined raw data.
* WinPEFile::RT_MESSAGETABLE - Message table.
* WinPEFile::RT_GROUP_CURSOR - Hardware-independent cursor.
* WinPEFile::RT_GROUP_ICON - Hardware-independent icon.
* WinPEFile::RT_VERSION - Version information.
* WinPEFile::RT_DLGINCLUDE - Resource editing tool-specific string.
* WinPEFile::RT_PLUGPLAY - Plug and Play.
* WinPEFile::RT_VXD - Virtual hardware driver.
* WinPEFile::RT_ANICURSOR - Animated cursor.
* WinPEFile::RT_ANIICON - Animated icon.
* WinPEFile::RT_HTML - HTML.
* WinPEFile::RT_MANIFEST - Side-by-Side (SxS) Assembly Manifest.

WinPEFile::CreateResourceIDNameNode($type, $idname)
---------------------------------------------------

Access:  public

Parameters:

* $type - An integer or a string containing the type of resource to create idempotently.
* $idname - An integer, or a string containing the resource ID or name to create idempotently OR a boolean of true.

Returns:  An integer containing the node number of the associated ID/name.

This function either locates and returns an existing node or creates a new node for the resource ID or name.  An initialized or successfully parsed PE file is expected.  Prefer calling `CreateResourceLangNode()`.

See `CreateResourceTypeNode()` for a list of constants for $type.

When $idname is true, the next available unused integer for the type is selected for the new node.

WinPEFile::CreateResourceLangNode($type, $idname, $lang, $data = false)
-----------------------------------------------------------------------

Access:  public

Parameters:

* $type - An integer or a string containing the type of resource to create idempotently.
* $idname - An integer, or a string containing the resource ID or name to create idempotently OR a boolean of true.
* $lang - An integer containing the language of the resource data to create idempotently OR a boolean of true to use the most popular language code.
* $data - A boolean of false or a string containing the resource data to assign (Default is false).

Returns:  An integer containing the node number of the associated language and leaf data.

This function either locates and returns an existing node or creates a new node for the resource language and leaf data.  An initialized or successfully parsed PE file is expected.  This function will initialize the resource data directory, create or locate the matching resource type, create or locate the matching resource ID/name, and create or locate the matching language as needed.

See `CreateResourceTypeNode()` for a list of constants for $type.

When $idname is true, the next available unused integer for the type is selected for the new node.

When $lang is true, the resource directory is scanned to determine which language is most popular within the PE file and that becomes the language code to use.

Example usage:

```php
<?php
	require_once "support/win_pe_file.php";

	$srcfile = "peview.exe";
	$manifestfile = "test_manifest.config";

	// Validation is optional but saves loading the entire file into RAM if the file isn't valid.
	$result = WinPEFile::ValidateFile($srcfile);
	if (!$result["success"])
	{
		var_dump($result);

		exit();
	}

	// Parse the file.
	$data = file_get_contents($srcfile);

	$options = array();

	$winpe = new WinPEFile();
	$result = $winpe->Parse($data, $options);
	if (!$result["success"])
	{
		var_dump($result);

		exit();
	}

	$manifestdata = file_get_contents($manifestfile);

	// Create or replace the application manifest.
	$result = $winpe->FindResource(WinPEFile::RT_MANIFEST, true, true);
	if ($result === false)  $winpe->CreateResourceLangNode(WinPEFile::RT_MANIFEST, 1, true, $manifestdata);
	else  $winpe->OverwriteResourceData($data, $result["num"], $manifestdata);

	// Save the resources back into the data.
	$result = $winpe->SavePEResourcesDirectory($data);
	if (!$result["success"])  CLI::DisplayResult($result);

	// Write out the modified executable.
	file_put_contents("peview_modified.exe", $data);
?>
```

WinPEFile::GetResource($num)
----------------------------

Access:  public

Parameters:

* $num - An integer containing the resource to return.

Returns:  An array containing the resource node on success, false otherwise.

This function accesses the `pe_data_dir["resources"]["dir_entries"]` array directly and returns the associated array.

WinPEFile::FindResources($type, $idname, $lang, $limit = false)
---------------------------------------------------------------

Access:  public

Parameters:

* $type - An integer or a string containing the type of resource to find OR a boolean of true to match all types.
* $idname - An integer or a string containing the resource ID or name OR a boolean of true to match all IDs and names.
* $lang - An integer containing the language of the resource data OR a boolean of true to match all language codes.
* $limit - A boolean of false for all matching resources or an integer that contains the maximum number of matching resources to return (Defualt is false).

Returns:  An array of matching resource directory resources.

This function finds all resources that match the type, ID/name, and language code up to the specified limit.

WinPEFile::FindResource($type, $idname, $lang)
----------------------------------------------

Access:  public

Parameters:

* $type - An integer or a string containing the type of resource to find OR a boolean of true to match all types.
* $idname - An integer or a string containing the resource ID or name OR a boolean of true to match all IDs and names.
* $lang - An integer containing the language of the resource data OR a boolean of true to match all language codes.

Returns:  A single resource array of the first matching resource directory resource or a boolean of false if nothing matched.

This function finds a single resource that matches the type, ID/name, and language code.

WinPEFile::DeleteResource($num)
-------------------------------

Access:  public

Parameters:

* $num - An integer containing the resource to delete.

Returns:  Nothing.

This function detaches and deletes a resource and deletes parent nodes to the root if the parent node's children entries array is empty.

WinPEFile::DeleteResources($type, $idname, $lang, $limit = false)
-----------------------------------------------------------------

Access:  public

Parameters:

* $type - An integer or a string containing the type of resource to find OR a boolean of true to match all types.
* $idname - An integer or a string containing the resource ID or name OR a boolean of true to match all IDs and names.
* $lang - An integer containing the language of the resource data OR a boolean of true to match all language codes.
* $limit - A boolean of false for all matching resources or an integer that contains the maximum number of matching resources to return (Defualt is false).

Returns:  Nothing.

This function deletes resources that match the type, ID/name, and language code up to the specified limit.

WinPEFile::GetExclusiveResourceRVARefAndZero(&$data, $num)
----------------------------------------------------------

Access:  public

Parameters:

* $data - A string containing the data passed to `Parse()`.
* $num - An integer containing the resource to zero.

Returns:  An array containing the position and size on success, false otherwise.

This function gets or makes the specified resource RVA-exclusive.  While unlikely to actually exist, it is theoretically possible for PE resource directory resources to be shared via RVA reuse.  This function prevents resource sharing, forces duplication of shared resources, and zeroes out the data area of the specified resource.

This function is usually called via `OverwriteResourceData()` instead of calling it directly.

WinPEFile::OverwriteResourceData(&$data, $num, $newdata)
--------------------------------------------------------

Access:  public

Parameters:

* $data - A string containing the data passed to `Parse()`.
* $num - An integer containing the resource to overwrite.
* $newdata - A string containing the replacement data for the resource.

Returns:  A boolean of true on success, false otherwise.

This function overwrites the specified resource and either replaces the new data inline OR sets it up to be applied when saving the modified resource directory later.

See `CreateResourceLangNode()` for example usage.

WinPEFile::UpdateChecksum(&$data, $zeroall = false)
---------------------------------------------------

Access:  public

Parameters:

* $data - A string containing the data passed to Parse()`.
* $zeroall - A boolean indicating whether or not to make all checksums zero (Default is false).

Returns:  Nothing.

This function calculates and updates the appropriate checksum for DOS, NE, or the PE header in the data.  The DOS header is always zeroed for NE and PE.

WinPEFile::SaveHeaders(&$data)
------------------------------

Access:  public

Parameters:

* $data - A string containing the data passed to `Parse()`.

Returns:  Nothing.

This function saves all of the headers, including PE section headers, in the data.

WinPEFile::GetRealImageHeadersSize($sections = true)
----------------------------------------------------

Access:  public

Parameters:

* $sections - A boolean indicating whether or not to include section size in the calculation (Default is true).

Returns:  An integer containing the real image header size minus padding.

This function adds the PE header offset + 24 bytes for the PE header (including PE signature) + the size of the PE optional header + the size of the sections (40 bytes per section, if $sections is true).  Assumes a PE file.

WinPEFile::AlignValue($val, $alignment)
---------------------------------------

Access:  public static

Parameters:

* $val - An integer containing the value to align.
* $alignment - A positive integer containing the alignment width.

Returns:  An aligned integer value.

This static function aligns (rounds up) values to the alignment boundary.  Much of the PE file format requires data alignment to 32-bit (DWORD) boundaries.

Example usage:

```php
<?php
	require_once "support/win_pe_file.php";

	for ($x = 0; $x < 9; $x++)
	{
		echo WinPEFile::AlignValue($x, 4) . "\n";
	}
?>
```

WinPEFile::SectionAlignValue($val)
----------------------------------

Access:  public

Parameters:

* $val - An integer containing the value to align to the section alignment.

Returns:  A section-aligned integer value.

This function aligns (rounds up) values to the PE optional header section alignment boundary.

WinPEFile::FileAlignValue($val)
-------------------------------

Access:  public

Parameters:

* $val - An integer containing the value to align to the file alignment.

Returns:  A section-aligned integer value.

This function aligns (rounds up) values to the PE optional header file alignment boundary.

WinPEFile::PrepareForNewPESection(&$data, $numbytes = 40)
---------------------------------------------------------

Access:  public

Parameters:

* $data - A string containing the data passed to `Parse()`.
* $numbytes - An integer containing the number of bytes in the header to reserve (Default is 40, the size of one PE section header).

Returns:  A standard array of information.

This function alters the various headers to create sufficient space for the requested number of bytes up to the section alignment.  The function will fail if there isn't sufficient space available.

In the event that the header is expanded, this function will also replace the DOS stub with the WinPEFile default DOS stub if it is smaller and clear anything unnecessary located in the PE header space (e.g. bound imports, debug directory data, and certificate data).

This function is also called by the `ExpandPEDataDirectories()` function in rare instances in order to free up sufficient space when the number of data directories in the PE optional header is less than the default (i.e. 16).

WinPEFile::UpdatePEOptHeaderSizes()
-----------------------------------

Access:  public

Parameters:  None.

Returns:  A standard array of information.

This function recalculates the PE optione header code size, initialized data size, uninitialized data size, and image size.

WinPEFile::CreateNewPESection(&$data, $name, $numbytes, $flags)
---------------------------------------------------------------

Access:  public

Parameters:

* $data - A string containing the data passed to `Parse()`.
* $numbytes - An integer containing the number of bytes to initially reserve (0 is recommended).
* $flags - An integer containing PE section flags for the new section.

Returns:  A standard array of information.

This function creates a new PE section at the end of the file data and returns the section number and section information.  The recommended approach is to call this function first with zero `$numbytes` and then call `ExpandLastPESection()` whenever more storage space is needed and assume any existing bytes of data within a section are opaque, unknown data.  The WinPEFile and WinPEUtils classes both utilize the recommended approach.

The $flags can be a combination of the following PE section flags:

* WinPEFile::IMAGE_SCN_CNT_CODE - Contains executable code.
* WinPEFile::IMAGE_SCN_CNT_INITIALIZED_DATA - Contains initialized data.
* WinPEFile::IMAGE_SCN_CNT_UNINITIALIZED_DATA - Contains uninitialized data.
* WinPEFile::IMAGE_SCN_NO_DEFER_SPEC_EXC - Reset speculative exceptions handling bits in the TLB entries.
* WinPEFile::IMAGE_SCN_GPREL - Contains data referenced through the global pointer.
* WinPEFile::IMAGE_SCN_LNK_NRELOC_OVFL - Contains extended relocations due to overflow.
* WinPEFile::IMAGE_SCN_MEM_DISCARDABLE - Can be discarded as needed.
* WinPEFile::IMAGE_SCN_MEM_NOT_CACHED - Cannot be cached.
* WinPEFile::IMAGE_SCN_MEM_NOT_PAGED - Cannot be paged.
* WinPEFile::IMAGE_SCN_MEM_SHARED - Can be shared in memory.
* WinPEFile::IMAGE_SCN_MEM_EXECUTE - Can be executed as code.
* WinPEFile::IMAGE_SCN_MEM_READ - Can be read.
* WinPEFile::IMAGE_SCN_MEM_WRITE - Can be written to.  Note that this constant is a float on 32-bit PHP and should be cast to integer when used.

There are other flags in WinPEFile but most of those are labeled as being for object files only (e.g. .obj/.lib) not for EXEs and DLLs even though such executable images DO exist.

WinPEFile::GetLastPESectionIfAtEnd(&$data, $checkflags = false)
---------------------------------------------------------------

Access:  public

Paramaters:

* $data - A string containing the data passed to `Parse()`.
* $checkflags - An integer containing the exact PE section flags to check.

Returns:  An integer containing the last PE section number if the last section passes all tests, a boolean of false otherwise.

This function returns the number of the last PE section if the last section meets a number of criteria:

* The $checkflags is identical to the section flags if $checkflags isn't false.
* The file is aligned properly.
* The last section is at the very end of the data.
* The virtual size of the last section is not greater than the raw data size.
* There are no other PE sections with larger RVAs than the last section.

This function is usually used to decide between using an existing section and creating a new one at the end of a file with `CreateNewPESection()`.

WinPEFile::ExpandLastPESection(&$data, $numbytes)
-------------------------------------------------

Access:  public

Paramaters:

* $data - A string containing the data passed to `Parse()`.
* $numbytes - An integer containing the number of additional bytes to reserve.

Returns:  A standard array of information.

This function expands the last PE section by the specified number of bytes, appends file aligned bytes to the data, and updates and saves headers.  Will fail if `GetLastPESectionIfAtEnd()` returns false.

WinPEFile::DeletePESection(&$data, $num)
----------------------------------------

Access:  public

Parameters:

* $data - A string containing the data passed to `Parse()`.
* $num - An integer containing the section number to delete.

Returns:  A standard array of information.

This function deletes a section, either zeroes out the data OR shrinks the data if it was the last section, and updates and saves headers.

WinPEFile::ExpandPEDataDirectories(&$data, $newnum = 16)
--------------------------------------------------------

Access:  public

Parameters:

* $data - A string containing the data passed to `Parse()`.
* $newnum - An integer containing the total number of data directories (Default is 16).

Returns:  A standard array of information.

This function expands the number of data directories in the PE optional header.

WinPEFile::Internal_SortPEResourceDirEntries($num, $num2)
---------------------------------------------------------

Access:  _internal_

Parameters:

* $num - An integer containing the left directory resource number.
* $num2 - An integer containing the right directory resource number.

Returns:  -1, 0, or 1 if the left directory entry ID or name is less than, equal to, or greater than the right directory entry ID or name.

This internal function sorts PE resource directory entries for `SavePEResourceDirectory()`.

WinPEFile::SavePEResourcesDirectory(&$data)
-------------------------------------------

Access:  public

Parameters:

* $data - A string containing the data passed to `Parse()`.

Returns:  A standard array of information.

This function saves the resource directory entries in the data.

See `CreateResourceLangNode()` for example usage.

WinPEFile::CalculateHashes(&$data)
----------------------------------

Access:  public

Parameters:

* $data - A string containing the data passed to `Parse()`.

Returns:  A standard array of information.

This function calculates Authenticode-compatible PE hashes (MD5, SHA-1, and SHA-256) for the data.

WinPEFile::ClearCertificates(&$data)
------------------------------------

Access:  public

Parameters:

* $data - A string containing the data passed to `Parse()`.

Returns:  A standard array of information.

This function zeroes out the PE optional header certificate table in the data and clears the certificate table position and size in the headers.

WinPEFile::ClearBoundImports(&$data)
------------------------------------

Access:  public

Parameters:

* $data - A string containing the data passed to `Parse()`.

Returns:  A standard array of information.

This function zeroes out the PE optional header bound imports table in the data and clears the bound imports table position and size in the headers.

WinPEFile::ClearDebugDirectory(&$data)
--------------------------------------

Access:  public

Parameters:

* $data - A string containing the data passed to `Parse()`.

Returns:  A standard array of information.

This function zeroes out the PE optional header debug directory table and its contents in the data and clears the debug directory table RVA and size in the headers.

WinPEFile::SanitizeDOSStub(&$data)
----------------------------------

Access:  public

Parameters:

* $data - A string containing the data passed to `Parse()`.

Returns:  A standard array of information.

This function replaces the DOS stub in the data with the WinPEFile DOS stub and updates the headers accordingly.  The WinPEFile DOS stub is a minimalist executable that does not contain a Rich header signature.

WinPEFile::RVAToPos($rva)
-------------------------

Access:  public

Parameters:

* $rva - An integer containing a Relative Virtual Address (RVA).

Returns:  An array containing the section number and relative position within the section on success, a boolean of false otherwise.

This function attempts to locate the section and the position within the section for the given RVA.

WinPEFile::GetRVAString(&$data, $rva)
-------------------------------------

Access:  public

Parameters:

* $data - A string containing the data passed to `Parse()`.
* $rva - An integer containing a Relative Virtual Address (RVA).

Returns:  The ASCII string at the RVA on success, a boolean of false otherwise.

This function attempts to extract the zero-terminated ASCII string from the data at the specified RVA.

WinPEFile::GetUInt8(&$data, &$x, $y)
------------------------------------

Access:  public static

Parameters:

* $data - A string containing the data passed to `Parse()`.
* $x - An integer containing the starting position of the UInt8.
* $y - An integer containing the size/limit of the data.

Returns:  The UInt8 value at the specified position.

This static function returns the unsigned 8-bit value at the specified position and increments $x by 1.  Calls `GetBytes()` to get the substring for the value.

WinPEFile::GetUInt16(&$data, &$x, $y)
-------------------------------------

Access:  public static

Parameters:

* $data - A string containing the data passed to `Parse()`.
* $x - An integer containing the starting position of the UInt16.
* $y - An integer containing the size/limit of the data.

Returns:  The UInt16 value at the specified position.

This static function returns the unsigned 16-bit value at the specified position and increments $x by 2.  Calls `GetBytes()` to get the substring for the value.

WinPEFile::GetUInt32(&$data, &$x, $y)
-------------------------------------

Access:  public static

Parameters:

* $data - A string containing the data passed to `Parse()`.
* $x - An integer containing the starting position of the UInt32.
* $y - An integer containing the size/limit of the data.

Returns:  The UInt32 value at the specified position.

This static function returns the unsigned 32-bit value at the specified position and increments $x by 4.  Calls `GetBytes()` to get the substring for the value.

Technically not a UInt32 on 32-bit PHP but rather a signed Int32.  The WinPEFile class adapts automatically for most scenarios.

WinPEFile::GetUInt64(&$data, &$x, $y)
-------------------------------------

Access:  public static

Parameters:

* $data - A string containing the data passed to `Parse()`.
* $x - An integer containing the starting position of the UInt64.
* $y - An integer containing the size/limit of the data.

Returns:  The UInt64 value at the specified position.

This static function returns the unsigned 64-bit value at the specified position and increments $x by 8.  Calls `GetBytes()` to get the substring for the value.

Technically not a UInt64 on PHP but rather a signed Int64 for 64-bit PHP and a float on 32-bit PHP for very large values (rare).  The actual data type is irrelevant though for all use-cases.

WinPEFile::GetBytes(&$data, &$x, $y, $size)
-------------------------------------------

Access:  public static

Parameters:

* $data - A string containing the data passed to `Parse()`.
* $x - An integer containing the starting position in the data.
* $y - An integer containing the size/limit of the data.
* $size - An integer containing the number of bytes to return.

Returns:  A string extracted from the data of the requested size.

This static function returns the requested number of bytes of data.  If $x goes past the end of the data, zeros pad out the remainder of the string that is returned.

WinPEFile::SetUInt8(&$data, &$x, $val)
--------------------------------------

Access:  public static

Parameters:

* $data - A string containing the data passed to `Parse()`.
* $x - An integer containing the starting position of the UInt8.
* $val - An integer containing the value to write.

Returns:  Nothing.

This static function converts the value to a 1-byte, little-endian string and calls `SetBytes()`.

WinPEFile::SetUInt16(&$data, &$x, $val)
---------------------------------------

Access:  public static

Parameters:

* $data - A string containing the data passed to `Parse()`.
* $x - An integer containing the starting position of the UInt16.
* $val - An integer containing the value to write.

Returns:  Nothing.

This static function converts the value to a 2-byte, little-endian string and calls `SetBytes()`.

WinPEFile::SetUInt32(&$data, &$x, $val)
---------------------------------------

Access:  public static

Parameters:

* $data - A string containing the data passed to `Parse()`.
* $x - An integer containing the starting position of the UInt32.
* $val - An integer containing the value to write.

Returns:  Nothing.

This static function converts the value to a 4-byte, little-endian string and calls `SetBytes()`.

WinPEFile::SetUInt64(&$data, &$x, $val)
---------------------------------------

Access:  public static

Parameters:

* $data - A string containing the data passed to `Parse()`.
* $x - An integer containing the starting position of the UInt64.
* $val - An integer (or float for 32-bit PHP) containing the value to write.

Returns:  Nothing.

This static function converts the value to an 8-byte, little-endian string and calls `SetBytes()`.

WinPEFile::SetBytes(&$data, &$x, $val, $size)
---------------------------------------------

Access:  public static

Parameters:

* $data - A string containing the data passed to `Parse()`.
* $x - An integer containing the starting position of the UInt64.
* $val - A string containing the value to write.
* $size - An integer containing the number of bytes to write.

Returns:  Nothing.

This static function copies the value to the data inline.  If the source value length is less than the size, zeroes pad out the remainder.
