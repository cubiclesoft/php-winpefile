WinPEUtils Class:  'support/win_pe_utils.php'
=============================================

The WinPEUtils class provides utility functions to perform advanced extraction and modification tasks of files stored in the Portable Executable (PE/COFF) file format.  This class depends on both the WinPEFile class and other dependencies.

WinPEUtils::GetIconOrCursorResource($winpe, $searchtype, $icoidname = true, $icoidlang = true)
----------------------------------------------------------------------------------------------

Access:  public static

Parameters:

* $winpe - A WinPEFile class instance.
* $searchtype - Either WinPEFile::RT_GROUP_CURSOR or WinPEFile::RT_GROUP_ICON.
* $icoidname - An integer or a string containing the resource ID or name OR a boolean of true to match the first ID or name (Default is true).
* $icoidlang - An integer containing the language of the resource data OR a boolean of true to match the first language code (Default is true).

Returns:  A standard array of information.

This static function reconstructs a valid icon (ICO) or cursor (CUR) from the first matching resource directory.  The resource directory structure splits up the header and each icon/cursor into their own resources so this function reverses that process.

Depends on the WinICO class.  Calling `GetIconResource()` or `GetCursorResource()` is preferred.

WinPEUtils::GetIconResource($winpe, $icoidname = true, $icoidlang = true)
-------------------------------------------------------------------------

Access:  public static

Parameters:

* $winpe - A WinPEFile class instance.
* $icoidname - An integer or a string containing the resource ID or name OR a boolean of true to match the first ID or name (Default is true).
* $icoidlang - An integer containing the language of the resource data OR a boolean of true to match the first language code (Default is true).

Returns:  A standard array of information.

This static function calls `GetIconOrCursorResource()` using WinPEFile::RT_GROUP_ICON to reconstruct a valid icon (ICO) from the first matching resource directory.

Example usage:

```php
<?php
	require_once "support/win_pe_file.php";
	require_once "support/win_pe_utils.php";

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

	// Extract the application icon (always the first icon group resource).
	$result = WinPEUtils::GetIconResource($winpe);
	if (!$result["success"])
	{
		var_dump($result);

		exit();
	}

	file_put_contents("peview.ico", $result["data"]);
?>
```

WinPEUtils::GetCursorResource($winpe, $icoidname = true, $icoidlang = true)
---------------------------------------------------------------------------

Access:  public static

Parameters:

* $winpe - A WinPEFile class instance.
* $icoidname - An integer or a string containing the resource ID or name OR a boolean of true to match the first ID or name (Default is true).
* $icoidlang - An integer containing the language of the resource data OR a boolean of true to match the first language code (Default is true).

Returns:  A standard array of information.

This static function calls `GetIconOrCursorResource()` using WinPEFile::RT_GROUP_CURSOR to reconstruct a valid cursor (CUR) from the first matching resource directory.

WinPEUtils::SetIconOrCursorResource($winpe, &$data, $icoinfo, $icoidname = true, $icoidlang = true)
---------------------------------------------------------------------------------------------------

Access:  public static

Parameters:

* $winpe - A WinPEFile class instance.
* $data - A string containing the data passed to `WinPEFile::Parse()`.
* $icoinfo - A string containing an icon or cursor OR an array containing the result of `WinICO::Parse()`.
* $icoidname - An integer or a string containing the resource ID or name OR a boolean of true to match the first ID or name (Default is true).
* $icoidlang - An integer containing the language of the resource data OR a boolean of true to match the first language code (Default is true).

Returns:  A standard array of information.

This static function overwrites an existing icon (ICO) or cursor (CUR) resource or creates a new resource in the resource directory.  The resource directory structure splits up the header and each icon/cursor into their own resources so this function simplifies the whole process.

Depends on the WinICO class.  Calling `SetIconResource()` or `SetCursorResource()` are preferred for code clarity/consistency.

WinPEUtils::SetIconResource($winpe, &$data, $icoinfo, $icoidname = true, $icoidlang = true)
-------------------------------------------------------------------------------------------

Access:  public static

Parameters:

* $winpe - A WinPEFile class instance.
* $data - A string containing the data passed to `WinPEFile::Parse()`.
* $icoinfo - A string containing an icon or cursor OR an array containing the result of `WinICO::Parse()`.
* $icoidname - An integer or a string containing the resource ID or name OR a boolean of true to match the first ID or name (Default is true).
* $icoidlang - An integer containing the language of the resource data OR a boolean of true to match the first language code (Default is true).

Returns:  A standard array of information.

This static function calls `SetIconOrCursorResource()` to overwrite an existing icon (ICO) resource or creates a new resource in the resource directory.

Example usage:

```php
<?php
	require_once "support/win_pe_file.php";
	require_once "support/win_pe_utils.php";

	$srcfile = "peview.exe";
	$icofile = "peview_new.ico";

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

	$icoinfo = file_get_contents($icofile);

	// Overwrite the application icon (always the first icon group resource).
	$result = WinPEUtils::SetIconResource($winpe, $data, $icoinfo);
	if (!$result["success"])
	{
		var_dump($result);

		exit();
	}

	// Save the resources back into the data.
	$result = $winpe->SavePEResourcesDirectory($data);
	if (!$result["success"])
	{
		var_dump($result);

		exit();
	}

	// Write out the modified executable.
	file_put_contents("peview_modified.exe", $data);
?>
```

WinPEUtils::SetCursorResource($winpe, &$data, $icoinfo, $icoidname = true, $icoidlang = true)
---------------------------------------------------------------------------------------------

Access:  public static

Parameters:

* $winpe - A WinPEFile class instance.
* $data - A string containing the data passed to `WinPEFile::Parse()`.
* $icoinfo - A string containing an icon or cursor OR an array containing the result of `WinICO::Parse()`.
* $icoidname - An integer or a string containing the resource ID or name OR a boolean of true to match the first ID or name (Default is true).
* $icoidlang - An integer containing the language of the resource data OR a boolean of true to match the first language code (Default is true).

Returns:  A standard array of information.

This static function calls `SetIconOrCursorResource()` to overwrite an existing cursor (CUR) resource or creates a new resource in the resource directory.

WinPEUtils::GetUnicodeStr(&$data, &$x, $y)
------------------------------------------

Access:  public static

Parameters:

* $data - A string containing the data passed to `WinPEFile::Parse()`.
* $x - An integer containing the starting position of the UTF-16 LE string in the data.
* $y - An integer containing the size/limit of the data.

Returns:  A UTF-8 string extracted from the data.

This static function extracts a zero-terminated UTF-16 LE string and converts it, minus the zero, to UTF-8 and returns the result.  $x is moved forward past the end of the string.

Requires the UTFUtils class.

WinPEUtils::SetUnicodeStr(&$data, &$x, $str)
--------------------------------------------

Access:  public static

Parameters:

* $data - A string containing the data passed to `WinPEFile::Parse()`.
* $x - An integer containing the starting position of the UTF-16 LE string in the data.
* $str - A UTF-8 string to convert and write.

Returns:  Nothing.

This static function converts the UTF-8 string to UTF-16 LE and writes a zero-terminated string to the data and adjusting $x to point past the end of the string.

Depends on the UTFUtils class.

WinPEUtils::Internal_ParseVersionInfoEntry(&$data, &$x, $y, $parentkey, $allowedkeys)
-------------------------------------------------------------------------------------

Access:  _internal_ static

Parameters:

* $data - A string containing the data passed to `WinPEFile::Parse()`.
* $x - An integer containing the starting position of the UTF-16 LE string in the data.
* $y - An integer containing the size/limit of the data.
* $parentkey - A string containing the parent key or a boolean of false for the root.
* $allowedkeys - An array of allowed keys or a boolean of true to allow any key.

Returns:  A standard array of information.

This internal static function recursively extracts a portion of structured version information.  The function implicitly prevents infinite recursion since the VS_VERSION_INFO structure only goes a few layers deep.

WinPEUtils::ParseVersionInfoData($data)
---------------------------------------

Access:  public static

Parameters:

* $data - A string containing a binary VS_VERSION_INFO structure to parse.

Returns:  A standard array of information.

This static function parses a binary VS_VERSION_INFO structure into a set of hierarchical arrays.

WinPEUtils::GetVersionResource($winpe, $veridlang = true)
---------------------------------------------------------

Access:  public static

Parameters:

* $winpe - A WinPEFile class instance.
* $veridlang - An integer containing the language of the resource data OR a boolean of true to match the first language code (Default is true).

Returns:  A standard array of information.

This static function extracts and parses a matching version information resource from the PE resource data directory.

Example usage:

```php
<?php
	require_once "support/win_pe_file.php";
	require_once "support/win_pe_utils.php";

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

	// Extract the version information resource and dump it out.
	$result = WinPEUtils::GetVersionResource($winpe);
	if (!$result["success"])
	{
		var_dump($result);

		exit();
	}

	$verinfo = $result;

	$verinfo["entry"]["fixed"]["file_ver"] = "1.0.0.0";
	$verinfo["entry"]["fixed"]["product_ver"] = "1.0.0.0";

	// Overwrite the version information resource.
	$result = WinPEUtils::SetVersionResource($winpe, $data, $verinfo);
	if (!$result["success"])
	{
		var_dump($result);

		exit();
	}

	// Save the resources back into the data.
	$result = $winpe->SavePEResourcesDirectory($data);
	if (!$result["success"])
	{
		var_dump($result);

		exit();
	}

	// Write out the modified executable.
	file_put_contents("peview_modified.exe", $data);
?>
```

WinPEUtils::GenerateVersionInfoData($verinfo)
---------------------------------------------

Access:  public static

Parameters:

* $verinfo - An array containing a parsed VS_VERSION_INFO structure.

Returns:  A standard array of information.

This static function generates, using the input array as a template, a binary VS_VERSION_INFO structure.

WinPEUtils::SetVersionResource($winpe, &$data, $verinfo, $veridlang = true)
---------------------------------------------------------------------------

Access:  public static

Parameters:

* $winpe - A WinPEFile class instance.
* $data - A string containing the data passed to `WinPEFile::Parse()`.
* $verinfo - An array containing a parsed VS_VERSION_INFO structure.
* $veridlang - An integer containing the language of the resource data OR a boolean of true to match the first language code (Default is true).

Returns:  A standard array of information.

This static function overwrites an existing version information resource or creates a new resource in the resource directory.

See `GetVersionResource()` for example usage.

WinPEUtils::CalculatePEImportsDirectoryOffsets($winpe, &$direntries)
--------------------------------------------------------------------

Access:  public static

Parameters:

* $winpe - A WinPEFile class instance.
* $direntries - An array of PE import directory entries.

Returns:  An array of various offsets.

This static function calculates offsets for a compact imports table.  Assumes the IAT appears before the main directory.  Used by `SavePEImportsDirectory()`.

WinPEUtils::SavePEImportsDirectory($winpe, &$data, $secnum, $baserva, &$direntries)
-----------------------------------------------------------------------------------

Access:  public static

Parameters:

* $winpe - A WinPEFile class instance.
* $data - A string containing the data passed to `WinPEFile::Parse()`.
* $secnum - An integer containing a section number to write the PE imports table to.
* $baserva - An integer containing the base RVA of the entire table or a boolean of false to select the base RVA of the section.  Must be DWORD-aligned.
* $direntries - An array of PE import directory entries.

Returns:  A standard array of information.

This static function generates and applies the PE import directory entries starting at the specified base RVA and sets both the PE imports and PE IAT data directory RVAs and sizes.  Used by `CreateHookDLL()`.

WinPEUtils::CalculatePEExportsDirectoryOffsets(&$exportdir, &$addresses, &$namemap)
-----------------------------------------------------------------------------------

Access:  public static

Parameter:

* $exportdir - An array containing PE export directory information.
* $addresses - An array containing PE export addresses.
* $namemap - An array containing a name to ordinal mapping.

Returns:  An array of various offsets.

This static function calculates offsets for a compact exports table.  Used by `SavePEExportsDirectory()`.

WinPEUtils::SavePEExportsDirectory($winpe, &$data, $secnum, $baserva, &$exportdir, &$addresses, &$namemap)
----------------------------------------------------------------------------------------------------------

Access:  public static

Parameters:

* $winpe - A WinPEFile class instance.
* $data - A string containing the data passed to `WinPEFile::Parse()`.
* $secnum - An integer containing a section number to write the PE exports table to.
* $baserva - An integer containing the base RVA of the entire table or a boolean of false to select the base RVA of the section.  Must be DWORD-aligned.
* $exportdir - An array containing PE export directory information.
* $addresses - An array containing PE export addresses.
* $namemap - An array containing a name to ordinal mapping.

Returns:  A standard array of information.

This static function generates and applies the PE exports directory entries starting at the specified base RVA and sets both the PE exports data directory RVA and size.  Used by `CreateHookDLL()`.

WinPEUtils::CalculatePEBaseRelocationsDirectorySize(&$blocks)
-------------------------------------------------------------

Access:  public static

Parameter:

* $blocks - An array containing PE base relocation blocks and offsets.

Returns:  An integer containing the total size of the base relocation directory.

This static function calculates the space required for the base relocation directory.  Used by `SavePEBaseRelocationsDirectory()`.

WinPEUtils::SavePEBaseRelocationsDirectory($winpe, &$data, $secnum, $baserva, &$blocks)
---------------------------------------------------------------------------------------

Access:  public static

Parameters:

* $winpe - A WinPEFile class instance.
* $data - A string containing the data passed to `WinPEFile::Parse()`.
* $secnum - An integer containing a section number to write the PE base relocations table to.
* $baserva - An integer containing the base RVA of the entire table or a boolean of false to select the base RVA of the section.  Must be DWORD-aligned.
* $blocks - An array containing PE base relocation blocks and offsets.

Returns:  A standard array of information.

This static function generates and applies the PE base relocation blocks starting at the specified base RVA and sets both the PE base relocation data directory RVA and size.  Used by `CreateHookDLL()`.

WinPEUtils::CreateHookDLL($origfilename, $hookfilename, $winpeorig, $winpehooks, $win9x = false)
------------------------------------------------------------------------------------------------

Access:  public static

Parameters:

* $origfilename - A string containing the original filename (e.g. kernel32.dll).
* $hookfilename - A string containing the hook DLL filename with exported hook functions.
* $winpeorig - A WinPEFile class instance of the original file.
* $winpehooks - A WinPEFile class instance of the hook DLL.
* $win9x - A boolean that indicates whether or not to generate a Windows 9x/Me compatible DLL through simulated export forwarding (Default is false).

Returns:  A standard array of information.

This function generates a brand new DLL that redirects exported functions based on whether the hook DLL has the function.  Export forwarding is primarily used to forward function calls to the correct DLL.

Export forwarding is an under-utilized feature of the PE file format that lets the Windows NT loader do the work of patching the IAT.  This feature makes it easy to bring in missing functions to DLL exports and is also slightly safer for general-purpose application hooking.  Simulated export forwarding is only slightly more complicated.

When this function simulates export forwarding for Win9x/Me support, it creates a table of Intel x86 `jmp ds:addr` instructions into the IAT.  This is sometimes referred to as [thunking](https://en.wikipedia.org/wiki/Thunk).  The Windows loader, again, does the hard work of loading the IAT with the correct addresses and each jmp instruction is referenced by relevant export table entry.  A relocation table is also generated so that each jump table address can be updated by the Windows loader.  This approach accomplishes the same thing as export forwarding but with one extra but harmless instruction in the mix.  Note that Win9x/Me is extremely ancient and/or very dead and a sufficiently capable version of PHP probably won't run on those OSes either.  So Win9x/Me support may be of limited value other than being a brief, "hmm, interesting."
