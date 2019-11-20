Windows PE File Tools for PHP
=============================

A command-line tool and a set of PHP classes to easily extract information, modify files, and even construct files from scratch in the Windows Portable Executable (PE) file format (i.e. EXEs, DLLs, etc).

[![Donate](https://cubiclesoft.com/res/donate-shield.png)](https://cubiclesoft.com/donate/)

Features
--------

* WinPEFile.  A self-contained class that extracts all useful structural information about a PE file and can also correctly modify a number of common portions of files.
* WinPEUtils.  A utility class with static functions for making more advanced modifications (e.g. applying and replacing icons), extracting version information resources, and creating hook DLLs.
* WinICO.  Another utility class for creating, extracting individual images from, and manipulating Windows ICO (icon) and CUR (cursor) files.
* A powerful command-line tool (pe_tools.php) to perform all of the core operations of the above classes with JSON output.
* Rapidly construct a PE file artifact library using multiple CPU cores.
* Can also read and write MS-DOS and Win16 NE file headers.
* Runs on any platform that PHP runs on.  Both 32-bit and 64-bit PHP are supported.
* Includes a unique, never before utilized PE file hooking mechanism.
* Has a liberal open source license.  MIT or LGPL, your choice.
* Designed for relatively painless integration into your environment.
* Sits on GitHub for all of that pull request and issue tracker goodness to easily submit changes and ideas respectively.

Use Cases
---------

* Understanding the PE file format and its structure.
* Extracting resources (e.g. icons, dialogs, and manifests).
* Statically analyzing executables for the minimum version of Windows that an application will probably run just fine on.
* Modifying minimum OS version requirements so that an executable runs on older Windows OSes post-compile/link.
* Neutralizing leftover debug information from compiling and linking phases that might contain sensitive file paths.
* Applying prepared executable manifests, application icons, and other directory resources without needing a resource compiler.
* Writing a compiler that generates binaries for Windows on non-Windows OSes (e.g. Linux or Mac OSX).
* Hooking executables to add missing functions and/or to make them do different things (e.g. making an app "portable").
* And much more!

Getting Started
---------------

Download or clone this repository.  PHP 7.x or later is required.  64-bit PHP 7.2 or later is recommended.  Windows is recommended too (but not required).  The PHP GD library is required for some parts of the `WinPEUtils` class.

When working with the PE file format for the first time ever, obtaining or building an artifact library containing samples of PE files to reference later with various tools is highly recommended (see "More Tools" below).  This is especially true if building any software that interacts with the PE file format (e.g. a class like `WinPEFile`).  Check out the curated [Windows PE Artifact Library](https://github.com/cubiclesoft/windows-pe-artifact-library) or build an artifact library with this command:

```
php pe_tools.php artifacts find C:\ "" Y 6
```

That command will use 6 CPU cores and scan all of the C: drive for executables under 15MB to construct an artifact library and JSON manifest.  Rare artifacts are noted at the end of a scan.  It takes approximately 15 minutes to scan 50,000 executable files (*.exe, *.dll, *.ocx, etc) across an entire system using a Core i7 with SSD drives.  This process only needs to complete successfully one time and provides an excellent reference resource later on while working with PE files.

The `pe_tools.php` command-line application is question-answer enabled.  Just running it will provide an interactive experience:

```
php pe_tools.php
```

Here's the full list of available commands that `pe_tools.php` supports:

```
artifacts:  Manage and find artifacts

  find:     Find interesting artifacts
  missing:  List missing artifacts
  origins:  Generate an origin Markdown file for new artifact files


extract:  Extract information and binary data

  info:          Get detailed information about a PE file
  dos-stub:      Write the MS-DOS stub to a file
  sections:      Write raw image sections to files
  resources:     Write resources table items to files (icons, cursors, etc.)
  version-info:  Get version information from the PE file resources table
  certificates:  Write raw Authenticode certificates to files


calculate:  Perform various calculations

  rva:       Get information about a RVA in a PE file
  checksum:  Calculate the relevant checksum for a file
  hashes:    Calculate Authenticode-compatible PE hashes for a file


modify:  Perform various useful modifications

  clear-certs:          Remove Authenticode certificates
  clear-debug:          Remove debug directory
  clear-bound-imports:  Remove rare bound imports
  clear-checksums:      Clear MS-DOS and NE/PE checksums
  sanitize-dos-stub:    Apply a sanitized MS-DOS stub
  set-min-os:           Set the minimum OS version required
  set-min-subsystem:    Set the minimum OS subsystem version required
  set-app-icon:         Add or overwrite the application icon resource
  set-manifest:         Add or overwrite the application manifest resource
  set-version-info:     Add or overwrite the application version resource
  create-hook-dll:      Generate a hook DLL
  hook:                 Apply a hook DLL
  unhook:               Remove a hook DLL
  add-section:          Adds a new section
  expand-last-section:  Expand the last section
  delete-section:       Deletes a section
  apply-checksum:       Apply MS-DOS/NE/PE checksum
```

Example usage of the `WinPEFile` PHP class:

```php
<?php
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

	// Sanitize the DOS stub.
	$result = $winpe->SanitizeDOSStub($data);
	if (!$result["success"])
	{
		var_dump($result);

		exit();
	}

	// Strip debug directory.
	$result = $winpe->ClearDebugDirectory($data);
	if (!$result["success"])
	{
		var_dump($result);

		exit();
	}

	// Strip Authenticode certificate(s).
	$result = $winpe->ClearCertificates($data);
	if (!$result["success"])
	{
		var_dump($result);

		exit();
	}

	// Update the checksum.
	$winpe->UpdateChecksum($data);

	// Write out the modified executable.
	file_put_contents("peview_modified.exe", $data);
?>
```

Additional examples can be found in the documentation for the various PHP classes.  Also, the source code to `pe_tools.php` has plenty of working examples as well.

Documentation
-------------

* [Microsoft PE/COFF specification](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format) - The official Portable Executable file format documentation from Microsoft.  It used to only be available as an offline Word document.
* [WinPEFile class](https://github.com/cubiclesoft/php-winpefile/blob/master/docs/win_pe_file.md) - A self-contained class for reading and altering PE file information and creating new PE files from scratch.
* [WinPEUtils class](https://github.com/cubiclesoft/php-winpefile/blob/master/docs/win_pe_utils.md) - Utility functions to do more complex tasks such as retrieve and set ICO and CUR files, apply specialized import, export, and base relocation tables, and generate a hook DLL from two source DLLs.
* [WinICO class](https://github.com/cubiclesoft/php-winpefile/blob/master/docs/win_ico.md) - Create, extract, manipulate, and generate Windows ICO and CUR files.  Can convert PNG, JPG, and non-animated GIF images to properly defined, multi-size ICO and CUR formats (requires the PHP GD library).

Hooking Executables
-------------------

Creating a functional hook DLL usually requires knowledge of the relevant Windows API(s) to hook, a C or C++ compiler, and a lot of patience.  Your first hook DLLs will probably fail.  A simple starting point is to hook something like `CreateFileA()` in `kernel32.dll` and have it write out each file being opened by the application to a log file.  Don't forget to pass the original call onto the intended function and don't get stuck in an infinite loop!

Of course, once the hook DLL is created, applying said hook DLL to an existing PE file comes with all kinds of caveats.  [Detours](https://github.com/microsoft/Detours) by Microsoft Research and [EasyHook](https://easyhook.github.io/) are two popular options to develop and apply a hook DLL and both options are certainly useful.  Both tools modify the Import Address Table (IAT) of the EXE and loaded DLLs during runtime so that the hooks are always correctly installed into all IATs.

The `WinPEUtils` class and `pe_tools.php` take a different, far more unique approach:  Automatically create a brand new, carefully named DLL from scratch that uses either real export forwarding (NT only) or simulated export forwarding (for Win9x/Me compatibility) to point at the correct DLL and function.  Then apply the newly generated DLL by replacing all of the references to the original file inside the original executable (e.g. replace the string "kernel32.dll" with "12xiasoa.dll").  Of note, the name for the new DLL is the same length as the original DLL name.  If all goes well, the application remains largely unaware that it has had some of its functions redirected elsewhere by abusing the Windows loader.  Undoing a hook is as simple as replacing a few strings.

Example usage:

```
php pe_tools.php modify create-hook-dll C:\Windows\System32\kernel32.dll myhook.dll .\hooktest\ N
php pe_tools.php modify hook .\path\to\myapp.exe "" kernel32.dll .\hooktest\in8rej1f.dll
php pe_tools.php modify apply-checksum .\path\to\myapp.exe ""

php pe_tools.php modify unhook .\path\to\myapp.exe "" kernel32.dll in8rej1f.dll
php pe_tools.php modify apply-checksum .\path\to\myapp.exe ""
```

The first command above creates the hook DLL and generates a randomly named file in the destination directory (e.g. 'in8rej1f.dll').  The second command applies the hook DLL and imported DLLs to the specified executable, replacing references to 'kernel32.dll' with 'in8rej1f.dll'.  The Windows loader will load 'in8rej1f.dll' instead of 'kernel32.dll'.  The 'in8rej1f.dll' file contains export forwards to the original DLLs, with the hooked functions taking priority.  The third command updates the PE checksum so it is valid, which is not required but still a good idea.

The fourth and fifth commands undo the changes to the application.

More Tools
----------

When working with the PE file format for the first time, you will need tools.  Lots of weird, esoteric tools that only run on Windows (and sometimes Wine).

* [PEview](http://wjradburn.com/software/) - Great for looking at the PE file format structure as close to how it is natively stored on disk as is possible in a GUI.  Doesn't really do much beyond viewing raw information and also doesn't work all that well with 64-bit binaries.  Drag-and-drop onto the interface opens a file.  The File -> Close menu option closes a file and release handles, which seems like a benign feature but ends up being really nice when modifying PE files.
* [PPEE](https://www.mzrst.com/) aka Puppy - A fairly decent tool for analyzing modified PE files for correctness.  It also has string finding and binary analysis for malware indicators.  Handles both 32-bit and 64-bit binaries.
* [CFF Explorer](https://ntcore.com/?page_id=388) - Mentioned regularly in reverse engineering circles but, while free, it's also kind of awkward for just looking at the PE structures themselves.  PEview and PPEE are, most of the time, better options.  The author also has a ~$700 per seat product called Cerbero for conducting forensic analysis.  It's probably fine at what it does, but that's well outside of the average person's budget.
* [Dependencies](https://github.com/lucasg/Dependencies) - THE replacement for the classic Dependency Walker.  It's faster than Dependency Walker and also supports API sets (aka Microsoft's broken-by-design breakup of APIs across zillions of DLLs).  Useful when verifying the results of the hook DLL feature of 'pe_tools.php' in this project.
* [Resource Hacker](http://www.angusj.com/resourcehacker/) - Classic resource directory EXE/DLL modification tool.  It resizes PE sections, which is a dangerous binary operation.  ResHack also crashes pretty regularly.  It is useful for checking the contents of resource directories of executables but not much else past that.  This project's WinPEFile and WinPEUtils classes take a much safer, slightly less optimal approach when modifying PE files.
