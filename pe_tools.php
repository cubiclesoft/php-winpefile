<?php
	// PE File command-line tools.
	// (C) 2019 CubicleSoft.  All Rights Reserved.

	if (!isset($_SERVER["argc"]) || !$_SERVER["argc"])
	{
		echo "This file is intended to be run from the command-line.";

		exit();
	}

	// Temporary root.
	$rootpath = str_replace("\\", "/", dirname(__FILE__));

	require_once $rootpath . "/support/cli.php";
	require_once $rootpath . "/support/win_pe_file.php";

	// Process the command-line options.
	$options = array(
		"shortmap" => array(
			"p" => "datapath",
			"s" => "suppressoutput",
			"?" => "help"
		),
		"rules" => array(
			"datapath" => array("arg" => true),
			"nocolor" => array("arg" => false),
			"suppressoutput" => array("arg" => false),
			"help" => array("arg" => false)
		),
		"allow_opts_after_param" => false
	);
	$args = CLI::ParseCommandLine($options);

	if (isset($args["opts"]["help"]))
	{
		echo "The PE File command-line tool\n";
		echo "Purpose:  Find, analyze, and manipulate PE files (EXEs, DLLs, etc) from the command-line.\n";
		echo "\n";
		echo "This tool is question/answer enabled.  Just running it will provide a guided interface.  It can also be run entirely from the command-line if you know all the answers.\n";
		echo "\n";
		echo "Syntax:  " . $args["file"] . " [options] [cmdgroup cmd [cmdoptions]]\n";
		echo "Options:\n";
		echo "\t-p   Data path.  Default is this tool's path.\n";
		echo "\t-s   Suppress most output.  Useful for capturing JSON output.\n";
		echo "\t-nocolor   Suppress XTerm color output.\n";
		echo "\n";
		echo "Examples:\n";
		echo "\tphp " . $args["file"] . "\n";
		echo "\tphp " . $args["file"] . " artifacts list\n";
		echo "\tphp " . $args["file"] . " artifacts find -path C:\Windows -exts exe,dll -copy Y\n";
		echo "\tphp " . $args["file"] . " extract info\n";
		echo "\tphp " . $args["file"] . " calculate checksum my.exe\n";
		echo "\tphp " . $args["file"] . " modify apply-checksum my.exe\n";

		exit();
	}

	$origargs = $args;
	$datapath = str_replace("\\", "/", (isset($args["opts"]["datapath"]) && realpath($args["opts"]["datapath"]) !== false ? realpath($args["opts"]["datapath"]) : $rootpath));
	$suppressoutput = (isset($args["opts"]["suppressoutput"]) && $args["opts"]["suppressoutput"]);
	$usecolor = !(isset($args["opts"]["nocolor"]) && $args["opts"]["nocolor"]);

	// Get the command group.
	$cmdgroups = array(
		"artifacts" => "Manage and find artifacts",
		"extract" => "Extract information and binary data",
		"calculate" => "Perform various calculations",
		"modify" => "Perform various useful modifications",
	);

	$cmdgroup = CLI::GetLimitedUserInputWithArgs($args, false, "Command group", false, "Available command groups:", $cmdgroups, true, $suppressoutput);

	// Get the command.
	switch ($cmdgroup)
	{
		case "artifacts":  $cmds = array("find" => "Find interesting artifacts", "missing" => "List missing artifacts", "origins" => "Generate an origin text file for each artifact file");  break;
		case "extract":  $cmds = array("info" => "Get detailed information about a PE file", "dos-stub" => "Write the MS-DOS stub to a file", "sections" => "Write raw image sections to files", "resources" => "Write resources table items to files (icons, cursors, etc.)", "version-info" => "Get version information from the PE file resources table", "certificates" => "Write raw Authenticode certificates to files");  break;
		case "calculate":  $cmds = array("rva" => "Get information about a RVA in a PE file", "checksum" => "Calculate the relevant checksum for a file", "hashes" => "Calculate Authenticode-compatible PE hashes for a file");  break;
		case "modify":  $cmds = array("clear-certs" => "Remove Authenticode certificates", "clear-debug" => "Remove debug directory", "clear-bound-imports" => "Remove rare bound imports", "clear-checksums" => "Clear MS-DOS and NE/PE checksums", "sanitize-dos-stub" => "Apply a sanitized MS-DOS stub", "set-min-os" => "Set the minimum OS version required", "set-min-subsystem" => "Set the minimum OS subsystem version required", "set-app-icon" => "Add or overwrite the application icon resource", "set-manifest" => "Add or overwrite the application manifest resource", "set-version-info" => "Add or overwrite the application version resource", "create-hook-dll" => "Generate a hook DLL", "hook" => "Apply a hook DLL", "unhook" => "Remove a hook DLL", "add-section" => "Adds a new section", "expand-last-section" => "Expand the last section", "delete-section" => "Deletes a section", "apply-checksum" => "Apply MS-DOS/NE/PE checksum");  break;
	}

	if ($cmds !== false)  $cmd = CLI::GetLimitedUserInputWithArgs($args, false, "Command", false, "Available commands:", $cmds, true, $suppressoutput);

	// Make sure directories exist.
	@mkdir($datapath . "/artifacts", 0770, true);
	@mkdir($datapath . "/artifacts/dos", 0770);
	@mkdir($datapath . "/artifacts/16_ne", 0770);
	@mkdir($datapath . "/artifacts/32_pe", 0770);
	@mkdir($datapath . "/artifacts/64_pe", 0770);

	@mkdir($datapath . "/extracts", 0770, true);

	if ($cmdgroup === "artifacts")
	{
		// Artifacts.
		if ($cmd === "find")
		{
			CLI::ReinitArgs($args, array("path", "exts", "copy", "processes"));

			require_once $rootpath . "/support/xterm.php";
			require_once $rootpath . "/support/process_helper.php";

			do
			{
				$path = CLI::GetUserInputWithArgs($args, "path", "Path to scan", false, "", $suppressoutput);
				$found = is_dir($path);
				if (!$found)  CLI::DisplayError("The path '" . $path . "' does not exist or is not a directory.", false, false);
			} while (!$found);

			$path = realpath($path);

			$exts = CLI::GetUserInputWithArgs($args, "exts", "File extensions", "exe,dll,sys,ocx,cpl,scr,com", "", $suppressoutput);
			$exts2 = explode(",", $exts);
			$exts = array();
			foreach ($exts2 as $ext)
			{
				$ext = strtolower(ltrim(trim($ext), "."));

				if ($ext !== false)  $exts["." . $ext] = true;
			}

			$copy = CLI::GetYesNoUserInputWithArgs($args, "copy", "Copy interesting files", "Y", "", $suppressoutput);

			$numprocs = (int)CLI::GetUserInputWithArgs($args, "processes", "Number of processes", "1", "The next question asks how many processes to hand requests off to.  Each process will use 100% of one CPU core and around 100 to 200MB RAM at peak usage.", $suppressoutput);
			if ($numprocs < 1)  $numprocs = 1;

			$startts = microtime(true);

			// Start processes.
			$readyqueue = array();
			$waitqueue = array();

			for ($x = 0; $x < $numprocs; $x++)
			{
				$cmd = escapeshellarg(PHP_BINARY) . " " . escapeshellarg($rootpath . "/support/artifact_find_helper.php");

				$options = array(
					"tcpstdin" => false
				);

				$result = ProcessHelper::StartProcess($cmd, $options);
				if (!$result["success"])  CLI::DisplayResult($result);

				unset($result["info"]);

				$readyqueue[] = $result;
			}

			$artifactnamemap = array();

			function AddArtifactToProcessingQueue($filename)
			{
				global $readyqueue, $waitqueue;

				$result = array_shift($readyqueue);
				$result["filename"] = $filename;
				$result["start"] = microtime(true);
				$result["line"] = "";

				fwrite($result["pipes"][0], $filename . "\n");

				$waitqueue[] = $result;
			}

			function ProcessArtifactQueue()
			{
				global $readyqueue, $waitqueue, $numprocs, $artifactnamemap, $suppressoutput, $usecolor;

				$numprocessed = 0;

				if (count($waitqueue))
				{
					do
					{
						// Only wait if the queue is full.
						if (count($waitqueue) >= $numprocs)
						{
							$ts = microtime(true);
							$readfps = array();
							foreach ($waitqueue as $result)
							{
								$readfps[] = $result["pipes"][1];
								$readfps[] = $result["pipes"][2];

								if ($ts - $result["start"] > 30)  echo "Waiting for 30+ seconds for:  " . $result["filename"] . "\n";
							}

							$writefps = array();
							$exceptfps = NULL;
							$result = @stream_select($readfps, $writefps, $exceptfps, 3, 0);
							if ($result === false)  break;
						}

						foreach ($waitqueue as $num => $result)
						{
							$line = fgets($result["pipes"][1]);

							if ($line !== false)
							{
								$waitqueue[$num]["line"] .= $line;

								if (substr($waitqueue[$num]["line"], -1) === "\n")
								{
									$result2 = @json_decode(trim($waitqueue[$num]["line"]), true);
									if (!is_array($result2))
									{
										echo "Unable to decode JSON response:\n";
										echo $result["filename"] . "\n";
										echo rtrim($line) . "\n";

										exit();
									}

									if ($result2["success"])
									{
										echo $result2["filename"] . " - " . number_format($result2["size"], 0) . " bytes\n";

										foreach ($result2["map"] as $name => $info)
										{
											if (!isset($artifactnamemap[$name]))
											{
												$artifactnamemap[$name] = array(
													"filename" => $result2["filename"],
													"size" => $result2["size"],
													"rare" => $info["rare"],
													"num" => 0,
													"samples" => array()
												);

												if (!$suppressoutput)
												{
													if ($usecolor)  XTerm::SetForegroundColor(120);
													echo "[New artifact]";
													if ($usecolor)  XTerm::SetForegroundColor(false);

													echo " " . $name . "\n";
												}
											}
											else if ($artifactnamemap[$name]["size"] > $result2["size"])
											{
												if (!$suppressoutput)
												{
													if ($usecolor)  XTerm::SetForegroundColor(80);
													echo "[Smaller artifact]";
													if ($usecolor)  XTerm::SetForegroundColor(false);

													echo " " . $name . "\n";
												}

												$artifactnamemap[$name]["filename"] = $result2["filename"];
												$artifactnamemap[$name]["size"] = $result2["size"];
											}

											$artifactnamemap[$name]["num"]++;

											if (substr($result2["filename"], -4) !== ".dat")  $artifactnamemap[$name]["samples"][$result2["filename"]] = $result2["size"];

											if (count($artifactnamemap[$name]["samples"]) > 25)
											{
												arsort($artifactnamemap[$name]["samples"]);

												$numleft = count($artifactnamemap[$name]["samples"]) - 3;
												foreach ($artifactnamemap[$name]["samples"] as $filename => $size)
												{
													unset($artifactnamemap[$name]["samples"][$filename]);

													$numleft--;
													if ($numleft <= 0)  break;
												}
											}
										}
									}

									unset($waitqueue[$num]);

									$readyqueue[] = $result;

									$numprocessed++;
								}
							}

							// Handle errors.
							$line = fgets($result["pipes"][2]);

							if ($line !== false)
							{
								echo $result["filename"] . "\n";
								echo rtrim($line) . "\n";
							}

							// Check for process termination.
							$pinfo = @proc_get_status($result["proc"]);
							if (!$pinfo["running"])  CLI::DisplayError("A helper process was terminated prematurely.");
						}
					} while (count($waitqueue) >= $numprocs);
				}

				return $numprocessed;
			}

			function ScanDirForArtifacts($path, $exts, &$paths)
			{
				global $suppressoutput;

				$path = rtrim(str_replace("\\", "/", $path), "/");

				$numprocessed = 0;

				$dir = @opendir($path);
				if ($dir)
				{
					while (($file = readdir($dir)) !== false)
					{
						if ($file !== "." && $file !== "..")
						{
							$filename = $path . "/" . $file;

							if (is_dir($filename))  $numprocessed += ScanDirForArtifacts($filename, $exts, $paths);
							else if (is_file($filename) && !is_link($filename))
							{
								$pos = strrpos($file, ".");
								if ($pos !== false && (isset($exts[".*"]) || isset($exts[strtolower(substr($file, $pos))])))
								{
									// Queue the file for processing.
									AddArtifactToProcessingQueue($filename);

									$numprocessed += ProcessArtifactQueue();
								}
							}
						}
					}

					closedir($dir);
				}

				return $numprocessed;
			}

			// Scan the manifest.
			$manifestfile = $datapath . "/artifacts/manifest.json";
			$manifest = @json_decode(file_get_contents($manifestfile), true);
			if (is_array($manifest) && isset($manifest["artifacts"]))
			{
				if (!$suppressoutput)  echo "\nInitializing manifest samples...\n";

				$artifactnamemap = array();
				foreach ($manifest["artifacts"] as $name => $info)
				{
					$samples = array();
					foreach ($info["samples"] as $filename)
					{
						if (file_exists($filename))  $samples[$filename] = filesize($filename);
					}

					$info["samples"] = $samples;

					$artifactnamemap[$name] = $info;
				}
			}
			else
			{
				$manifest = array(
					"scans" => array(),
					"artifacts" => array()
				);
			}

			// Scan the artifact library.
			$totalprocessed = 0;
			$origsuppressoutput = $suppressoutput;
			if (!$suppressoutput)  echo "\nLoading artifact library at '" . realpath($datapath . "/artifacts") . "'...\n";
			$suppressoutput = true;
			$totalprocessed += ScanDirForArtifacts($datapath . "/artifacts", array(".dat" => true), $paths);

			// Wait for the artifact processing queue to clear so weird stuff doesn't show up during the main scan.
			$orignumprocs = $numprocs;
			$numprocs = 1;
			$totalprocessed += ProcessArtifactQueue();
			$numprocs = $orignumprocs;
			$suppressoutput = $origsuppressoutput;

			// Update totals from the manifest.
			foreach ($artifactnamemap as $name => $info)
			{
				if (isset($manifest["artifacts"][$name]))
				{
					$info["num"] = $manifest["artifacts"][$name]["num"];

					$artifactnamemap[$name] = $info;
				}
			}

			// Now perform the main scan.
			if (!$suppressoutput)  echo "\nScanning '" . $path . "'...\n";
			$numprocessed = ScanDirForArtifacts($path, $exts, $paths);

			// Finalize the queue.
			$numprocs = 1;
			$numprocessed += ProcessArtifactQueue();
			$totalprocessed += $numprocessed;

			ksort($artifactnamemap, SORT_NATURAL | SORT_FLAG_CASE);

			// Copy new artifacts to the library and clean up the samples.
			$rareartifacts = array();
			foreach ($artifactnamemap as $name => $info)
			{
				if ($info["rare"])  $rareartifacts[] = $name . ".dat";

				if ($copy && (!is_file($datapath . "/artifacts/" . $name . ".dat") || file_get_contents($datapath . "/artifacts/" . $name . ".dat") !== file_get_contents($info["filename"])))
				{
					file_put_contents($datapath . "/artifacts/" . $name . ".dat", file_get_contents($info["filename"]));

					@unlink($datapath . "/artifacts/" . $name . ".txt");
				}

				arsort($info["samples"]);

				if (count($info["samples"]) > 3)
				{
					$numleft = count($info["samples"]) - 3;
					foreach ($info["samples"] as $filename => $size)
					{
						unset($info["samples"][$filename]);

						$numleft--;
						if ($numleft <= 0)  break;
					}
				}

				$artifactnamemap[$name]["samples"] = array_keys($info["samples"]);
			}

			if (!$suppressoutput && count($rareartifacts))
			{
				echo "\nCongratulations!  You have found the following rare " . (count($rareartifacts) == 1 ? "artifact" : "artifacts") . ":\n\n";
				echo "\t* " . implode("\n\t* ", $rareartifacts) . "\n\n";
				echo "Please consider submitting rare artifacts to:\n\nhttps://github.com/cubiclesoft/windows-pe-artifact-library\n\n";
			}

			// Save the manifest.
			$endts = microtime(true);

			$scaninfo = array(
				"path" => str_replace("\\", "/", $path),
				"processed_total" => $totalprocessed,
				"processed_path" => $numprocessed,
				"start" => gmdate("Y-m-d H:i:s", $startts) . " GMT",
				"start_ts" => $startts,
				"end" => gmdate("Y-m-d H:i:s", $endts) . " GMT",
				"end_ts" => $endts,
				"time" => $endts - $startts,
			);

			$manifest["scans"][] = $scaninfo;
			$manifest["artifacts"] = $artifactnamemap;

			file_put_contents($manifestfile, str_replace("    ", "\t", json_encode($manifest, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT)));

			$result = array(
				"success" => true,
				"path" => $scaninfo["path"],
				"processed_total" => $scaninfo["processed_total"],
				"processed_path" => $scaninfo["processed_path"],
				"start" => $scaninfo["start"],
				"end" => $scaninfo["end"],
				"time" => $scaninfo["time"],
				"manifest" => $manifestfile
			);

			CLI::DisplayResult($result);
		}
		else if ($cmd === "missing")
		{
			require_once $rootpath . "/support/artifact_rules.php";

			$namemap = array();
			function MissingArtifacts_BuildNameMap(&$rules)
			{
				global $namemap;

				foreach ($rules as $pkey => $pinfo)
				{
					if (is_string($pkey))  MissingArtifacts_BuildNameMap($pinfo);
					else if (!isset($pinfo["op"]) || $pinfo["op"] !== "hash")
					{
						if (isset($pinfo["prefix"]) && !$pinfo["prefix"])  $namemap[] = $pinfo["name"];
						else
						{
							$namemap[] = "32_pe/32_" . $pinfo["name"];
							$namemap[] = "64_pe/64_" . $pinfo["name"];
						}
					}
				}
			}

			MissingArtifacts_BuildNameMap($g_artifact_rules);

			$result = array(
				"success" => true,
				"missing" => array()
			);

			foreach ($namemap as $filename)
			{
				if (!file_exists($datapath . "/artifacts/" . $filename . ".dat"))  $result["missing"][] = $filename . ".dat";
			}

			CLI::DisplayResult($result);
		}
		else if ($cmd === "origins")
		{
			require_once $rootpath . "/support/win_pe_utils.php";

			$manifestfile = $datapath . "/artifacts/manifest.json";
			if (!is_file($manifestfile))  CLI::DisplayError("Artifact manifest file '" . $manifestfile . "' does not exist.");

			$manifest = @json_decode(file_get_contents($manifestfile), true);
			if (!is_array($manifest) || !isset($manifest["artifacts"]))  CLI::DisplayError("Artifact manifest file '" . $manifestfile . "' is not a valid manifest.");

			CLI::ReinitArgs($args, array("name", "email", "org"));

			$submittername = CLI::GetUserInputWithArgs($args, "name", "Your name", false, "", $suppressoutput);
			$submitteremail = CLI::GetUserInputWithArgs($args, "email", "Contact email address", false, "", $suppressoutput);
			$submitterorg = CLI::GetUserInputWithArgs($args, "org", "Business or organization name", false, "", $suppressoutput);

			$result = array(
				"success" => true,
				"origins" => array()
			);

			foreach ($manifest["artifacts"] as $name => $info)
			{
				// Skip files that sourced from artifacts or already have an associated origin text file.
				$mdfilename = $datapath . "/artifacts/" . $name . ".txt";
				if (strtolower(substr($info["filename"], -4)) === ".dat" || is_file($mdfilename))  continue;

				if (!$suppressoutput)  echo "Processing '" . $name . "'...\n";

				// Attempt to extract useful summary information.
				$fixedinfo = false;
				$verinfo = false;
				$certhashes = false;

				$filename = $datapath . "/artifacts/" . $name . ".dat";
				$filedata = file_get_contents($filename);
				if ($filedata !== file_get_contents($info["filename"]))  continue;

				$winpe = new WinPEFile();
				$result2 = $winpe->Parse($filedata);
				if ($result2["success"])
				{
					$result2 = WinPEUtils::GetVersionResource($winpe);
					if ($result2["success"])
					{
						if (isset($result2["entry"]["fixed"]))  $fixedinfo = $result2["entry"]["fixed"];
						if (isset($result2["entry"]["string_file_info"]["string_tables"]) && count($result2["entry"]["string_file_info"]["string_tables"]))  $verinfo = array_shift($result2["entry"]["string_file_info"]["string_tables"]);
					}

					$result2 = $winpe->CalculateHashes($filedata);
					if ($result2["success"])  $certhashes = $result2;
				}

				$data = $name . "\n";
				$data .= str_repeat("=", strlen($name)) . "\n";
				$data .= "\n";
				$data .= "Source:  " . $info["filename"] . "\n";
				$data .= "Size:  " . number_format(filesize($info["filename"]), 0) . " bytes\n";
				$data .= "Created:  " . gmdate("F j, Y, g:i a", filectime($info["filename"])) . " GMT\n";
				$data .= "Modified:  " . gmdate("F j, Y, g:i a", filemtime($info["filename"])) . " GMT\n";
				$data .= "\n";
				if ($fixedinfo !== false || $verinfo !== false)
				{
					$data .= "File Details\n";
					$data .= "------------\n";
					$data .= "\n";

					if ($fixedinfo !== false)
					{
						$os = array();
						if ($fixedinfo["os"] & 0x00070000 === WinPEFile::VERINFO_VOS_DOS)  $os[] = "DOS";
						if ($fixedinfo["os"] & 0x00070000 === WinPEFile::VERINFO_VOS_OS216)  $os[] = "OS/2-16";
						if ($fixedinfo["os"] & 0x00070000 === WinPEFile::VERINFO_VOS_OS232)  $os[] = "OS/2-32";
						if ($fixedinfo["os"] & 0x00070000 === WinPEFile::VERINFO_VOS_NT)  $os[] = "NT";
						if ($fixedinfo["os"] & 0x00000007 === WinPEFile::VERINFO_VOS__WINDOWS16)  $os[] = "WIN16";
						if ($fixedinfo["os"] & 0x00000007 === WinPEFile::VERINFO_VOS__PM16)  $os[] = "PM-16";
						if ($fixedinfo["os"] & 0x00000007 === WinPEFile::VERINFO_VOS__PM32)  $os[] = "PM-32";
						if ($fixedinfo["os"] & 0x00000007 === WinPEFile::VERINFO_VOS__WINDOWS32)  $os[] = "WIN32";

						if (!count($os))  $os[] = "VOS_UNKNOWN";

						$data .= "Product Version:  " . $fixedinfo["product_ver"] . "\n";
						$data .= "OS:  " . implode("-", $os) . "\n";

						if ($fixedinfo["type"] === WinPEFile::VERINFO_VFT_APP)  $data .= "Type:  Application\n";
						else if ($fixedinfo["type"] === WinPEFile::VERINFO_VFT_DLL)  $data .= "Type:  DLL\n";
						else if ($fixedinfo["type"] === WinPEFile::VERINFO_VFT_DRV)  $data .= "Type:  Device driver\n";
						else if ($fixedinfo["type"] === WinPEFile::VERINFO_VFT_FONT)  $data .= "Type:  Font\n";
						else if ($fixedinfo["type"] === WinPEFile::VERINFO_VFT_VXD)  $data .= "Type:  Virtual device (VxD)\n";
						else if ($fixedinfo["type"] === WinPEFile::VERINFO_VFT_STATIC_LIB)  $data .= "Type:  Static library\n";
						else  $data .= "Type:  UNKNOWN\n";

						$data .= "\n";
					}

					if ($verinfo !== false)
					{
						foreach ($verinfo as $key => $val)  $data .= $key . ":  " . $val . "\n";
						$data .= "\n";
					}
				}
				$data .= "Hashes\n";
				$data .= "------\n";
				$data .= "\n";
				$data .= "Raw MD5:  " . hash("md5", $filedata) . "\n";
				$data .= "Raw SHA1:  " . hash("sha1", $filedata) . "\n";
				$data .= "Raw SHA256:  " . hash("sha256", $filedata) . "\n";
				$data .= "\n";
				if ($certhashes !== false)
				{
					$data .= "Certificate MD5:  " . $certhashes["md5"] . "\n";
					$data .= "Certificate SHA1:  " . $certhashes["sha1"] . "\n";
					$data .= "Certificate SHA256:  " . $certhashes["sha256"] . "\n";
					$data .= "\n";
				}
				$data .= "Similar\n";
				$data .= "-------\n";
				$data .= "\n";
				$data .= "Samples:  " . number_format($info["num"], 0) . "\n";
				$data .= "\n";
				foreach ($info["samples"] as $filename)
				{
					if (strtolower(substr($filename, -4)) !== ".dat" && $filename !== $info["filename"])  $data .= $filename . "\n";
				}
				$data .= "\n";
				$data .= "Submitter\n";
				$data .= "---------\n";
				$data .= "\n";
				$data .= $submittername . "\n";
				$data .= $submitteremail . "\n";
				$data .= $submitterorg . "\n";

				file_put_contents($mdfilename, $data);

				$result["origins"][] = $mdfilename;
			}

			CLI::DisplayResult($result);
		}
	}
	else if ($cmdgroup === "extract")
	{
		// Extract.
		if ($cmd === "info")  CLI::ReinitArgs($args, array("src", "structure", "translate"));
		else if ($cmd === "dos-stub" || $cmd === "version-info" || $cmd === "certificate")  CLI::ReinitArgs($args, array("src"));
		else if ($cmd === "section")  CLI::ReinitArgs($args, array("src", "section"));
		else if ($cmd === "resources")  CLI::ReinitArgs($args, array("src", "type"));

		$found = false;
		do
		{
			$srcfile = CLI::GetUserInputWithArgs($args, "src", "Source file", false, "", $suppressoutput);
			if (!is_file($srcfile))  CLI::DisplayError("The source file '" . $srcfile . "' does not exist or is not a file.", false, false);
			else
			{
				$srcfile = str_replace("\\", "/", realpath($srcfile));

				$result = WinPEFile::ValidateFile($srcfile, false);
				if (!$result["success"])  CLI::DisplayError("Unable to validate '" . $srcfile . "' as a valid executable file.", false, false);
				else  $found = true;
			}
		} while (!$found);

		// Load the file.
		$winpe = new WinPEFile();

		$options = array();
		if ($cmd === "info")  $options["pe_directory_data"] = false;
		else if ($cmd === "dos-stub")  $options["pe_directories"] = "";
		else if ($cmd === "sections")
		{
			$options["pe_section_data"] = true;
			$options["pe_directories"] = "";
		}

		$winpe->Parse(file_get_contents($srcfile), $options);

		if ($cmd === "info")
		{
			require_once $rootpath . "/support/array_utils.php";
			require_once $rootpath . "/support/utf_utils.php";
			require_once $rootpath . "/support/utf8.php";

			$structures = array(
				"all" => "All extracted structures"
			);

			if (isset($winpe->dos_header))  $structures["dos-header"] = "MS-DOS header";
			if (isset($winpe->ne_header))  $structures["ne-header"] = "Win16 header";
			if (isset($winpe->pe_header))  $structures["pe-header"] = "PE header";
			if (isset($winpe->pe_opt_header))  $structures["pe-opt-header"] = "PE optional header";

			if (isset($winpe->pe_data_dir))
			{
				foreach ($winpe->pe_data_dir as $key => $info)
				{
					if ((isset($info["rva"]) && $info["rva"] > 0) || (isset($info["pos"]) && $info["pos"] > 0))
					{
						$structures["pe-data-dir-" . $key] = "PE " . str_replace("_", " ", $key) . " data directory";
					}
				}
			}

			if (isset($winpe->pe_sections))
			{
				foreach ($winpe->pe_sections as $num => $sinfo)
				{
					$structures["pe-section-" . ($num + 1)] = rtrim(str_replace("\x00", " ", $sinfo["name"])) . " section";
				}
			}

			$structure = CLI::GetLimitedUserInputWithArgs($args, "structure", "Structure", "all", "Available structures (no binary data):", $structures, true, $suppressoutput);

			$translate = CLI::GetYesNoUserInputWithArgs($args, "translate", "Translate flags and some values to human-readable strings", "Y", "", $suppressoutput);

			$result = array(
				"success" => true
			);

			// DOS header.
			if (isset($winpe->dos_header) && ($structure === "all" || $structure === "dos-header"))
			{
				$winpe->dos_header["reserved_1"] = bin2hex($winpe->dos_header["reserved_1"]);
				$winpe->dos_header["reserved_2"] = bin2hex($winpe->dos_header["reserved_2"]);

				$result["dos_header"] = $winpe->dos_header;
			}

			// Win16 NE header.
			if (isset($winpe->ne_header) && ($structure === "all" || $structure === "ne-header"))
			{
				if ($translate)
				{
					$flags = array();
					if (($winpe->ne_header["program_flags"] & 0x03) === WinPEFile::WIN16_NE_PROGRAM_FLAGS_DGROUP_NONE)  $flags[] = "DGROUP_NONE";
					if (($winpe->ne_header["program_flags"] & 0x03) === WinPEFile::WIN16_NE_PROGRAM_FLAGS_DGROUP_SINSHARED)  $flags[] = "DGROUP_SINSHARED";
					if (($winpe->ne_header["program_flags"] & 0x03) === WinPEFile::WIN16_NE_PROGRAM_FLAGS_DGROUP_MULTIPLE)  $flags[] = "DGROUP_MULTIPLE";
					if (($winpe->ne_header["program_flags"] & 0x03) === WinPEFile::WIN16_NE_PROGRAM_FLAGS_DGROUP_NULL)  $flags[] = "DGROUP_NULL";
					if ($winpe->ne_header["program_flags"] & WinPEFile::WIN16_NE_PROGRAM_FLAGS_GLOBAL_INIT)  $flags[] = "GLOBAL_INIT";
					if ($winpe->ne_header["program_flags"] & WinPEFile::WIN16_NE_PROGRAM_FLAGS_PROTECTED_MODE_ONLY)  $flags[] = "PROTECTED_MODE_ONLY";
					if ($winpe->ne_header["program_flags"] & WinPEFile::WIN16_NE_PROGRAM_FLAGS_8086)  $flags[] = "8086";
					if ($winpe->ne_header["program_flags"] & WinPEFile::WIN16_NE_PROGRAM_FLAGS_80286)  $flags[] = "80286";
					if ($winpe->ne_header["program_flags"] & WinPEFile::WIN16_NE_PROGRAM_FLAGS_80386)  $flags[] = "80386";
					if ($winpe->ne_header["program_flags"] & WinPEFile::WIN16_NE_PROGRAM_FLAGS_8087)  $flags[] = "8087";

					if (count($flags))  $winpe->ne_header["program_flags"] = implode(" | ", $flags) . " (0x" . sprintf("%02X", $winpe->ne_header["program_flags"]) . ")";

					$flags = array();
					if (($winpe->ne_header["app_flags"] & 0x03) === WinPEFile::WIN16_NE_APP_FLAGS_TYPE_NONE)  $flags[] = "TYPE_NONE";
					if (($winpe->ne_header["app_flags"] & 0x03) === WinPEFile::WIN16_NE_APP_FLAGS_TYPE_FULLSCREEN)  $flags[] = "TYPE_FULLSCREEN";
					if (($winpe->ne_header["app_flags"] & 0x03) === WinPEFile::WIN16_NE_APP_FLAGS_TYPE_WINPMCOMPAT)  $flags[] = "TYPE_WINPMCOMPAT";
					if (($winpe->ne_header["app_flags"] & 0x03) === WinPEFile::WIN16_NE_APP_FLAGS_TYPE_WINPMUSES)  $flags[] = "TYPE_WINPMUSES";
					if ($winpe->ne_header["app_flags"] & WinPEFile::WIN16_NE_APP_FLAGS_OS2_APP)  $flags[] = "OS2_APP";
					if ($winpe->ne_header["app_flags"] & 0x10)  $flags[] = "RESERVED_0x10";
					if ($winpe->ne_header["app_flags"] & WinPEFile::WIN16_NE_APP_FLAGS_IMAGE_ERROR)  $flags[] = "IMAGE_ERROR";
					if ($winpe->ne_header["app_flags"] & WinPEFile::WIN16_NE_APP_FLAGS_NON_CONFORM)  $flags[] = "NON_CONFORM";
					if ($winpe->ne_header["app_flags"] & WinPEFile::WIN16_NE_APP_FLAGS_DLL)  $flags[] = "DLL";

					if (count($flags))  $winpe->ne_header["app_flags"] = implode(" | ", $flags) . " (0x" . sprintf("%02X", $winpe->ne_header["app_flags"]) . ")";

					if (isset(WinPEFile::$ne_target_oses[$winpe->ne_header["target_os"]]))  $winpe->ne_header["target_os"] = WinPEFile::$ne_target_oses[$winpe->ne_header["target_os"]];

					$flags = array();
					if ($winpe->ne_header["os2_exe_flags"] & WinPEFile::WIN16_NE_OS2_EXE_FLAGS_LFN)  $flags[] = "LONG_FILE_NAMES";
					if ($winpe->ne_header["os2_exe_flags"] & WinPEFile::WIN16_NE_OS2_EXE_FLAGS_PROTECTED_MODE)  $flags[] = "PROTECTED_MODE";
					if ($winpe->ne_header["os2_exe_flags"] & WinPEFile::WIN16_NE_OS2_EXE_FLAGS_PROPORTIONAL_FONTS)  $flags[] = "PROPORTIONAL_FONTS";
					if ($winpe->ne_header["os2_exe_flags"] & WinPEFile::WIN16_NE_OS2_EXE_FLAGS_GANGLOAD_AREA)  $flags[] = "GANGLOAD_AREA";

					if (count($flags))  $winpe->ne_header["os2_exe_flags"] = implode(" | ", $flags) . " (0x" . sprintf("%02X", $winpe->ne_header["os2_exe_flags"]) . ")";
				}

				$result["ne_header"] = $winpe->ne_header;
			}

			// PE header.
			if (isset($winpe->pe_header) && ($structure === "all" || $structure === "pe-header"))
			{
				if ($translate)
				{
					if (isset(WinPEFile::$machine_types[$winpe->pe_header["machine_type"]]))  $winpe->pe_header["machine_type"] = WinPEFile::$machine_types[$winpe->pe_header["machine_type"]] . " (0x" . sprintf("%04X", $winpe->pe_header["machine_type"]) . ")";

					$flags = array();
					if ($winpe->pe_header["flags"] & WinPEFile::IMAGE_FILE_RELOCS_STRIPPED)  $flags[] = "RELOCS_STRIPPED";
					if ($winpe->pe_header["flags"] & WinPEFile::IMAGE_FILE_EXECUTABLE_IMAGE)  $flags[] = "EXECUTABLE_IMAGE";
					if ($winpe->pe_header["flags"] & WinPEFile::IMAGE_FILE_LINE_NUMS_STRIPPED)  $flags[] = "LINE_NUMS_STRIPPED";
					if ($winpe->pe_header["flags"] & WinPEFile::IMAGE_FILE_LOCAL_SYMS_STRIPPED)  $flags[] = "LOCAL_SYMS_STRIPPED";
					if ($winpe->pe_header["flags"] & WinPEFile::IMAGE_FILE_AGGRESSIVE_WS_TRIM)  $flags[] = "AGGRESSIVE_WS_TRIM";
					if ($winpe->pe_header["flags"] & WinPEFile::IMAGE_FILE_LARGE_ADDRESS_AWARE)  $flags[] = "LARGE_ADDRESS_AWARE";
					if ($winpe->pe_header["flags"] & 0x0040)  $flags[] = "RESERVED_0x0040";
					if ($winpe->pe_header["flags"] & WinPEFile::IMAGE_FILE_BYTES_REVERSED_LO)  $flags[] = "BYTES_REVERSED_LO";
					if ($winpe->pe_header["flags"] & WinPEFile::IMAGE_FILE_32BIT_MACHINE)  $flags[] = "32BIT_MACHINE";
					if ($winpe->pe_header["flags"] & WinPEFile::IMAGE_FILE_DEBUG_STRIPPED)  $flags[] = "DEBUG_STRIPPED";
					if ($winpe->pe_header["flags"] & WinPEFile::IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP)  $flags[] = "REMOVABLE_RUN_FROM_SWAP";
					if ($winpe->pe_header["flags"] & WinPEFile::IMAGE_FILE_NET_RUN_FROM_SWAP)  $flags[] = "NET_RUN_FROM_SWAP";
					if ($winpe->pe_header["flags"] & WinPEFile::IMAGE_FILE_SYSTEM)  $flags[] = "SYSTEM";
					if ($winpe->pe_header["flags"] & WinPEFile::IMAGE_FILE_DLL)  $flags[] = "DLL";
					if ($winpe->pe_header["flags"] & WinPEFile::IMAGE_FILE_UP_SYSTEM_ONLY)  $flags[] = "UP_SYSTEM_ONLY";
					if ($winpe->pe_header["flags"] & WinPEFile::IMAGE_FILE_BYTES_REVERSED_HI)  $flags[] = "BYTES_REVERSED_HI";

					if (count($flags))  $winpe->pe_header["flags"] = implode(" | ", $flags) . " (0x" . sprintf("%04X", $winpe->pe_header["flags"]) . ")";
				}

				$winpe->pe_header["signature"] = "PE  ";

				$result["pe_header"] = $winpe->pe_header;
			}

			// PE optional header.
			if (isset($winpe->pe_opt_header) && ($structure === "all" || $structure === "pe-opt-header"))
			{
				if ($translate)
				{
					if (isset(WinPEFile::$opt_header_signatures[$winpe->pe_opt_header["signature"]]))  $winpe->pe_opt_header["signature"] = WinPEFile::$opt_header_signatures[$winpe->pe_opt_header["signature"]];
					if (isset(WinPEFile::$image_subsystems[$winpe->pe_opt_header["subsystem"]]))  $winpe->pe_opt_header["subsystem"] = WinPEFile::$image_subsystems[$winpe->pe_opt_header["subsystem"]];

					$flags = array();
					if ($winpe->pe_opt_header["dll_characteristics"] & 0x0001)  $flags[] = "RESERVED_0x0001";
					if ($winpe->pe_opt_header["dll_characteristics"] & 0x0002)  $flags[] = "RESERVED_0x0002";
					if ($winpe->pe_opt_header["dll_characteristics"] & 0x0004)  $flags[] = "RESERVED_0x0004";
					if ($winpe->pe_opt_header["dll_characteristics"] & 0x0008)  $flags[] = "RESERVED_0x0008";
					if ($winpe->pe_opt_header["dll_characteristics"] & 0x0010)  $flags[] = "UNKNOWN_0x0010";
					if ($winpe->pe_opt_header["dll_characteristics"] & 0x0020)  $flags[] = "UNKNOWN_0x0020";
					if ($winpe->pe_opt_header["dll_characteristics"] & WinPEFile::IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE)  $flags[] = "DYNAMIC_BASE";
					if ($winpe->pe_opt_header["dll_characteristics"] & WinPEFile::IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY)  $flags[] = "FORCE_INTEGRITY";
					if ($winpe->pe_opt_header["dll_characteristics"] & WinPEFile::IMAGE_DLL_CHARACTERISTICS_NX_COMPAT)  $flags[] = "NX_COMPAT";
					if ($winpe->pe_opt_header["dll_characteristics"] & WinPEFile::IMAGE_DLL_CHARACTERISTICS_NO_ISOLATION)  $flags[] = "NO_ISOLATION";
					if ($winpe->pe_opt_header["dll_characteristics"] & WinPEFile::IMAGE_DLL_CHARACTERISTICS_NO_SEH)  $flags[] = "NO_SEH";
					if ($winpe->pe_opt_header["dll_characteristics"] & WinPEFile::IMAGE_DLL_CHARACTERISTICS_NO_BIND)  $flags[] = "NO_BIND";
					if ($winpe->pe_opt_header["dll_characteristics"] & 0x1000)  $flags[] = "RESERVED_0x1000";
					if ($winpe->pe_opt_header["dll_characteristics"] & WinPEFile::IMAGE_DLL_CHARACTERISTICS_WDM_DRIVER)  $flags[] = "WDM_DRIVER";
					if ($winpe->pe_opt_header["dll_characteristics"] & 0x4000)  $flags[] = "RESERVED_0x4000";
					if ($winpe->pe_opt_header["dll_characteristics"] & WinPEFile::IMAGE_DLL_CHARACTERISTICS_TERMINAL_SERVER_AWARE)  $flags[] = "TERMINAL_SERVER_AWARE";

					if (count($flags))  $winpe->pe_opt_header["dll_characteristics"] = implode(" | ", $flags) . " (0x" . sprintf("%04X", $winpe->pe_opt_header["dll_characteristics"]) . ")";
				}

				if (is_string($winpe->pe_opt_header["image_base"]))  $winpe->pe_opt_header["image_base"] = bin2hex($winpe->pe_opt_header["image_base"]);
				if (is_string($winpe->pe_opt_header["stack_reserve_size"]))  $winpe->pe_opt_header["stack_reserve_size"] = bin2hex($winpe->pe_opt_header["stack_reserve_size"]);
				if (is_string($winpe->pe_opt_header["stack_commit_size"]))  $winpe->pe_opt_header["stack_commit_size"] = bin2hex($winpe->pe_opt_header["stack_commit_size"]);
				if (is_string($winpe->pe_opt_header["heap_reserve_size"]))  $winpe->pe_opt_header["heap_reserve_size"] = bin2hex($winpe->pe_opt_header["heap_reserve_size"]);
				if (is_string($winpe->pe_opt_header["heap_commit_size"]))  $winpe->pe_opt_header["heap_commit_size"] = bin2hex($winpe->pe_opt_header["heap_commit_size"]);

				$result["pe_opt_header"] = $winpe->pe_opt_header;
			}

			// PE data directories.
			if (isset($winpe->pe_data_dir) && $winpe->pe_data_dir["exports"]["rva"] && $winpe->pe_data_dir["exports"]["size"] && ($structure === "all" || $structure === "pe-data-dir-exports"))
			{
				if (isset($winpe->pe_data_dir["exports"]["namemap"]))
				{
					foreach ($winpe->pe_data_dir["exports"]["namemap"] as $key => $num)
					{
						if (isset($winpe->pe_data_dir["exports"]["addresses"][$num]))
						{
							if ($winpe->pe_data_dir["exports"]["addresses"][$num]["type"] === "forward")  $winpe->pe_data_dir["exports"]["addresses"][$num]["to"] = $winpe->pe_data_dir["exports"]["addresses"][$num]["name"];

							$winpe->pe_data_dir["exports"]["addresses"][$num]["name"] = $key;
						}
					}
				}

				$result["pe_data_dir_exports"] = $winpe->pe_data_dir["exports"];
			}

			if (isset($winpe->pe_data_dir) && $winpe->pe_data_dir["imports"]["rva"] && $winpe->pe_data_dir["imports"]["size"] && ($structure === "all" || $structure === "pe-data-dir-imports"))
			{
				if (isset($winpe->pe_data_dir["imports"]["dir_entries"]))
				{
					foreach ($winpe->pe_data_dir["imports"]["dir_entries"] as $num => $entry)
					{
						if (isset($entry["name"]) && is_string($entry["name"]))  $entry["name"] = UTF8::MakeValid($entry["name"]);

						foreach ($entry["imports"] as $num2 => $import)
						{
							if ($import["type"] === "named")  $entry["imports"][$num2]["name"] = UTF8::MakeValid($import["name"]);
						}

						$winpe->pe_data_dir["imports"]["dir_entries"][$num] = $entry;
					}
				}

				$result["pe_data_dir_imports"] = $winpe->pe_data_dir["imports"];
			}

			if (isset($winpe->pe_data_dir) && $winpe->pe_data_dir["resources"]["rva"] && $winpe->pe_data_dir["resources"]["size"] && ($structure === "all" || $structure === "pe-data-dir-resources"))
			{
				if (isset($winpe->pe_data_dir["resources"]["dir_entries"]))
				{
					foreach ($winpe->pe_data_dir["resources"]["dir_entries"] as $num => $entry)
					{
						if (isset($entry["name"]) && is_string($entry["name"]))  $entry["name"] = UTFUtils::Convert($entry["name"], UTFUtils::UTF16_LE, UTFUtils::UTF8);

						if ($translate)
						{
							if (isset($entry["id"]) && $entry["parent"] === 0 && isset(WinPEFile::$resource_types[$entry["id"]]))  $entry["id"] = WinPEFile::$resource_types[$entry["id"]] . " (" . $entry["id"] . ")";

							if ($entry["parent"] !== false)  $entry = ArrayUtils::InsertAfterKey($entry, "subtype", array("path" => (isset($winpe->pe_data_dir["resources"]["dir_entries"][$entry["parent"]]["path"]) ? $winpe->pe_data_dir["resources"]["dir_entries"][$entry["parent"]]["path"] . " | " : "") . (isset($entry["id"]) ? $entry["id"] : $entry["name"])));
						}

						$winpe->pe_data_dir["resources"]["dir_entries"][$num] = $entry;
					}
				}

				$result["pe_data_dir_resources"] = $winpe->pe_data_dir["resources"];
			}

			if (isset($winpe->pe_data_dir) && $winpe->pe_data_dir["exceptions"]["rva"] && $winpe->pe_data_dir["exceptions"]["size"] && ($structure === "all" || $structure === "pe-data-dir-exceptions"))
			{
				$result["pe_data_dir_exceptions"] = $winpe->pe_data_dir["exceptions"];
			}

			if (isset($winpe->pe_data_dir) && $winpe->pe_data_dir["certificates"]["pos"] && $winpe->pe_data_dir["certificates"]["size"] && ($structure === "all" || $structure === "pe-data-dir-certificates"))
			{
				if ($translate && isset($winpe->pe_data_dir["certificates"]["certs"]))
				{
					foreach ($winpe->pe_data_dir["certificates"]["certs"] as $num => $entry)
					{
						if ($entry["revision"] === WinPEFile::WIN_CERT_REVISION_1_0)  $entry["revision"] = "1.0 (0x0100)";
						if ($entry["revision"] === WinPEFile::WIN_CERT_REVISION_2_0)  $entry["revision"] = "2.0 (0x0200)";

						if ($entry["cert_type"] === WinPEFile::WIN_CERT_TYPE_X509)  $entry["cert_type"] = "X.509 (0x0001)";
						if ($entry["cert_type"] === WinPEFile::WIN_CERT_TYPE_PKCS_SIGNED_DATA)  $entry["cert_type"] = "PKCS#7 (0x0002)";
						if ($entry["cert_type"] === WinPEFile::WIN_CERT_TYPE_TS_STACK_SIGNED)  $entry["cert_type"] = "Terminal Server Protocol Stack Certificate signing (0x0004)";
					}

					$winpe->pe_data_dir["certificates"]["certs"][$num] = $entry;
				}

				$result["pe_data_dir_certificates"] = $winpe->pe_data_dir["certificates"];
			}

			if (isset($winpe->pe_data_dir) && $winpe->pe_data_dir["base_relocations"]["rva"] && $winpe->pe_data_dir["base_relocations"]["size"] && ($structure === "all" || $structure === "pe-data-dir-base_relocations"))
			{
				if ($translate && isset($winpe->pe_data_dir["base_relocations"]["blocks"]))
				{
					foreach ($winpe->pe_data_dir["base_relocations"]["blocks"] as $num => $block)
					{
						foreach ($block["offsets"] as $num2 => $entry)
						{
							if ($entry["type"] === WinPEFile::IMAGE_REL_BASED_ABSOLUTE)  $entry["type"] = "ABSOLUTE (0)";
							if ($entry["type"] === WinPEFile::IMAGE_REL_BASED_HIGH)  $entry["type"] = "HIGH (1)";
							if ($entry["type"] === WinPEFile::IMAGE_REL_BASED_LOW)  $entry["type"] = "LOW (2)";
							if ($entry["type"] === WinPEFile::IMAGE_REL_BASED_HIGHLOW)  $entry["type"] = "HIGHLOW (3)";
							if ($entry["type"] === WinPEFile::IMAGE_REL_BASED_HIGHADJ)  $entry["type"] = "HIGHADJ (4)";
							if ($entry["type"] === WinPEFile::IMAGE_REL_BASED_MIPS_JMPADDR)  $entry["type"] = "MIPS_JMPADDR/ARM_MOV32/RISCV_HIGH20 (5)";
							if ($entry["type"] === 6)  $entry["type"] = "RESERVED_6 (6)";
							if ($entry["type"] === WinPEFile::IMAGE_REL_BASED_THUMB_MOV32)  $entry["type"] = "THUMB_MOV32/RISCV_LOW12I (7)";
							if ($entry["type"] === WinPEFile::IMAGE_REL_BASED_RISCV_LOW12S)  $entry["type"] = "RISCV_LOW12S (8)";
							if ($entry["type"] === WinPEFile::IMAGE_REL_BASED_MIPS_JMPADDR16)  $entry["type"] = "MIPS_JMPADDR16/IA64_IMM64 (9)";
							if ($entry["type"] === WinPEFile::IMAGE_REL_BASED_DIR64)  $entry["type"] = "DIR64 (10)";
							if ($entry["type"] === WinPEFile::IMAGE_REL_BASED_HIGH3ADJ)  $entry["type"] = "HIGH3ADJ (11)";

							$block["offsets"][$num2] = $entry;
						}

						$winpe->pe_data_dir["base_relocations"]["blocks"][$num] = $block;
					}
				}

				$result["pe_data_dir_base_relocations"] = $winpe->pe_data_dir["base_relocations"];
			}

			if (isset($winpe->pe_data_dir) && $winpe->pe_data_dir["debug"]["rva"] && $winpe->pe_data_dir["debug"]["size"] && ($structure === "all" || $structure === "pe-data-dir-debug"))
			{
				if ($translate && isset($winpe->pe_data_dir["debug"]["dir_entries"]))
				{
					foreach ($winpe->pe_data_dir["debug"]["dir_entries"] as $num => $entry)
					{
						if ($entry["type"] === WinPEFile::IMAGE_DEBUG_TYPE_UNKNOWN)  $entry["type"] = "UNKNOWN (0)";
						if ($entry["type"] === WinPEFile::IMAGE_DEBUG_TYPE_COFF)  $entry["type"] = "COFF (1)";
						if ($entry["type"] === WinPEFile::IMAGE_DEBUG_TYPE_CODEVIEW)  $entry["type"] = "CODEVIEW (2)";
						if ($entry["type"] === WinPEFile::IMAGE_DEBUG_TYPE_FPO)  $entry["type"] = "FPO (3)";
						if ($entry["type"] === WinPEFile::IMAGE_DEBUG_TYPE_MISC)  $entry["type"] = "MISC (4)";
						if ($entry["type"] === WinPEFile::IMAGE_DEBUG_TYPE_EXCEPTION)  $entry["type"] = "EXCEPTION (5)";
						if ($entry["type"] === WinPEFile::IMAGE_DEBUG_TYPE_FIXUP)  $entry["type"] = "FIXUP (6)";
						if ($entry["type"] === WinPEFile::IMAGE_DEBUG_TYPE_OMAP_TO_SRC)  $entry["type"] = "OMAP_TO_SRC (7)";
						if ($entry["type"] === WinPEFile::IMAGE_DEBUG_TYPE_OMAP_FROM_SRC)  $entry["type"] = "OMAP_FROM_SRC (8)";
						if ($entry["type"] === WinPEFile::IMAGE_DEBUG_TYPE_BORLAND)  $entry["type"] = "BORLAND (9)";
						if ($entry["type"] === 10)  $entry["type"] = "RESERVED_10 (10)";
						if ($entry["type"] === WinPEFile::IMAGE_DEBUG_TYPE_CLSID)  $entry["type"] = "CLSID (11)";
						if ($entry["type"] === WinPEFile::IMAGE_DEBUG_TYPE_REPRO)  $entry["type"] = "REPRO (16)";
						if ($entry["type"] === WinPEFile::IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS)  $entry["type"] = "EX_DLLCHARACTERISTICS (20)";

						$winpe->pe_data_dir["debug"]["dir_entries"][$num] = $entry;
					}
				}

				$result["pe_data_dir_debug"] = $winpe->pe_data_dir["debug"];
			}

			if (isset($winpe->pe_data_dir) && $winpe->pe_data_dir["architecture"]["rva"] && $winpe->pe_data_dir["architecture"]["size"] && ($structure === "all" || $structure === "pe-data-dir-architecture"))
			{
				$result["pe_data_dir_architecture"] = $winpe->pe_data_dir["architecture"];
			}

			if (isset($winpe->pe_data_dir) && $winpe->pe_data_dir["global_ptr"]["rva"] && $winpe->pe_data_dir["global_ptr"]["size"] && ($structure === "all" || $structure === "pe-data-dir-global_ptr"))
			{
				$result["pe_data_dir_global_ptr"] = $winpe->pe_data_dir["global_ptr"];
			}

			if (isset($winpe->pe_data_dir) && $winpe->pe_data_dir["tls"]["rva"] && $winpe->pe_data_dir["tls"]["size"] && ($structure === "all" || $structure === "pe-data-dir-tls"))
			{
				if (isset($winpe->pe_data_dir["tls"]["dir"]))
				{
					if (is_string($winpe->pe_data_dir["tls"]["dir"]["data_start_va"]))  $winpe->pe_data_dir["tls"]["dir"]["data_start_va"] = bin2hex($winpe->pe_data_dir["tls"]["dir"]["data_start_va"]);
					if (is_string($winpe->pe_data_dir["tls"]["dir"]["data_end_va"]))  $winpe->pe_data_dir["tls"]["dir"]["data_end_va"] = bin2hex($winpe->pe_data_dir["tls"]["dir"]["data_end_va"]);
					if (is_string($winpe->pe_data_dir["tls"]["dir"]["index_addr"]))  $winpe->pe_data_dir["tls"]["dir"]["index_addr"] = bin2hex($winpe->pe_data_dir["tls"]["dir"]["index_addr"]);
					if (is_string($winpe->pe_data_dir["tls"]["dir"]["callbacks_addr"]))  $winpe->pe_data_dir["tls"]["dir"]["callbacks_addr"] = bin2hex($winpe->pe_data_dir["tls"]["dir"]["callbacks_addr"]);
				}

				$result["pe_data_dir_tls"] = $winpe->pe_data_dir["tls"];
			}

			if (isset($winpe->pe_data_dir) && $winpe->pe_data_dir["load_config"]["rva"] && $winpe->pe_data_dir["load_config"]["size"] && ($structure === "all" || $structure === "pe-data-dir-load_config"))
			{
				if (isset($winpe->pe_data_dir["load_config"]["dir"]))
				{
					foreach ($winpe->pe_data_dir["load_config"]["dir"] as $key => $val)
					{
						if (is_string($val))  $winpe->pe_data_dir["load_config"]["dir"][$key] = bin2hex($val);
					}
				}

				$result["pe_data_dir_load_config"] = $winpe->pe_data_dir["load_config"];
			}

			if (isset($winpe->pe_data_dir) && $winpe->pe_data_dir["bound_imports"]["pos"] && $winpe->pe_data_dir["bound_imports"]["size"] && ($structure === "all" || $structure === "pe-data-dir-bound_imports"))
			{
				if (isset($winpe->pe_data_dir["bound_imports"]["dir_entries"]))
				{
					foreach ($winpe->pe_data_dir["bound_imports"]["dir_entries"] as $num => $entry)
					{
						$entry["name"] = UTF8::MakeValid($entry["name"]);

						$winpe->pe_data_dir["bound_imports"]["dir_entries"][$num] = $entry;
					}
				}

				$result["pe_data_dir_bound_imports"] = $winpe->pe_data_dir["bound_imports"];
			}

			if (isset($winpe->pe_data_dir) && $winpe->pe_data_dir["iat"]["rva"] && $winpe->pe_data_dir["iat"]["size"] && ($structure === "all" || $structure === "pe-data-dir-iat"))
			{
				if (isset($winpe->pe_data_dir["iat"]["data"]))  $winpe->pe_data_dir["iat"]["data"] = bin2hex($winpe->pe_data_dir["iat"]["data"]);

				$result["pe_data_dir_iat"] = $winpe->pe_data_dir["iat"];
			}

			if (isset($winpe->pe_data_dir) && $winpe->pe_data_dir["delay_imports"]["rva"] && $winpe->pe_data_dir["delay_imports"]["size"] && ($structure === "all" || $structure === "pe-data-dir-delay_imports"))
			{
				if (isset($winpe->pe_data_dir["delay_imports"]["dir_entries"]))
				{
					foreach ($winpe->pe_data_dir["delay_imports"]["dir_entries"] as $num => $entry)
					{
						if (isset($entry["name"]) && is_string($entry["name"]))  $entry["name"] = UTF8::MakeValid($entry["name"]);

						foreach ($entry["imports"] as $num2 => $import)
						{
							if ($import["type"] === "named")  $entry["imports"][$num2]["name"] = UTF8::MakeValid($import["name"]);
						}

						$winpe->pe_data_dir["delay_imports"]["dir_entries"][$num] = $entry;
					}
				}

				$result["pe_data_dir_delay_imports"] = $winpe->pe_data_dir["delay_imports"];
			}

			if (isset($winpe->pe_data_dir) && $winpe->pe_data_dir["clr_runtime_header"]["rva"] && $winpe->pe_data_dir["clr_runtime_header"]["size"] && ($structure === "all" || $structure === "pe-data-dir-clr_runtime_header"))
			{
				$result["pe_data_dir_clr_runtime_header"] = $winpe->pe_data_dir["clr_runtime_header"];
			}

			// PE sections.
			if (isset($winpe->pe_sections))
			{
				foreach ($winpe->pe_sections as $num => $sinfo)
				{
					if ($structure === "all" || $structure === "pe-section-" . ($num + 1))
					{
						if ($translate)
						{
							$flags = array();
							if ($sinfo["flags"] === 0x00000000)  $flags[] = "RESERVED_0x00000000";
							if ($sinfo["flags"] & 0x00000001)  $flags[] = "RESERVED_0x00000001";
							if ($sinfo["flags"] & 0x00000002)  $flags[] = "RESERVED_0x00000002";
							if ($sinfo["flags"] & 0x00000004)  $flags[] = "RESERVED_0x00000004";
							if ($sinfo["flags"] & WinPEFile::IMAGE_SCN_TYPE_NO_PAD)  $flags[] = "TYPE_NO_PAD";
							if ($sinfo["flags"] & 0x00000010)  $flags[] = "RESERVED_0x00000010";
							if ($sinfo["flags"] & WinPEFile::IMAGE_SCN_CNT_CODE)  $flags[] = "CNT_CODE";
							if ($sinfo["flags"] & WinPEFile::IMAGE_SCN_CNT_INITIALIZED_DATA)  $flags[] = "CNT_INITIALIZED_DATA";
							if ($sinfo["flags"] & WinPEFile::IMAGE_SCN_CNT_UNINITIALIZED_DATA)  $flags[] = "CNT_UNINITIALIZED_DATA";
							if ($sinfo["flags"] & WinPEFile::IMAGE_SCN_LNK_OTHER)  $flags[] = "LNK_OTHER";
							if ($sinfo["flags"] & WinPEFile::IMAGE_SCN_LNK_INFO)  $flags[] = "LNK_INFO";
							if ($sinfo["flags"] & 0x00000400)  $flags[] = "RESERVED_0x00000400";
							if ($sinfo["flags"] & WinPEFile::IMAGE_SCN_LNK_REMOVE)  $flags[] = "LNK_REMOVE";
							if ($sinfo["flags"] & WinPEFile::IMAGE_SCN_LNK_COMDAT)  $flags[] = "LNK_COMDAT";
							if ($sinfo["flags"] & 0x00002000)  $flags[] = "RESERVED_0x00002000";
							if ($sinfo["flags"] & WinPEFile::IMAGE_SCN_NO_DEFER_SPEC_EXC)  $flags[] = "NO_DEFER_SPEC_EXC";
							if ($sinfo["flags"] & WinPEFile::IMAGE_SCN_GPREL)  $flags[] = "GPREL";
							if ($sinfo["flags"] & 0x00010000)  $flags[] = "RESERVED_0x00010000";
							if ($sinfo["flags"] & WinPEFile::IMAGE_SCN_MEM_PURGEABLE)  $flags[] = "MEM_PURGEABLE";
							if ($sinfo["flags"] & WinPEFile::IMAGE_SCN_MEM_16BIT)  $flags[] = "MEM_16BIT";
							if ($sinfo["flags"] & WinPEFile::IMAGE_SCN_MEM_LOCKED)  $flags[] = "MEM_LOCKED";
							if ($sinfo["flags"] & WinPEFile::IMAGE_SCN_MEM_PRELOAD)  $flags[] = "MEM_PRELOAD";
							if (($sinfo["flags"] & 0x00F00000) === WinPEFile::IMAGE_SCN_ALIGN_1BYTES)  $flags[] = "ALIGN_1BYTES";
							if (($sinfo["flags"] & 0x00F00000) === WinPEFile::IMAGE_SCN_ALIGN_2BYTES)  $flags[] = "ALIGN_2BYTES";
							if (($sinfo["flags"] & 0x00F00000) === WinPEFile::IMAGE_SCN_ALIGN_4BYTES)  $flags[] = "ALIGN_4BYTES";
							if (($sinfo["flags"] & 0x00F00000) === WinPEFile::IMAGE_SCN_ALIGN_8BYTES)  $flags[] = "ALIGN_8BYTES";
							if (($sinfo["flags"] & 0x00F00000) === WinPEFile::IMAGE_SCN_ALIGN_16BYTES)  $flags[] = "ALIGN_16BYTES";
							if (($sinfo["flags"] & 0x00F00000) === WinPEFile::IMAGE_SCN_ALIGN_32BYTES)  $flags[] = "ALIGN_32BYTES";
							if (($sinfo["flags"] & 0x00F00000) === WinPEFile::IMAGE_SCN_ALIGN_64BYTES)  $flags[] = "ALIGN_64BYTES";
							if (($sinfo["flags"] & 0x00F00000) === WinPEFile::IMAGE_SCN_ALIGN_128BYTES)  $flags[] = "ALIGN_128BYTES";
							if (($sinfo["flags"] & 0x00F00000) === WinPEFile::IMAGE_SCN_ALIGN_256BYTES)  $flags[] = "ALIGN_256BYTES";
							if (($sinfo["flags"] & 0x00F00000) === WinPEFile::IMAGE_SCN_ALIGN_512BYTES)  $flags[] = "ALIGN_512BYTES";
							if (($sinfo["flags"] & 0x00F00000) === WinPEFile::IMAGE_SCN_ALIGN_1024BYTES)  $flags[] = "ALIGN_1024BYTES";
							if (($sinfo["flags"] & 0x00F00000) === WinPEFile::IMAGE_SCN_ALIGN_2048BYTES)  $flags[] = "ALIGN_2048BYTES";
							if (($sinfo["flags"] & 0x00F00000) === WinPEFile::IMAGE_SCN_ALIGN_4096BYTES)  $flags[] = "ALIGN_4096BYTES";
							if (($sinfo["flags"] & 0x00F00000) === WinPEFile::IMAGE_SCN_ALIGN_8192BYTES)  $flags[] = "ALIGN_8192BYTES";
							if (($sinfo["flags"] & 0x00F00000) === 0x00F00000)  $flags[] = "RESERVED_0x00F00000";
							if ($sinfo["flags"] & WinPEFile::IMAGE_SCN_LNK_NRELOC_OVFL)  $flags[] = "LNK_NRELOC_OVFL";
							if ($sinfo["flags"] & WinPEFile::IMAGE_SCN_MEM_DISCARDABLE)  $flags[] = "MEM_DISCARDABLE";
							if ($sinfo["flags"] & WinPEFile::IMAGE_SCN_MEM_NOT_CACHED)  $flags[] = "MEM_NOT_CACHED";
							if ($sinfo["flags"] & WinPEFile::IMAGE_SCN_MEM_NOT_PAGED)  $flags[] = "MEM_NOT_PAGED";
							if ($sinfo["flags"] & WinPEFile::IMAGE_SCN_MEM_SHARED)  $flags[] = "MEM_SHARED";
							if ($sinfo["flags"] & WinPEFile::IMAGE_SCN_MEM_EXECUTE)  $flags[] = "MEM_EXECUTE";
							if ($sinfo["flags"] & WinPEFile::IMAGE_SCN_MEM_READ)  $flags[] = "MEM_READ";
							if ($sinfo["flags"] & (int)WinPEFile::IMAGE_SCN_MEM_WRITE)  $flags[] = "MEM_WRITE";

							if (count($flags))  $sinfo["flags"] = implode(" | ", $flags) . " (0x" . sprintf("%08X", $sinfo["flags"]) . ")";
						}

						$sinfo["name"] = UTF8::MakeValid(rtrim(str_replace("\x00", " ", $sinfo["name"])));

						$result["pe_section_" . ($num + 1)] = $sinfo;
					}
				}
			}

			CLI::DisplayResult($result);
		}
		else if ($cmd === "dos-stub")
		{
			$destfile = $datapath . "/extracts/" . substr($srcfile, strrpos($srcfile, "/") + 1);
			@mkdir($destfile, 0770);

			$destfile .=  "/dos-stub.dat";

			if (file_put_contents($destfile, $winpe->dos_stub) === false)  CLI::DisplayResult(array("success" => false, "error" => "Unable to write MS-DOS stub to '" . $destfile . "'.", "errorcode" => "write_failed"));

			$result = array(
				"success" => true,
				"destfile" => $destfile
			);

			CLI::DisplayResult($result);
		}
		else if ($cmd === "sections")
		{
			$destfile = $datapath . "/extracts/" . substr($srcfile, strrpos($srcfile, "/") + 1);
			@mkdir($destfile, 0770);

			$result = array(
				"success" => true,
				"files" => array()
			);

			if (isset($winpe->pe_sections))
			{
				foreach ($winpe->pe_sections as $num => $sinfo)
				{
					$destfile2 = $destfile . "/pe_section_" . ($num + 1) . "_" . str_replace(" ", "_", trim(preg_replace('/[^A-Za-z0-9]/', " ", $sinfo["name"]))) . "_0x" . sprintf("%08X", $sinfo["rva"]) . ".dat";

					if (file_put_contents($destfile2, $sinfo["data"]) === false)  CLI::DisplayResult(array("success" => false, "error" => "Unable to write section data to '" . $destfile2 . "'.", "errorcode" => "write_failed"));

					$result["files"][] = $destfile2;
				}
			}

			CLI::DisplayResult($result);
		}
		else if ($cmd === "resources")
		{
			require_once $rootpath . "/support/win_ico.php";

			$destfile = $datapath . "/extracts/" . substr($srcfile, strrpos($srcfile, "/") + 1);
			@mkdir($destfile, 0770);

			$result = array(
				"success" => true,
				"files" => array()
			);

			if (isset($winpe->pe_data_dir["resources"]["dir_entries"]))
			{
				foreach ($winpe->pe_data_dir["resources"]["dir_entries"] as $num => $entry)
				{
					if ($entry["type"] !== "leaf" || !isset($entry["data"]))  continue;

					$parents = array();
					$num2 = $num;
					while (($num2 = $winpe->pe_data_dir["resources"]["dir_entries"][$num2]["parent"]) !== 0)
					{
						array_unshift($parents, $num2);
					}

					if (!count($parents))  continue;

					$filename = "res_";
					$ext = ".dat";

					$rootentry = $winpe->pe_data_dir["resources"]["dir_entries"][$parents[0]];
					if (!isset($rootentry["id"]))  $filename .= "named_";
					else
					{
						switch ($rootentry["id"])
						{
							case WinPEFile::RT_CURSOR:
							case WinPEFile::RT_ICON:
							{
								if ($rootentry["id"] === WinPEFile::RT_CURSOR)  $filename .= "cursor_";
								else  $filename .= "icon_";

								// Check data for known signatures.  Only PNG and headerless BMP are the formats supported by ICO/CUR.
								// PNG signature:  \x89PNG\r\n\x1A\n
								if (substr($entry["data"], 0, 8) === "\x89PNG\r\n\x1A\n")
								{
									file_put_contents($destfile . "/" . $filename . $num . ".png", $entry["data"]);

									$result["files"][] = $destfile . "/" . $filename . $num . ".png";
								}
								else
								{
									$result2 = WinICO::ConvertICOBMPToPNG($entry["data"]);
									if ($result2["success"])
									{
										file_put_contents($destfile . "/" . $filename . $num . ".bmp", $result2["bmp_data"]);
										file_put_contents($destfile . "/" . $filename . $num . ".png", $result2["png_data"]);

										$result["files"][] = $destfile . "/" . $filename . $num . ".bmp";
										$result["files"][] = $destfile . "/" . $filename . $num . ".png";
									}
								}

								break;
							}
							case WinPEFile::RT_BITMAP:  $filename .= "bitmap_";  $ext = ".bmp";  break;
							case WinPEFile::RT_MENU:  $filename .= "menu_";  break;
							case WinPEFile::RT_DIALOG:  $filename .= "dialog_";  break;
							case WinPEFile::RT_STRING:  $filename .= "string_";  break;
							case WinPEFile::RT_FONTDIR:  $filename .= "fontdir_";  break;
							case WinPEFile::RT_FONT:  $filename .= "font_";  $ext = ".ttf";  break;
							case WinPEFile::RT_ACCELERATOR:  $filename .= "accelerator_";  break;
							case WinPEFile::RT_RCDATA:  $filename .= "rcdata_";  break;
							case WinPEFile::RT_MESSAGETABLE:  $filename .= "messagetable_";  break;
							case WinPEFile::RT_GROUP_CURSOR:
							case WinPEFile::RT_GROUP_ICON:
							{
								if ($rootentry["id"] === WinPEFile::RT_GROUP_CURSOR)
								{
									$filename .= "group_cursor_";

									$searchtype = WinPEFile::RT_CURSOR;
								}
								else
								{
									$filename .= "group_icon_";

									$searchtype = WinPEFile::RT_ICON;
								}

								if (isset($entry["id"]))
								{
									// Extract the ICO/CUR header.
									$result2 = WinICO::ParseHeader($entry["data"], true);
									if ($result2["success"] && (($rootentry["id"] === WinPEFile::RT_GROUP_CURSOR && $result2["type"] === WinICO::TYPE_CUR) || ($rootentry["id"] === WinPEFile::RT_GROUP_ICON && $result2["type"] === WinICO::TYPE_ICO)))
									{
										// Locate each icon/cursor resource and reconstruct the original icon/cursor.
										foreach ($result2["icons"] as $num2 => $icon)
										{
											$result3 = $winpe->FindResource($searchtype, $icon["id"], $entry["id"]);
											if ($result3 === false)  unset($result2["icons"][$num2]);
											else
											{
												$icon["data"] = $result3["entry"]["data"];
												unset($icon["id"]);

												$result2["icons"][$num2] = $icon;
											}
										}

										// Generate and write the ICO/CUR file to disk.
										$result3 = WinICO::Generate($result2["type"], $result2["icons"]);
										if ($result3["success"])
										{
											$destfile2 = $destfile . "/" . $filename . $num . ($result2["type"] === WinICO::TYPE_CUR ? ".cur" : ".ico");

											file_put_contents($destfile2, $result3["data"]);

											$result["files"][] = $destfile2;
										}
									}
								}

								break;
							}
							case WinPEFile::RT_VERSION:  $filename .= "version_";  break;
							case WinPEFile::RT_DLGINCLUDE:  $filename .= "dlginclude_";  break;
							case WinPEFile::RT_PLUGPLAY:  $filename .= "plugplay_";  break;
							case WinPEFile::RT_VXD:  $filename .= "vxd_";  break;
							case WinPEFile::RT_ANICURSOR:  $filename .= "anicursor_";  $ext = ".ani";  break;
							case WinPEFile::RT_ANIICON:  $filename .= "aniicon_";  $ext = ".ani";  break;
							case WinPEFile::RT_HTML:  $filename .= "html_";  $ext = ".html";  break;
							case WinPEFile::RT_MANIFEST:  $filename .= "manifest_";  $ext = ".config";  break;
							default:  $filename .= "unknown_" . $rootentry["id"] . "_";  break;
						}
					}

					$filename .= $num . $ext;

					$destfile2 = $destfile . "/" . $filename;

					if (file_put_contents($destfile2, $entry["data"]) === false)  CLI::DisplayResult(array("success" => false, "error" => "Unable to write resource data to '" . $destfile2 . "'.", "errorcode" => "write_failed"));

					$result["files"][] = $destfile2;
				}
			}

			CLI::DisplayResult($result);
		}
		else if ($cmd === "version-info")
		{
			require_once $rootpath . "/support/win_pe_utils.php";

			$result = WinPEUtils::GetVersionResource($winpe);

			CLI::DisplayResult($result);
		}
		else if ($cmd === "certificates")
		{
			$destfile = $datapath . "/extracts/" . substr($srcfile, strrpos($srcfile, "/") + 1);
			@mkdir($destfile, 0770);

			$result = array(
				"success" => true,
				"files" => array()
			);

			if (isset($winpe->pe_data_dir["certificates"]["certs"]))
			{
				foreach ($winpe->pe_data_dir["certificates"]["certs"] as $num => $entry)
				{
					$destfile2 = $destfile . "/cert_" . ($num + 1) . ".p7";

					if (file_put_contents($destfile2, $entry["cert_data"]) === false)  CLI::DisplayResult(array("success" => false, "error" => "Unable to write certificate data to '" . $destfile2 . "'.", "errorcode" => "write_failed"));

					$result["files"][] = $destfile2;
				}
			}

			CLI::DisplayResult($result);
		}
	}
	else if ($cmdgroup === "calculate")
	{
		// Calculate.
		if ($cmd === "rva")  CLI::ReinitArgs($args, array("src", "rva"));
		else if ($cmd === "checksum" || $cmd === "hashes")  CLI::ReinitArgs($args, array("src"));

		$found = false;
		do
		{
			$srcfile = CLI::GetUserInputWithArgs($args, "src", "Source file", false, "", $suppressoutput);
			if (!is_file($srcfile))  CLI::DisplayError("The source file '" . $srcfile . "' does not exist or is not a file.", false, false);
			else
			{
				$srcfile = str_replace("\\", "/", realpath($srcfile));

				$result = WinPEFile::ValidateFile($srcfile, false);
				if (!$result["success"])  CLI::DisplayError("Unable to validate '" . $srcfile . "' as a valid executable file.", false, false);
				else  $found = true;
			}
		} while (!$found);

		// Load the file.
		$winpe = new WinPEFile();

		$options = array();
		if ($cmd !== "hashes")  $options["pe_directories"] = "";

		$data = file_get_contents($srcfile);
		$winpe->Parse($data, $options);

		if ($cmd === "rva")
		{
			require_once $rootpath . "/support/utf8.php";

			$rva = CLI::GetUserInputWithArgs($args, "rva", "RVA", false, "", $suppressoutput);
			$pos = stripos($rva, "x");
			$rva = ($pos !== false ? hexdec(substr($rva, $pos + 1)) : (int)$rva);

			$dirinfo = $winpe->RVAToPos($rva);
			if ($dirinfo === false)  CLI::DisplayError("The specified RVA " . $rva . " (0x" . sprintf("%08X", $rva) . ") does not map to a section.");

			$sinfo = $winpe->pe_sections[$dirinfo["section"]];
			$sinfo["name"] = UTF8::MakeValid(rtrim(str_replace("\x00", " ", $sinfo["name"])));

			$filepos = ($dirinfo["pos"] < $winpe->pe_sections[$dirinfo["section"]]["raw_data_size"] ? $winpe->pe_sections[$dirinfo["section"]]["raw_data_ptr"] + $dirinfo["pos"] : false);

			$dirinfo["section"]++;

			$result = array(
				"success" => true,
				"rva" => $rva,
				"dirinfo" => $dirinfo,
				"section" => $sinfo,
				"filepos" => $filepos,
				"filepos_str" => "0x" . sprintf("%08X", $filepos)
			);

			CLI::DisplayResult($result);
		}
		else if ($cmd === "checksum")
		{
			$winpe->UpdateChecksum($data);

			$result = array(
				"success" => true
			);

			if (isset($winpe->pe_opt_header))
			{
				$result["type"] = "PE";
				$result["checksum"] = $winpe->pe_opt_header["checksum"];
				$result["checksum_str"] = "0x" . sprintf("%08X", $winpe->pe_opt_header["checksum"]);
			}
			else if (isset($winpe->ne_header))
			{
				$result["type"] = "NE";
				$result["checksum"] = $winpe->ne_header["checksum"];
				$result["checksum_str"] = "0x" . sprintf("%08X", $winpe->ne_header["checksum"]);
			}
			else
			{
				$result["type"] = "DOS";
				$result["checksum"] = $winpe->dos_header["checksum"];
				$result["checksum_str"] = "0x" . sprintf("%04X", $winpe->dos_header["checksum"]);
			}

			CLI::DisplayResult($result);
		}
		else if ($cmd === "hashes")
		{
			$result = $winpe->CalculateHashes($data);

			CLI::DisplayResult($result);
		}
	}
	else if ($cmdgroup === "modify")
	{
		// Modify.
		if ($cmd === "clear-certs" || $cmd === "clear-debug" || $cmd === "clear-bound-imports" || $cmd === "update-checksum")  CLI::ReinitArgs($args, array("src", "dest"));
		else if ($cmd === "set-min-os" || $cmd === "set-min-subsystem")  CLI::ReinitArgs($args, array("src", "dest", "ver"));
		else if ($cmd === "set-app-icon")  CLI::ReinitArgs($args, array("src", "dest", "ico"));
		else if ($cmd === "set-manifest")  CLI::ReinitArgs($args, array("src", "dest", "manifest"));
		else if ($cmd === "set-version-info")  CLI::ReinitArgs($args, array("src", "dest", "verinfo"));
		else if ($cmd === "create-hook-dll")  CLI::ReinitArgs($args, array("src", "hook", "destdir", "win9x"));
		else if ($cmd === "hook" || $cmd === "unhook")  CLI::ReinitArgs($args, array("src", "dest", "prehook", "hook"));
		else if ($cmd === "add-section")  CLI::ReinitArgs($args, array("src", "dest", "name", "bytes", "flags"));
		else if ($cmd === "expand-last-section")  CLI::ReinitArgs($args, array("src", "dest", "bytes"));
		else if ($cmd === "delete-section")  CLI::ReinitArgs($args, array("src", "dest", "section"));

		$found = false;
		do
		{
			$srcfile = CLI::GetUserInputWithArgs($args, "src", "Source file", false, "", $suppressoutput);
			if (!is_file($srcfile))  CLI::DisplayError("The file '" . $srcfile . "' does not exist or is not a file.", false, false);
			else
			{
				$srcfile = str_replace("\\", "/", realpath($srcfile));

				$result = WinPEFile::ValidateFile($srcfile, false);
				if (!$result["success"])  CLI::DisplayError("Unable to validate '" . $srcfile . "' as a valid executable file.", false, false);
				else  $found = true;
			}
		} while (!$found);

		if ($cmd === "create-hook-dll")  $destfile = false;
		else
		{
			$found = false;
			do
			{
				$destfile = CLI::GetUserInputWithArgs($args, "dest", "Destination file", $srcfile, "", $suppressoutput);
				if (is_dir($destfile))  CLI::DisplayError("The file '" . $destfile . "' is a directory.", false, false);
				else  $found = true;
			} while (!$found);
		}

		// Load the file.
		$winpe = new WinPEFile();

		$data = file_get_contents($srcfile);
		$winpe->Parse($data);

		if ($srcfile === $destfile && !file_exists($srcfile . ".bak"))  file_put_contents($srcfile . ".bak", $data);

		if ($cmd === "clear-certs")
		{
			$result = $winpe->ClearCertificates($data);
			if (!$result["success"])  CLI::DisplayResult($result);

			file_put_contents($destfile, $data);

			CLI::DisplayResult($result);
		}
		else if ($cmd === "clear-debug")
		{
			$result = $winpe->ClearDebugDirectory($data);
			if (!$result["success"])  CLI::DisplayResult($result);

			file_put_contents($destfile, $data);

			CLI::DisplayResult($result);
		}
		else if ($cmd === "clear-bound-imports")
		{
			$result = $winpe->ClearBoundImports($data);
			if (!$result["success"])  CLI::DisplayResult($result);

			file_put_contents($destfile, $data);

			CLI::DisplayResult($result);
		}
		else if ($cmd === "update-checksum")
		{
			$winpe->UpdateChecksum($data, true);

			file_put_contents($destfile, $data);

			$result = array(
				"success" => true
			);

			CLI::DisplayResult($result);
		}
		else if ($cmd === "sanitize-dos-stub")
		{
			$result = $winpe->SanitizeDOSStub($data);
			if (!$result["success"])  CLI::DisplayResult($result);

			file_put_contents($destfile, $data);

			CLI::DisplayResult($result);
		}
		else if ($cmd === "set-min-os")
		{
			if (isset($winpe->ne_header))  $newver = $winpe->ne_header["expected_win_ver_major"] . "." . $winpe->ne_header["expected_win_ver_minor"];
			else if (isset($winpe->pe_opt_header))  $newver = $winpe->pe_opt_header["major_os_ver"] . "." . $winpe->pe_opt_header["minor_os_ver"];
			else  CLI::DisplayError("Not a valid PE file.");

			$newver = CLI::GetUserInputWithArgs($args, "ver", "Minimum OS version", $newver, "", $suppressoutput);
			$newver = explode(".", $newver);
			while (count($newver) < 2)  $newver[] = 0;

			if (isset($winpe->ne_header))
			{
				$winpe->ne_header["expected_win_ver_major"] = (int)$newver[0];
				$winpe->ne_header["expected_win_ver_minor"] = (int)$newver[1];
			}
			else if (isset($winpe->pe_opt_header))
			{
				$winpe->pe_opt_header["major_os_ver"] = (int)$newver[0];
				$winpe->pe_opt_header["minor_os_ver"] = (int)$newver[1];
			}

			$winpe->SaveHeaders($data);

			file_put_contents($destfile, $data);

			$result = array(
				"success" => true
			);

			CLI::DisplayResult($result);
		}
		else if ($cmd === "set-min-subsystem")
		{
			if (isset($winpe->ne_header))  $newver = $winpe->ne_header["expected_win_ver_major"] . "." . $winpe->ne_header["expected_win_ver_minor"];
			else if (isset($winpe->pe_opt_header))  $newver = $winpe->pe_opt_header["major_subsystem_ver"] . "." . $winpe->pe_opt_header["minor_subsystem_ver"];
			else  CLI::DisplayError("Not a valid PE file.");

			$newver = CLI::GetUserInputWithArgs($args, "ver", "Minimum subsystem version", $newver, "", $suppressoutput);
			$newver = explode(".", $newver);
			while (count($newver) < 2)  $newver[] = 0;

			if (isset($winpe->ne_header))
			{
				$winpe->ne_header["expected_win_ver_major"] = (int)$newver[0];
				$winpe->ne_header["expected_win_ver_minor"] = (int)$newver[1];
			}
			else if (isset($winpe->pe_opt_header))
			{
				$winpe->pe_opt_header["major_subsystem_ver"] = (int)$newver[0];
				$winpe->pe_opt_header["minor_subsystem_ver"] = (int)$newver[1];
			}

			$winpe->SaveHeaders($data);

			file_put_contents($destfile, $data);

			$result = array(
				"success" => true
			);

			CLI::DisplayResult($result);
		}
		else if ($cmd === "set-app-icon")
		{
			require_once $rootpath . "/support/win_pe_utils.php";
			require_once $rootpath . "/support/win_ico.php";

			$found = false;
			do
			{
				$icofile = CLI::GetUserInputWithArgs($args, "ico", "ICO file", false, "", $suppressoutput);
				if (!is_file($icofile))  CLI::DisplayError("The file '" . $icofile . "' does not exist or is not a file.", false, false);
				else
				{
					$icofile = str_replace("\\", "/", realpath($icofile));

					$result = WinICO::Parse(file_get_contents($icofile));
					if (!$result["success"])  CLI::DisplayError("The file '" . $icofile . "' does not appear to be a valid icon (ICO) file.", false, false);
					else if ($result["type"] !== WinICO::TYPE_ICO)  CLI::DisplayError("The file '" . $icofile . "' does not appear to be a valid icon (ICO) file.  Type mismatch (" . $result["type"] . ").", false, false);
					else  $found = true;
				}
			} while (!$found);

			$result = WinPEUtils::SetIconResource($winpe, $data, $result);
			if (!$result["success"])  CLI::DisplayResult($result);

			$result = $winpe->SavePEResourcesDirectory($data);
			if (!$result["success"])  CLI::DisplayResult($result);

			file_put_contents($destfile, $data);

			CLI::DisplayResult($result);
		}
		else if ($cmd === "set-manifest")
		{
			$found = false;
			do
			{
				$manifestfile = CLI::GetUserInputWithArgs($args, "manifest", "Manifest file", false, "", $suppressoutput);
				if (!is_file($manifestfile))  CLI::DisplayError("The file '" . $manifestfile . "' does not exist or is not a file.", false, false);
				else
				{
					$manifestfile = str_replace("\\", "/", realpath($manifestfile));

					$manifestdata = file_get_contents($manifestfile);

					if ($manifestdata === false)  CLI::DisplayError("The file '" . $manifestfile . "' failed to load.", false, false);
					else  $found = true;
				}
			} while (!$found);

			$result = $winpe->FindResource(WinPEFile::RT_MANIFEST, true, true);
			if ($result === false)  $winpe->CreateResourceLangNode(WinPEFile::RT_MANIFEST, 1, true, $manifestdata);
			else  $winpe->OverwriteResourceData($data, $result["num"], $manifestdata);

			$result = $winpe->SavePEResourcesDirectory($data);
			if (!$result["success"])  CLI::DisplayResult($result);

			file_put_contents($destfile, $data);

			CLI::DisplayResult($result);
		}
		else if ($cmd === "set-version-info")
		{
			require_once $rootpath . "/support/win_pe_utils.php";

			$found = false;
			do
			{
				$verinfofile = CLI::GetUserInputWithArgs($args, "verinfo", "Version Info file", false, "", $suppressoutput);
				if (!is_file($verinfofile))  CLI::DisplayError("The file '" . $verinfofile . "' does not exist or is not a file.", false, false);
				else
				{
					$verinfofile = str_replace("\\", "/", realpath($verinfofile));

					$data2 = file_get_contents($verinfofile);

					if ($data2 === false)  CLI::DisplayError("The file '" . $verinfofile . "' failed to load.", false, false);
					else
					{
						// Attempt to decode as JSON.
						$verinfo = @json_decode($data2, true);

						if (is_array($verinfo))  $found = true;
						else
						{
							$verinfo = WinPEUtils::ParseVersionInfoData($data2);
							if (!$verinfo["success"])  CLI::DisplayError("The file '" . $verinfofile . "' failed to parse as a valid version information structure.", false, false);
							else  $found = true;
						}
					}
				}
			} while (!$found);

			$result = WinPEUtils::SetVersionResource($winpe, $data, $verinfo);
			if (!$result["success"])  CLI::DisplayResult($result);

			$result = $winpe->SavePEResourcesDirectory($data);
			if (!$result["success"])  CLI::DisplayResult($result);

			file_put_contents($destfile, $data);

			CLI::DisplayResult($result);
		}
		else if ($cmd === "create-hook-dll")
		{
			require_once $rootpath . "/support/win_pe_utils.php";

			$found = false;
			do
			{
				$hookfile = CLI::GetUserInputWithArgs($args, "hook", "Real Hook DLL", false, "", $suppressoutput);
				if (!is_file($hookfile))  CLI::DisplayError("The file '" . $hookfile . "' does not exist or is not a file.", false, false);
				else
				{
					$hookfile = str_replace("\\", "/", realpath($hookfile));

					$result = WinPEFile::ValidateFile($hookfile, false);
					if (!$result["success"])  CLI::DisplayError("Unable to validate '" . $hookfile . "' as a valid executable file.", false, false);
					else  $found = true;
				}
			} while (!$found);

			$found = false;
			do
			{
				$destdir = CLI::GetUserInputWithArgs($args, "destdir", "Destination directory", false, "", $suppressoutput);

				@mkdir($destdir, 0770, true);
				$destdir = str_replace("\\", "/", realpath($destdir));

				if (!is_dir($destdir))  CLI::DisplayError("The specified directory '" . $destdir . "' was unable to be created or is not a directory.", false, false);
				else  $found = true;
			} while (!$found);

			$win9x = CLI::GetYesNoUserInputWithArgs($args, "win9x", "Win9x/Me support", "N", "", $suppressoutput);

			// Load the file.
			$winpehooks = new WinPEFile();

			$data2 = file_get_contents($hookfile);
			$winpehooks->Parse($data2);

			$result = WinPEUtils::CreateHookDLL($srcfile, $hookfile, $winpe, $winpehooks, $win9x);
			if (!$result["success"])  CLI::DisplayResult($result);

			file_put_contents($destdir . "/" . $result["filename"], $result["data"]);
			file_put_contents($destdir . "/" . $result["origfilename"], $data);
			file_put_contents($destdir . "/" . $result["hookfilename"], $data2);

			$result = array(
				"success" => true,
				"filename" => $destdir . "/" . $result["filename"],
				"origfilename" => $destdir . "/" . $result["origfilename"],
				"hookfilename" => $destdir . "/" . $result["hookfilename"]
			);

			CLI::DisplayResult($result);
		}
		else if ($cmd === "hook")
		{
			require_once $rootpath . "/support/win_pe_utils.php";
			require_once $rootpath . "/support/str_basics.php";

			$prehook = CLI::GetUserInputWithArgs($args, "prehook", "Prehook string", false, "The next question asks for the string to locate and replace in the destination file (e.g. kernel32.dll).", $suppressoutput);

			$found = false;
			do
			{
				$hookfile = CLI::GetUserInputWithArgs($args, "hook", "Generated hook DLL", false, "The next question asks for the generated hook DLL file from a previous 'create-hook-dll' operation.", $suppressoutput);
				$hookfilename = Str::ExtractFilename($hookfile);

				if (!is_file($hookfile))  CLI::DisplayError("The file '" . $hookfile . "' does not exist or is not a file.", false, false);
				else if (strlen($hookfilename) != strlen($prehook))  CLI::DisplayError("The name '" . $hookfilename . "' is not the same length as the prehook string.", false, false);
				else
				{
					$hookfile = str_replace("\\", "/", realpath($hookfile));

					$result = WinPEFile::ValidateFile($hookfile, false);
					if (!$result["success"])  CLI::DisplayError("Unable to validate '" . $hookfile . "' as a valid executable file.", false, false);
					else  $found = true;
				}
			} while (!$found);

			$hookdir = Str::ExtractPathname($hookfile);

			// Load the file.
			$winpehooks = new WinPEFile();

			$data2 = file_get_contents($hookfile);
			$winpehooks->Parse($data2);

			// Copy referenced export forward and import files to the destination directory.
			$destdir = dirname($destfile);
			@mkdir($destdir, 0770, true);
			$destdir = str_replace("\\", "/", realpath($destdir));

			$copied = array();
			foreach ($winpehooks->pe_data_dir["exports"]["namemap"] as $name => $ord)
			{
				if (isset($winpehooks->pe_data_dir["exports"]["addresses"][$ord]) && $winpehooks->pe_data_dir["exports"]["addresses"][$ord]["type"] === "forward")
				{
					$pos = strpos($winpehooks->pe_data_dir["exports"]["addresses"][$ord]["name"], ".");
					if ($pos !== false)
					{
						$name = substr($winpehooks->pe_data_dir["exports"]["addresses"][$ord]["name"], 0, $pos) . ".dll";

						if ($name !== ".dll" && !isset($copied[strtolower($name)]))
						{
							@copy($hookdir . $name, $destdir . "/" . $name);

							$copied[strtolower($name)] = true;
						}
					}
				}
			}

			foreach ($winpehooks->pe_data_dir["imports"]["dir_entries"] as $direntry)
			{
				$name = $direntry["name"];

				if ($name !== "" && !isset($copied[strtolower($name)]))
				{
					@copy($hookdir . $name, $destdir . "/" . $name);

					$copied[strtolower($name)] = true;
				}
			}

			// Replace the string with the hook string.
			$data = str_ireplace($prehook, $hookfilename, $data);

			file_put_contents($destfile, $data);
			file_put_contents($destdir . "/" . $hookfilename, $data2);

			$result = array(
				"success" => true,
				"filename" => $destfile,
				"prehook" => $prehook,
				"hook" => $hookfilename
			);

			CLI::DisplayResult($result);
		}
		else if ($cmd === "unhook")
		{
			require_once $rootpath . "/support/win_pe_utils.php";

			$valid = false;
			do
			{
				$prehook = CLI::GetUserInputWithArgs($args, "prehook", "Prehook string", false, "The next question asks for the string to replace with in the destination file (e.g. kernel32.dll).", $suppressoutput);
				$hook = CLI::GetUserInputWithArgs($args, "hook", "Hook string", false, "The next question asks for the string to locate and replace in the destination file (e.g. 12rAnD0M.dll).", $suppressoutput);

				if (strlen($prehook) != strlen($hook))  CLI::DisplayError("The length of the prehook and hook strings do not match.", false, false);
				else  $valid = true;
			} while (!$valid);

			// Replace the string with the hook string.
			$data = str_ireplace($hook, $prehook, $data);

			file_put_contents($destfile, $data);

			$result = array(
				"success" => true,
				"filename" => $destfile
			);

			CLI::DisplayResult($result);
		}
		else if ($cmd === "add-section")
		{
			$name = CLI::GetUserInputWithArgs($args, "name", "Section name (8 bytes max)", false, "", $suppressoutput);
			$bytes = (int)CLI::GetUserInputWithArgs($args, "bytes", "Bytes to reserve", false, "", $suppressoutput);
			if ($bytes < 0)  $bytes = 0;

			$desc = "The next question asks for pipe-delimited flags that are prefixed 0x hex values, integers, and/or these named flags:\n\n";
			$desc .= "  IMAGE_SCN_CNT_CODE - Contains executable code.\n";
			$desc .= "  IMAGE_SCN_CNT_INITIALIZED_DATA - Contains initialized data.\n";
			$desc .= "  IMAGE_SCN_CNT_UNINITIALIZED_DATA - Contains uninitialized data.\n";
			$desc .= "  IMAGE_SCN_NO_DEFER_SPEC_EXC - Reset speculative exceptions handling bits in the TLB entries.\n";
			$desc .= "  IMAGE_SCN_GPREL - Contains data referenced through the global pointer.\n";
			$desc .= "  IMAGE_SCN_LNK_NRELOC_OVFL - Contains extended relocations due to overflow.\n";
			$desc .= "  IMAGE_SCN_MEM_DISCARDABLE - Can be discarded as needed.\n";
			$desc .= "  IMAGE_SCN_MEM_NOT_CACHED - Cannot be cached.\n";
			$desc .= "  IMAGE_SCN_MEM_NOT_PAGED - Cannot be paged.\n";
			$desc .= "  IMAGE_SCN_MEM_SHARED - Can be shared in memory.\n";
			$desc .= "  IMAGE_SCN_MEM_EXECUTE - Can be executed as code.\n";
			$desc .= "  IMAGE_SCN_MEM_READ - Can be read.\n";
			$desc .= "  IMAGE_SCN_MEM_WRITE - Can be written to.";

			$flags = CLI::GetUserInputWithArgs($args, "flags", "Section flags", "IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ", $desc, $suppressoutput);

			$flags2 = explode("|", $flags);
			$flags = 0;
			foreach ($flags2 as $flag)
			{
				$flag = strtoupper(trim($flag));

				if (substr($flag, 0, 2) === "0X")  $flags |= hexdec(trim(substr($flag, 2)));
				else if ($flag === "IMAGE_SCN_CNT_CODE")  $flags |= WinPEFile::IMAGE_SCN_CNT_CODE;
				else if ($flag === "IMAGE_SCN_CNT_INITIALIZED_DATA")  $flags |= WinPEFile::IMAGE_SCN_CNT_INITIALIZED_DATA;
				else if ($flag === "IMAGE_SCN_CNT_UNINITIALIZED_DATA")  $flags |= WinPEFile::IMAGE_SCN_CNT_UNINITIALIZED_DATA;
				else if ($flag === "IMAGE_SCN_NO_DEFER_SPEC_EXC")  $flags |= WinPEFile::IMAGE_SCN_NO_DEFER_SPEC_EXC;
				else if ($flag === "IMAGE_SCN_GPREL")  $flags |= WinPEFile::IMAGE_SCN_GPREL;
				else if ($flag === "IMAGE_SCN_LNK_NRELOC_OVFL")  $flags |= WinPEFile::IMAGE_SCN_LNK_NRELOC_OVFL;
				else if ($flag === "IMAGE_SCN_MEM_DISCARDABLE")  $flags |= WinPEFile::IMAGE_SCN_MEM_DISCARDABLE;
				else if ($flag === "IMAGE_SCN_MEM_NOT_CACHED")  $flags |= WinPEFile::IMAGE_SCN_MEM_NOT_CACHED;
				else if ($flag === "IMAGE_SCN_MEM_NOT_PAGED")  $flags |= WinPEFile::IMAGE_SCN_MEM_NOT_PAGED;
				else if ($flag === "IMAGE_SCN_MEM_SHARED")  $flags |= WinPEFile::IMAGE_SCN_MEM_SHARED;
				else if ($flag === "IMAGE_SCN_MEM_EXECUTE")  $flags |= WinPEFile::IMAGE_SCN_MEM_EXECUTE;
				else if ($flag === "IMAGE_SCN_MEM_READ")  $flags |= WinPEFile::IMAGE_SCN_MEM_READ;
				else if ($flag === "IMAGE_SCN_MEM_WRITE")  $flags |= (int)WinPEFile::IMAGE_SCN_MEM_WRITE;
				else  $flags |= (int)$flag;
			}

			$result = $winpe->CreateNewPESection($data, $name, $bytes, $flags);
			if (!$result["success"])  CLI::DisplayResult($result);

			file_put_contents($destfile, $data);

			CLI::DisplayResult($result);
		}
		else if ($cmd === "expand-last-section")
		{
			$bytes = (int)CLI::GetUserInputWithArgs($args, "bytes", "Additional bytes to reserve", false, "", $suppressoutput);
			if ($bytes < 0)  $bytes = 0;

			$result = $winpe->ExpandLastPESection($data, $bytes);
			if (!$result["success"])  CLI::DisplayResult($result);

			file_put_contents($destfile, $data);

			CLI::DisplayResult($result);
		}
		else if ($cmd === "delete-section")
		{
			$sections = array();

			$lastnum = false;
			if (isset($winpe->pe_sections))
			{
				foreach ($winpe->pe_sections as $num => $sinfo)
				{
					$lastnum = $num + 1;
					$structures[$num + 1] = rtrim(str_replace("\x00", " ", $sinfo["name"])) . " section";
				}
			}

			if ($lastnum !== false)  $sections["last"] = "Last section";

			if (!count($sections))  CLI::DisplayError("No PE sections are available.");
			$section = CLI::GetLimitedUserInputWithArgs($args, "section", "Section", false, "Available sections:", $sections, true, $suppressoutput);
			if ($section === "last")  $section = $lastnum;

			$section--;
			$result = $winpe->DeletePESection($data, $section);
			if (!$result["success"])  CLI::DisplayResult($result);

			file_put_contents($destfile, $data);

			CLI::DisplayResult($result);
		}
		else if ($cmd === "apply-checksum")
		{
			$winpe->UpdateChecksum($data);

			file_put_contents($destfile, $data);

			$result = array(
				"success" => true
			);

			CLI::DisplayResult($result);
		}
	}
?>