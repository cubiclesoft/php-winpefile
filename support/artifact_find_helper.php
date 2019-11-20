<?php
	// PE File bulk artifact finder command-line helper.
	// (C) 2019 CubicleSoft.  All Rights Reserved.

	if (!isset($_SERVER["argc"]) || !$_SERVER["argc"])
	{
		echo "This file is intended to be run from the command-line.";

		exit();
	}

	// Temporary root.
	$rootpath = str_replace("\\", "/", dirname(__FILE__));

	require_once $rootpath . "/win_pe_file.php";
	require_once $rootpath . "/artifact_rules.php";

	// Custom functions referenced by the artifact rules.
	function IsRVAOutsideResourceDir($rva)
	{
		global $winpe;

		return ($rva < $winpe->pe_data_dir["resources"]["rva"] || $rva >= $winpe->pe_data_dir["resources"]["rva"] + $winpe->pe_data_dir["resources"]["size"]);
	}

	function HasOverlappingSectionRVA($val)
	{
		global $winpe;

		$sections = array();

		foreach ($winpe->pe_sections as &$info)
		{
			if (isset($sections[$info["rva"]]))  return true;

			$sections[$info["rva"]] = $info["rva"] + max($info["virtual_size"], $info["raw_data_size"]);
		}

		ksort($sections);

		$lastrva = false;
		foreach ($sections as $rva)
		{
			if ($lastrva !== false && $rva < $lastrva)  return true;

			$lastrva = $rva;
		}

		return false;
	}

	function HasDataAfterCertificatesTable($val)
	{
		global $winpe, $filename;

		return ($winpe->pe_data_dir["certificates"]["pos"] && $winpe->pe_data_dir["certificates"]["size"] && $winpe->pe_data_dir["certificates"]["pos"] + $winpe->pe_data_dir["certificates"]["size"] < filesize($filename));
	}

	// Uses the rules to traverse the data structure looking for artifact matches.
	function GetArtifactPaths($prefix, $tree, &$rules, &$break)
	{
		$result = array();

		foreach ($rules as $pkey => $pinfo)
		{
			if (is_string($pkey))
			{
				// Find the array to traverse.
				$pkey = explode(".", $pkey);
				$curr = &$tree;
				$found = true;
				foreach ($pkey as $key)
				{
					if (is_array($curr))
					{
						if (isset($curr[$key]))  $curr = &$curr[$key];
						else
						{
							$found = false;

							break;
						}
					}
					else
					{
						if (isset($curr->$key))  $curr = &$curr->$key;
						else
						{
							$found = false;

							break;
						}
					}
				}

				if ($found)
				{
					foreach ($curr as $item)
					{
						$result2 = GetArtifactPaths($prefix, $item, $pinfo, $break);

						foreach ($result2 as $name => $val)  $result[$name] = $val;

						if ($break)  return $result;
					}
				}
			}
			else
			{
				if (isset($pinfo["if"]))  $ifpaths = $pinfo["if"];
				else  $ifpaths = array($pinfo);

				$matches = 0;
				foreach ($ifpaths as $ifpath)
				{
					// Calculate the value for comparison.
					$vals = array();
					$pkeys = explode("|", $ifpath["path"]);
					$found = true;
					foreach ($pkeys as $pkey)
					{
						$pkey = explode(".", $pkey);
						$curr = &$tree;
						$found = true;
						foreach ($pkey as $key)
						{
							if (is_array($curr))
							{
								if (isset($curr[$key]))  $curr = &$curr[$key];
								else
								{
									$found = false;

									break;
								}
							}
							else
							{
								if (isset($curr->$key))  $curr = &$curr->$key;
								else
								{
									$found = false;

									break;
								}
							}
						}

						if (!$found)  break;

						$vals[] = $curr;
					}

					// Compare the value with the artifact.
					if ($found)
					{
						$val = (count($vals) == 1 ? $vals[0] : implode("|", $vals));

						$name = false;
						switch ($ifpath["op"])
						{
							case "<":
							{
								if ($val < $ifpath["val"])  $name = $pinfo["name"];

								break;
							}
							case "<=":
							{
								if ($val <= $ifpath["val"])  $name = $pinfo["name"];

								break;
							}
							case "==":
							{
								if ($val === $ifpath["val"])  $name = $pinfo["name"];

								break;
							}
							case "!=":
							{
								if (is_array($ifpath["val"]))
								{
									if (!in_array($val, $ifpath["val"]))  $name = $pinfo["name"];
								}
								else if ($val !== $ifpath["val"])
								{
									$name = $pinfo["name"];
								}

								break;
							}
							case ">=":
							{
								if ($val >= $ifpath["val"])  $name = $pinfo["name"];

								break;
							}
							case ">":
							{
								if ($val > $ifpath["val"])  $name = $pinfo["name"];

								break;
							}
							case "&":
							{
								if (($val & $ifpath["val"]) === $ifpath["val"])  $name = $pinfo["name"];

								break;
							}
							case "&=":
							{
								// Mask and compare.
								if (($val & $ifpath["mask"]) === $ifpath["val"])  $name = $pinfo["name"];

								break;
							}
							case "hash":
							{
								$name = $pinfo["name"] . str_replace("|", "_", $val);

								break;
							}
							case "custom":
							{
								if (call_user_func($pinfo["cmp"], $val))  $name = $pinfo["name"];

								break;
							}
							default:
							{
								echo "Unhandled operation '" . $ifpath["op"] . "'.\n";

								exit();
							}
						}

						if ($name !== false)  $matches++;
					}
				}

				if ($matches == count($ifpaths))
				{
					if (!isset($pinfo["prefix"]) || $pinfo["prefix"])  $name = $prefix . $name;

					$result[$name] = array(
						"rare" => (isset($pinfo["rare"]) && ($pinfo["rare"] === true || (is_string($pinfo["rare"]) && substr($name, 0, strlen($pinfo["rare"])) === $pinfo["rare"])) ? $pinfo["rare"] : false)
					);

					if (isset($pinfo["break"]) && $pinfo["break"])
					{
						$break = true;

						break;
					}
				}
			}
		}

		return $result;
	}

	// Handle incoming file processing requests, process the PE file, and return JSON responses.
	$fp = fopen("php://stdin", "rb");
	while (($line = fgets($fp)) !== false)
	{
		if ($line === "" && feof($fp))  break;

		$filename = str_replace("\\", "/", realpath(trim($line)));

		// Read a little bit of the file to determine viability.
		$result = WinPEFile::ValidateFile($filename, false);
		if ($result["success"])
		{
			if (filesize($filename) < 15000000)
			{
				$size = filesize($filename);

				$winpe = new WinPEFile();
				$winpe->Parse(file_get_contents($filename));

				$break = false;
				$artifactmap = GetArtifactPaths((isset($winpe->pe_opt_header) && $winpe->pe_opt_header["signature"] === 0x020B ? "64_pe/64_" : "32_pe/32_"), $winpe, $g_artifact_rules, $break);

				$result = array(
					"success" => true,
					"origfile" => trim($line),
					"filename" => $filename,
					"size" => $size,
					"map" => $artifactmap
				);
			}
			else
			{
				$result = array(
					"success" => false,
					"error" => "Skipping.  File '" . $filename . "' is larger than 15MB.",
					"errorcode" => "file_too_large"
				);
			}
		}

		echo json_encode($result, JSON_UNESCAPED_SLASHES) . "\n";
	}
?>