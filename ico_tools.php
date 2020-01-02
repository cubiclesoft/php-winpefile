<?php
	// ICO/CUR command-line tools.
	// (C) 2019 CubicleSoft.  All Rights Reserved.

	if (!isset($_SERVER["argc"]) || !$_SERVER["argc"])
	{
		echo "This file is intended to be run from the command-line.";

		exit();
	}

	// Temporary root.
	$rootpath = str_replace("\\", "/", dirname(__FILE__));

	require_once $rootpath . "/support/cli.php";
	require_once $rootpath . "/support/win_ico.php";

	// Process the command-line options.
	$options = array(
		"shortmap" => array(
			"s" => "suppressoutput",
			"?" => "help"
		),
		"rules" => array(
			"suppressoutput" => array("arg" => false),
			"help" => array("arg" => false)
		),
		"allow_opts_after_param" => false
	);
	$args = CLI::ParseCommandLine($options);

	if (isset($args["opts"]["help"]))
	{
		echo "The ICO/CUR file command-line tool\n";
		echo "Purpose:  Create and get information about icon and cursor files from the command-line.\n";
		echo "\n";
		echo "This tool is question/answer enabled.  Just running it will provide a guided interface.  It can also be run entirely from the command-line if you know all the answers.\n";
		echo "\n";
		echo "Syntax:  " . $args["file"] . " [options] [cmd [cmdoptions]]\n";
		echo "Options:\n";
		echo "\t-s   Suppress most output.  Useful for capturing JSON output.\n";
		echo "\n";
		echo "Examples:\n";
		echo "\tphp " . $args["file"] . "\n";
		echo "\tphp " . $args["file"] . " create ICO -src myicon.png -dest myicon.ico\n";
		echo "\tphp " . $args["file"] . " get-info myicon.ico\n";

		exit();
	}

	$origargs = $args;
	$suppressoutput = (isset($args["opts"]["suppressoutput"]) && $args["opts"]["suppressoutput"]);

	// Get the command.
	$cmds = array(
		"create" => "Create an ICO/CUR file from an image",
		"get-info" => "Extract information about an ICO/CUR file"
	);

	$cmd = CLI::GetLimitedUserInputWithArgs($args, false, "Command", false, "Available commands:", $cmds, true, $suppressoutput);

	if ($cmd === "create")
	{
		CLI::ReinitArgs($args, array("type", "src", "dest", "x", "y"));

		$types = array(
			"ICO" => "Create an icon",
			"CUR" => "Create a cursor"
		);

		$type = CLI::GetLimitedUserInputWithArgs($args, "type", "Type", false, "Available types:", $types, true, $suppressoutput);

		$found = false;
		do
		{
			$srcfile = CLI::GetUserInputWithArgs($args, "src", "Source file", false, "", $suppressoutput);
			if (!is_file($srcfile))  CLI::DisplayError("The source file '" . $srcfile . "' does not exist or is not a file.", false, false);
			else
			{
				$srcfile = str_replace("\\", "/", realpath($srcfile));
				$data = file_get_contents($srcfile);

				$result = WinICO::Create($data);
				if (!$result["success"])  CLI::DisplayError("Unable to create " . ($type === "ICO" ? "an icon" : "a cursor") . " from '" . $srcfile . "'.", $result, false);
				else  $found = true;
			}
		} while (!$found);

		$found = false;
		do
		{
			$destfile = CLI::GetUserInputWithArgs($args, "dest", "Destination file", false, "", $suppressoutput);
			if (is_dir($destfile))  CLI::DisplayError("The file '" . $destfile . "' is a directory.", false, false);
			else  $found = true;
		} while (!$found);

		if ($type === "CUR")
		{
			$x = (int)CLI::GetUserInputWithArgs($args, "x", "X hotspot", "0", "", $suppressoutput);
			$y = (int)CLI::GetUserInputWithArgs($args, "y", "Y hotspot", "0", "", $suppressoutput);

			$result = WinICO::Create($data, $x, $y);
			if (!$result["success"])  CLI::DisplayError("Unable to create a cursor from '" . $srcfile . "'.", $result, false);
		}

		file_put_contents($destfile, $result["data"]);

		$result = array(
			"success" => true,
			"file" => str_replace("\\", "/", realpath($destfile))
		);

		CLI::DisplayResult($result);
	}
	else if ($cmd === "get-info")
	{
		CLI::ReinitArgs($args, array("file"));

		$found = false;
		do
		{
			$srcfile = CLI::GetUserInputWithArgs($args, "file", "ICO/CUR file", false, "", $suppressoutput);
			if (!is_file($srcfile))  CLI::DisplayError("The file '" . $srcfile . "' does not exist or is not a file.", false, false);
			else
			{
				$srcfile = str_replace("\\", "/", realpath($srcfile));
				$data = file_get_contents($srcfile);

				$result = WinICO::Parse($data);
				if (!$result["success"])  CLI::DisplayError("Unable to parse '" . $srcfile . "' as an ICO/CUR file.", $result, false);
				else  $found = true;
			}
		} while (!$found);

		foreach ($result["icons"] as &$icon)
		{
			unset($icon["data"]);
		}

		$result["file"] = $srcfile;

		CLI::DisplayResult($result);
	}
?>