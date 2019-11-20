WinICO Class:  'support/win_ico.php'
====================================

The WinICO class creates and parses Windows ICO (.ico) and CUR (.cur) files.  The file format contains multiple images and masks.  Cursors also contain hotspots.  Requires PHP GD to be installed.

WinICO::Create($data, $hotspotx = false, $hotspoty = false)
-----------------------------------------------------------

Access:  public static

Parameters:

* $data - A string containing a GD-compatible image, preferably 256x256 or larger.
* $hotspotx - An integer containing the horizontal position of the hotspot for a cursor or a boolean of false for an icon (Default is false).
* $hotspoty - An integer containing the vertical position of the hotspot for a cursor or a boolean of false for an icon (Default is false).

Returns:  A standard array of information.

This static function creates a Windows icon or cursor from a source image.  A square PNG is preferred but any GD-compatible image will work.

The generated icon has the following sizes and bit depths:

* 16x16, 24-bits
* 24x24, 24-bits
* 32x32, 24-bits
* 48x48, 24-bits
* 16x16, 32-bits
* 24x24, 32-bits
* 32x32, 32-bits
* 48x48, 32-bits
* 256x256, 32-bits (PNG)

If the source image is smaller than a specific size, then the size is skipped.

Example usage:

```php
<?php
	require_once "support/win_ico.php";

	$data = file_get_contents("installer_icon.png");

	$result = WinICO::Create($data);
	if (!$result["success"])
	{
		var_dump($result);

		exit();
	}

	file_put_contents("installer_icon.ico", $result["data"]);
?>
```

WinICO::ResizeImage(&$data, $destwidth, $destheight)
----------------------------------------------------

Access:  public static

Parameters:

* $data - A string containing a GD-compatible image.
* $destwidth - An integer containing the width to resize to.
* $destheight - An integer containing the height to resize to.

Returns:  A standard array of information.

This static function is used by `Create()` to resize the input image if it is larger than 2048x2048.

WinICO::ResizeAndConvertToIcon(&$data, $destwidth, $destheight, $bits, $hotspotx = false, $hotspoty = false)
------------------------------------------------------------------------------------------------------------

Access:  public static

Parameters:

* $data - A string containing a GD-compatible image.
* $destwidth - An integer containing the width to resize to.
* $destheight - An integer containing the height to resize to.
* $hotspotx - An integer containing the horizontal position of the hotspot for a cursor or a boolean of false for an icon (Default is false).
* $hotspoty - An integer containing the vertical position of the hotspot for a cursor or a boolean of false for an icon (Default is false).

Returns:  A standard array of information.

This static function is used by `Create()` to resize the input image and convert it to a PNG if 256x256 or to a ICO BMP with a mask otherwise.  The result is wrapped in a `Generate()`-compatible wrapper.

WinICO::ParseHeader($data, $groupdir)
-------------------------------------

Access:  public static

Parameters:

* $data - A string containing the data to extract header information from.
* $groupdir - A boolean of true if the data is the header from a RT_GROUP_ICON or RT_GROUP_CURSOR directory resource or a boolean of false if the data is from a normal ICO/CUR file.

Returns:  A standard array of information.

This static function parses the header of ICO/CUR data.  This function supports both ICO/CUR files and PE directory resources.

WinICO::Parse($data)
--------------------

Access:  public static

Parameters:

* $data - A string containing a Windows icon (.ico) or cursor (.cur) file data.

Returns:  A standard array of information.

This static function parses and extracts Windows icon and cursor data.  Note that the function does not attempt to decode or decompress the binary image data.

Example usage:

```php
<?php
	require_once "support/win_ico.php";

	$data = file_get_contents("installer_icon.ico");

	$result = WinICO::Parse($data);
	if (!$result["success"])
	{
		var_dump($result);

		exit();
	}

	foreach ($result["icons"] as $num => &$icon)
	{
		if ($icon["type"] === "PNG")  file_put_contents("installer_icon_" . $num . ".png", $icon["data"]);
		else
		{
			$result2 = WinICO::ConvertICOBMPToPNG($icon["data"]);
			if ($result2["success"])  file_put_contents("installer_icon_" . $num . ".png", $result2["png_data"]);
		}

		unset($icon["data"]);
	}

	var_dump($result);
?>
```

WinICO::ConvertICOBMPToPNG($data)
---------------------------------

Access:  public static

Parameters:

* $data - A string in the "headerless" BMP w/ mask format used for ICO/CUR (aka "ICO_BMP").

Returns:  A standard array of information.

This static function attempts to convert an "ICO_BMP" to both a BMP without its mask (it'll look strange if saved) and a PNG with suitable transparency bits.  ICO_BMP images are incorrectly double-height, lack a valid BMP file header, and have a bit mask.  The format is a very non-standard BMP that looks quite strange in standard image editing software.  This function converts the icon to a PNG with the mask correctly applied.

Requires PHP 7.2.0 or later w/ the PHP GD extension.  Support for BMP files was added to the `imagecreatefromstring()` function in PHP 7.2.

See `Parse()` for example usage.

WinICO::Generate($type, $icons)
-------------------------------

Access:  public static

Parameters:

* $type - One of WinICO::TYPE_ICO or WinICO::TYPE_CUR.
* $icons - An array containing icon information and either icon data or PE directory resource IDs.

Returns:  A standard array of information.

This static function generates a string containing a Windows icon or cursor from a set of icons.  The typical use for this function is to `Parse()` an icon/cursor file, add or remove an icon/cursor, and then call this function to generate a new icon/cursor file.

Note that little validation is performed and the inputs are expected to be correct.

WinICO::GetUInt8(&$data, &$x, $y)
---------------------------------

Access:  public static

Parameters:

* $data - A string containing the data.
* $x - An integer containing the starting position of the UInt8.
* $y - An integer containing the size/limit of the data.

Returns:  The UInt8 value at the specified position.

This static function returns the unsigned 8-bit value at the specified position and increments $x by 1.  Calls `GetBytes()` to get the substring for the value.

WinICO::GetUInt16(&$data, &$x, $y)
----------------------------------

Access:  public static

Parameters:

* $data - A string containing the data.
* $x - An integer containing the starting position of the UInt16.
* $y - An integer containing the size/limit of the data.

Returns:  The UInt16 value at the specified position.

This static function returns the unsigned 16-bit value at the specified position and increments $x by 2.  Calls `GetBytes()` to get the substring for the value.

WinICO::GetUInt32(&$data, &$x, $y)
----------------------------------

Access:  public static

Parameters:

* $data - A string containing the data.
* $x - An integer containing the starting position of the UInt32.
* $y - An integer containing the size/limit of the data.

Returns:  The UInt32 value at the specified position.

This static function returns the unsigned 32-bit value at the specified position and increments $x by 4.  Calls `GetBytes()` to get the substring for the value.

Technically not a UInt32 on 32-bit PHP but rather a signed Int32.  The WinICO class adapts automatically for most scenarios.

WinICO::GetBytes(&$data, &$x, $y, $size)
----------------------------------------

Access:  public static

Parameters:

* $data - A string containing the data.
* $x - An integer containing the starting position in the data.
* $y - An integer containing the size/limit of the data.
* $size - An integer containing the number of bytes to return.

Returns:  A string extracted from the data of the requested size.

This static function returns the requested number of bytes of data.  If $x goes past the end of the data, zeros pad out the remainder of the string that is returned.

WinICO::WICOTranslate($format, ...)
-----------------------------------

Access:  _internal_ static

Parameters:

* $format - A string containing valid sprintf() format specifiers.

Returns:  A string containing a translation.

This internal static function takes input strings and translates them from English to some other language if CS_TRANSLATE_FUNC is defined to be a valid PHP function name.
