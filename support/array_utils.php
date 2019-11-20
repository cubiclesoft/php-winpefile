<?php
	// CubicleSoft PHP associative array utility functions.
	// (C) 2019 CubicleSoft.  All Rights Reserved.

	class ArrayUtils
	{
		// Inserts one or more key-value array parameters after the specified key.  Overrides existing keys in $data.
		// If $findkey can't be found, the returned array will be identical to the input array.
		public static function InsertAfterKey($data, $findkey, ...$params)
		{
			if (!is_array($data))  return $data;

			if ($findkey === false)  $findkey = null;
			if (!is_null($findkey) && !is_string($findkey) && !is_int($findkey))  $findkey = (string)$findkey;

			$keys = array();
			$result = array();
			$inserted = false;
			foreach ($data as $key => $val)
			{
				if ($findkey !== null && !isset($keys[$key]))
				{
					$result[$key] = $val;

					$keys[$key] = true;
				}

				if (!$inserted && ($findkey === null || $key === $findkey))
				{
					$x = 0;
					$y = count($params);
					for ($x = 0; $x < $y; $x++)
					{
						if (!is_array($params[$x]))  $params[$x] = array($params[$x]);

						foreach ($params[$x] as $key2 => $val2)
						{
							unset($result[$key2]);
							$result[$key2] = $val2;
						}
					}

					$inserted = true;
				}

				if ($findkey === null && !isset($keys[$key]))
				{
					$result[$key] = $val;

					$keys[$key] = true;
				}
			}

			return $result;
		}

		// Inserts one or more key-value array parameters before the specified key.  Overrides existing keys in $data.
		// If $findkey can't be found, the returned array will be identical to the input array.
		public static function InsertBeforeKey($data, $findkey, ...$params)
		{
			if (!is_array($data))  return $data;

			if ($findkey === false)  $findkey = null;
			if (!is_null($findkey) && !is_string($findkey) && !is_int($findkey))  $findkey = (string)$findkey;

			$keys = array();
			$result = array();
			$inserted = false;
			foreach ($data as $key => $val)
			{
				if (!$inserted && $key === $findkey)
				{
					$x = 0;
					$y = count($params);
					for ($x = 0; $x < $y; $x++)
					{
						if (!is_array($params[$x]))  $params[$x] = array($params[$x]);

						foreach ($params[$x] as $key2 => $val2)
						{
							unset($result[$key2]);
							$result[$key2] = $val2;
						}
					}

					$inserted = true;
				}

				if (!isset($keys[$key]))
				{
					$result[$key] = $val;

					$keys[$key] = true;
				}
			}

			if (!$inserted && $findkey === null)
			{
				$x = 0;
				$y = count($params);
				for ($x = 0; $x < $y; $x++)
				{
					if (!is_array($params[$x]))  $params[$x] = array($params[$x]);

					foreach ($params[$x] as $key2 => $val2)
					{
						unset($result[$key2]);
						$result[$key2] = $val2;
					}
				}
			}

			return $result;
		}
	}
?>