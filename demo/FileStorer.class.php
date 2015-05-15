<?php
/*
Author : Edouard Thivet <ed@suikatech.net>
Homepage : https://github.com/suikatech/
Licence : AGPLv3
*/

class FileStorer
{
	private $_fileName;
	private $_dataArray;
	
	function __construct($fileName)
	{
		$this->_fileName = $fileName;
		$this->_dataArray = array();
	}
	
	public function addKey($key, $value)
	{
		// Get Array
		$this->getArray();
		if (array_key_exists($key, $this->_dataArray) === false)
		{
			// Add to array
			$this->_dataArray[$key] = $value;
			// Write
			if ($this->writeArray() !== false)
			{
				return true;
			}
		}
		return false;
	}
	
	public function updateKey($key, $value)
	{
		// Get Array
		$this->getArray();
		if (array_key_exists($key, $this->_dataArray) === false)
		{
			return $this->addKey($key, $value);
		}
		else
		{
			// Update array
			$this->_dataArray[$key] = $value;
			// Write
			if ($this->writeArray() !== false)
			{
				return true;
			}			
		}		
		return false;
	}
	
	public function getKey($key)
	{
		// Get Array
		$this->getArray();
		if (array_key_exists($key, $this->_dataArray) !== false)
		{
			// Return value
			return $this->_dataArray[$key];
		}
		return false;
	}
	
	private function getArray()
	{
		// Does the file exists ?
		if (file_exists($this->_fileName) !== false)
		{
			// Read content
			$jsonArray = file_get_contents($this->_fileName);
			// Decode it
			$this->_dataArray = json_decode($jsonArray, true);
		}
	}
	
	private function writeArray()
	{
		// Json Encode array
		$jsonArray = json_encode($this->_dataArray);
		
		// Write it to file
		return file_put_contents($this->_fileName, $jsonArray);
	}
}
