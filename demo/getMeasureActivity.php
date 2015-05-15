<?php
// Variables to edit
$consumerKey = YOUR_CONSUMER_KEY;
$consumerSecret = YOUR_CONSUMER_SECRET;




// Including the class
require_once('../PhpForHealthApi.class.php');

// Including a FileStorer class
// This is a simple class used for testing purposes ONLY which stores the tokens
// You should use something more secure in production 
require_once('FileStorer.class.php');
// File storer is for testing purposes
// test.store is the file holding our tokens
$fileStorer = new FileStorer('test.store');

// Create a PhpForHealthApi instance
$phpForHealthApi = new PhpForHealthApi($consumerKey, $consumerSecret, $fileStorer->getKey('accessToken'), $fileStorer->getKey('accessTokenSecret'));

// Send query and display results
echo $phpForHealthApi->getMeasureActivity($fileStorer->getKey('userid'), '2013-05-15');
?>
