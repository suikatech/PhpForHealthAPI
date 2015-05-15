<?php
// Variables to edit
$consumerKey = YOUR_CONSUMER_KEY;
$consumerSecret = YOUR_CONSUMER_SECRET;
$callbackUrl = YOUR_CALLBACK_URL; // ex:'http://domainname/getAccessToken.php'



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
$phpForHealthApi = new PhpForHealthApi($consumerKey, $consumerSecret);

// Try to get request token
if (($serverAnswer = $phpForHealthApi->sendGetRequestToken($callbackUrl)) !== false)
{
	// Parse response
	parse_str($serverAnswer, $tempTokens);
	$fileStorer->updateKey('requestToken', $tempTokens['oauth_token']);
	$fileStorer->updateKey('requestTokenSecret', $tempTokens['oauth_token_secret']);	
	
	// Redirect
	$authUrl = $phpForHealthApi->generateAuthorizationUrl($tempTokens['oauth_token'], $tempTokens['oauth_token_secret']);
	header("Location: ".$authUrl);
}
?>
