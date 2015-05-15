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


// Check if the variables are set
if (isset($_GET['oauth_token']) && isset($_GET['userid']))
{
	// Create a PhpForHealthApi instance
	$phpForHealthApi = new PhpForHealthApi($consumerKey, $consumerSecret);

	// Get acces tokens
	if (($serverAnswer = $phpForHealthApi->sendGetAccessToken($_GET['oauth_token'], $fileStorer->getKey('requestTokenSecret'), $_GET['userid'])) !== false)
	{
		// Parse response
		parse_str($serverAnswer, $tempTokens);
		$fileStorer->updateKey('userid', $_GET['userid']);
		$fileStorer->updateKey('accessToken', $tempTokens['oauth_token']);
		$fileStorer->updateKey('accessTokenSecret', $tempTokens['oauth_token_secret']);	
		
		// We have now an access token that we can use
		echo "Credentials: "."<br />";
		echo "User Id : ".$_GET['userid']."<br />";
		echo "Access Token : ".$tempTokens['oauth_token']."<br />";
		echo "Access Token Secret : ".$tempTokens['oauth_token_secret']."<br />"."<br />";

		// Link to getMeasureActivity demo
		echo "Demo: "."<br />";
		echo "<a href='./getMeasureActivity.php'>getMeasureActivity</a>";
	}
}
?>
