<?php
/*
Author : Edouard Thivet <ed@suikatech.net>
Homepage : https://github.com/suikatech/PhpForHealthAPI
Licence : AGPLv3
*/

/**
 * Helper class to access the API
 * @author Edouard Thivet <ed@suikatech.net>
 * @version 1.0
 * 
 */
class PhpForHealthApi
{
	// Some useful variables

	/**
	 * Application Consumer Key
	 * 
	 * @see PhpForHealthApi#getConsumerKey()
	 * @see PhpForHealthApi#setConsumerKey($consumerKey)
	 */
	private $_consumerKey;

	/**
	 * Application Consumer Key Secret
	 * 
	 * @see PhpForHealthApi#getConsumerSecret()
	 * @see PhpForHealthApi#setConsumerSecret($consumerSecret)
	 */
	private $_consumerSecret;

	/**
	 * API Access Token
	 * 
	 * @see PhpForHealthApi#getAccessToken()
	 * @see PhpForHealthApi#setAccessToken($accessToken)
	 */
	private $_accessToken;

	/**
	 * API Access Token Secret
	 * 
	 * @see PhpForHealthApi#getAccessTokenSecret()
	 * @see PhpForHealthApi#setAccessTokenSecret($accessTokenSecret)
	 */
	private $_accessTokenSecret;
	
	// URLs to use

	/**
	 * URL to query for a request token
	 * @const URL_REQUEST_TOKEN
	 */
	const URL_REQUEST_TOKEN = "https://oauth.withings.com/account/request_token";

	/**
	 * Base URL for redirection authentication
	 * @const URL_AUTH
	 */
	const URL_AUTH = "https://oauth.withings.com/account/authorize";

	/**
	 * URL to query for an access token
	 * @const URL_ACCESS_TOKEN
	 */
	const URL_ACCESS_TOKEN = "https://oauth.withings.com/account/access_token";
	
	/**
	 * URL to query for measurements
	 * @const URL_MEASURE
	 */
	const URL_MEASURE = "https://wbsapi.withings.net/measure";

	/**
	 * URL to query for measurements v2
	 * @const URL_MEASURE_V2
	 */
	const URL_MEASURE_V2 = "https://wbsapi.withings.net/v2/measure";

	/**
	 * URL to query for sleep measurements
	 * @const URL_SLEEP
	 */
	const URL_SLEEP = "https://wbsapi.withings.net/v2/sleep";

	/**
	 * URL to query for notifications
	 * @const URL_NOTIFY
	 */
	const URL_NOTIFY = "https://wbsapi.withings.net/notify";
	
	
	/**
	 * Constructor for the class
	 * 
	 * @param consumerKey
	 * 		Consumer key of the application
	 * @param consumerSecret
	 * 		Consumer Secret of the application
	 * @param accessToken
	 * 		Access token to use
	 * @param accessTokenSecret
	 * 		Access token secret to use
	 */
	function __construct($consumerKey, $consumerSecret, $accessToken = "", $accessTokenSecret = "")
	{
		$this->setConsumerKey($consumerKey);
		$this->setConsumerSecret($consumerSecret);
		$this->setAccessToken($accessToken);
		$this->setAccessTokenSecret($accessTokenSecret);
	}

	/**
	 * Creates a context for http queries
	 * 
	 * @param httpKeyValue
	 * 		Array of values to use as http headers
	 * @param headerKeyValue
	 * 		Array of values to use as headers
	 * @param method
	 * 		Method to use (GET|POST)
	 * 
	 * @return A http context
	 */
	public function buildContext(array $httpKeyValue, array $headerKeyValue = array(), $method = "POST")
	{
		// use key 'http' even if you send the request to https://...
		$options = array(
			'http' => array(
				'header'  => "Content-type: application/x-www-form-urlencoded\r\n",
				'method'  => $method,
				'ignore_errors' => '1'
			),
		);
		
		foreach ($headerKeyValue as $key => $value)
		{
			$options['http']['header'] .= $key.": ".$value."\r\n";
		}

		foreach ($httpKeyValue as $key => $value)
		{
			$options['http'][$key] = $value;
		}

		return stream_context_create($options);
	}

	/**
	 * Generates a nonce
	 * 
	 * @return A nonce
	 */
	public function generateNonce()
	{
		return md5(time().rand());
	}
	
	/**
	 * Creates a parameter string to build the base string for signing
	 * 
	 * @param parameters
	 * 		Array of parameters
	 * 
	 * @return A string based on the parameters
	 */
	public function generateParameterString($parameters)
	{
		// Sort keys
		ksort($parameters);
		
		// Create parameter string
		$parameterString = '';
		
		foreach ($parameters as $key => $value)
		{
			if ($parameterString != '')
			{
				$parameterString .= '&';
			}
			
			$parameterString .= $key.'='.$value;
		}
		
		return $parameterString;
	}
	
	/**
	 * Creates the base string and generates the signature
	 * 
	 * @param method
	 * 		Method (GET|POST)
	 * @param requestUrl
	 * 		Url to query
	 * @param parameterString
	 * 		Parameter string build with PhpForHealthApi#generateParameterString
	 * @param consumerSecret
	 * 		Consumer Secret
	 * @param tokenSecret
	 * 		Token secret
	 * 
	 * @return Signature
	 */
	public function generateSignature($method, $requestUrl, $parameterString, $consumerSecret, $tokenSecret)
	{
		if ($method != 'POST' && $method != 'GET')
		{
			return false;
		}

		// Create signature base string
		$signatureBaseString = $method.'&'.rawurlencode($requestUrl).'&'.rawurlencode($parameterString);

		// Create signing key
		$signingKey = rawurlencode($consumerSecret).'&'.rawurlencode($tokenSecret);

		// Signature
		return base64_encode(hash_hmac('sha1', $signatureBaseString, $signingKey, true));
	}	
	
	/**
	 * Generates an auth string
	 * 
	 * @param parameters
	 * 		Array of parameters
	 * @param signature
	 * 		Signature
	 * 
	 * @return Auth String
	 */
	public function generateAuthString($parameters, $signature)
	{
		// Build auth string parameter
		$authString = 'OAuth ';
		
		foreach ($parameters as $key => $value)
		{
			// We only need oauth related parameters
			if ($key == 'oauth_consumer_key' || $key == 'oauth_nonce' || $key == 'oauth_callback' || $key == 'oauth_token' || $key == 'oauth_signature_method' || $key == 'oauth_timestamp' || $key == 'oauth_version')
			{
				if ($authString != 'OAuth ')
				{
					$authString .= '", ';
				}
				
				$authString .= rawurlencode($key).'="'.$value;
			}
		}
		
		$authString .= '", ';

		$authString .= rawurlencode('oauth_signature').'="'.rawurlencode($signature).'"';
		
		return $authString;
	}
	
	/**
	 * Builds a query string to be appended to the URL.
	 * It does not encode the parameter to avoid double encoding
	 * 
	 * @param parameters
	 * 		Array of parameters already url encoded
	 * 
	 * @return Query string
	 */
	public function http_build_query_noencode($parameters)
	{
		$query = "";
		foreach($parameters as $key => $parameter)
		{
			if ("" != $query)
			{
				$query .= "&";
			}
			$query .= $key.'='.$parameter;
		}
		return $query;
	}
	
	/**
	 * Builds an URL used for the authorization step (redirection of the user)
	 * 
	 * @param requestToken
	 * 		Request token fetched from the API (step 1)
	 * @param requestTokenSecret
	 * 		Request token secret fetched from the API (step 1)
	 * 
	 * @return Authorization URL
	 */
	public function generateAuthorizationUrl($requestToken, $requestTokenSecret)
	{
		// Create Nonce
		$nonce = $this->generateNonce();

		// Create parameter array
		$parameters = array();
				
		$parameters['oauth_consumer_key'] = rawurlencode($this->getConsumerKey());
		$parameters['oauth_nonce'] = rawurlencode($nonce);
		$parameters['oauth_token'] = rawurlencode($requestToken);
		$parameters['oauth_signature_method'] = rawurlencode('HMAC-SHA1');
		$parameters['oauth_timestamp'] = rawurlencode(time());
		$parameters['oauth_version'] = rawurlencode('1.0');

		// Create a parameter string
		$parameterString = $this->generateParameterString($parameters);

		// Create signature
		$signature = $this->generateSignature("GET", self::URL_AUTH, $parameterString, $this->getConsumerSecret(), $requestTokenSecret);		

		$parameters['oauth_signature'] = rawurlencode($signature);

		return self::URL_AUTH.'?'.http_build_query($parameters);
	}
	

	/**
	 * Sends a request to fetch the request token + secret
	 * 
	 * @param callbackUrl
	 * 		Callback URL to use when the user successfully authenticates
	 * 
	 * @return Request result
	 */
	public function sendGetRequestToken($callbackUrl)
	{
	
		// Request temporary credentials
		// Create Nonce
		$nonce = $this->generateNonce();

		// Create parameter array
		$parameters = array();
				
		$parameters['oauth_consumer_key'] = rawurlencode($this->getConsumerKey());
		$parameters['oauth_nonce'] = rawurlencode($nonce);
		$parameters['oauth_callback'] = rawurlencode($callbackUrl);
		$parameters['oauth_signature_method'] = rawurlencode('HMAC-SHA1');
		$parameters['oauth_timestamp'] = rawurlencode(time());
		$parameters['oauth_version'] = rawurlencode('1.0');

		// Create a parameter string
		$parameterString = $this->generateParameterString($parameters);

		// Create signature
		$signature = $this->generateSignature("GET", self::URL_REQUEST_TOKEN, $parameterString, $this->getConsumerSecret(), "");		
		
		// Create an auth string
		$authString = $this->generateAuthString($parameters, $signature);
		
		// Build context
		$headersKeyValue = array('Authorization' => $authString);
		$context = $this->buildContext(array(), $headersKeyValue, 'GET');
		
		$parameters['oauth_signature'] = rawurlencode($signature);

		// Get Tokens
		$serverAnswer = file_get_contents(self::URL_REQUEST_TOKEN.'?'.http_build_query($parameters), false, $context);
		
		
		return $serverAnswer;
	}

	/**
	 * Sends a request to fetch the access token + secret
	 * 
	 * @param oauthToken
	 * 		Token provided by the API once the user successfully authenticates
	 * @param requestTokenSecret
	 * 		Request token secret fetched from the API (step 1)
	 * @param userid
	 * 		User id
	 * 
	 * @return Request result
	 */
	public function sendGetAccessToken($oauthToken, $requestTokenSecret, $userid)
	{
	
		// Request temporary credentials
		// Create Nonce
		$nonce = $this->generateNonce();

		// Create parameter array
		$parameters = array();
		
		$parameters['oauth_consumer_key'] = rawurlencode($this->getConsumerKey());
		$parameters['oauth_nonce'] = rawurlencode($nonce);
		$parameters['oauth_token'] = rawurlencode($oauthToken);
		$parameters['oauth_signature_method'] = rawurlencode('HMAC-SHA1');
		$parameters['oauth_timestamp'] = rawurlencode(time());
		$parameters['oauth_version'] = rawurlencode('1.0');

		// Userid
		$parameters['userid'] = rawurlencode($userid);

		// Create a parameter string
		$parameterString = $this->generateParameterString($parameters);

		// Create signature
		$signature = $this->generateSignature("GET", self::URL_ACCESS_TOKEN, $parameterString, $this->getConsumerSecret(), $requestTokenSecret);		

		// Create an auth string
		$authString = $this->generateAuthString($parameters, $signature);
		
		// Build context
		$headersKeyValue = array('Authorization' => $authString);
		$context = $this->buildContext(array(), $headersKeyValue, 'GET');
		
		$parameters['oauth_signature'] = rawurlencode($signature);

		// Get Tokens
		$serverAnswer = file_get_contents(self::URL_ACCESS_TOKEN.'?'.http_build_query($parameters), false, $context);
		
		return $serverAnswer;				
	}

	/**
	 * Sends a signed request to the API
	 * 
	 * @param method
	 * 		Method (GET|POST)
	 * @param requestUrl
	 * 		URL to query
	 * @param args
	 * 		Array of arguments to send
	 * 
	 * @return Request result
	 */
	public function sendSignedRequest($method, $requestUrl, $args = array())
	{	
		// Create Nonce
		$nonce = $this->generateNonce();

		// Create parameter array
		$parameters = array();
		
		// GET Params
		foreach ($args as $key => $value)
		{
			$parameters[rawurlencode($key)] = rawurlencode($value);
		}
		
		$parameters['oauth_consumer_key'] = rawurlencode($this->getConsumerKey());
		$parameters['oauth_nonce'] = rawurlencode($nonce);
		$parameters['oauth_token'] = rawurlencode($this->getAccessToken());
		$parameters['oauth_signature_method'] = rawurlencode('HMAC-SHA1');
		$parameters['oauth_timestamp'] = rawurlencode(time());
		$parameters['oauth_version'] = rawurlencode('1.0');

		// Create a parameter string
		$parameterString = $this->generateParameterString($parameters);

		// Create signature
		$signature = $this->generateSignature($method, $requestUrl, $parameterString, $this->getConsumerSecret(), $this->getAccessTokenSecret());		

		// Create an auth string
		$authString = $this->generateAuthString($parameters, $signature);
		
		$parameters['oauth_signature'] = rawurlencode($signature);

		// Build context
		$headersKeyValue = array('Authorization' => $authString);

		// If post method
		if ($method == "POST")
		{
			// Query content
			$httpHeader = array ('content' => http_build_query($args));
			
			// Build context
			$context = $this->buildContext($httpHeader, $headersKeyValue);
			
			// Get response
			$serverAnswer = file_get_contents($requestUrl, false, $context);
		}
		else
		{
			// Assume GET
			// Build context
			$context = $this->buildContext(array(), $headersKeyValue, 'GET');

			// Get response
			$serverAnswer = file_get_contents($requestUrl.'?'.$this->http_build_query_noencode($parameters), false, $context);			
		}

		return $serverAnswer;
	}
	
	
	/**
	 * Get Activity Measurements
	 * 
	 * @param userid
	 * 		User id
	 * @param date
	 * 		(optional) Date YYYY-mm-dd
	 * @param startdateymd
	 * 		(optional) Start date YYYY-mm-dd
	 * @param enddateymd
	 * 		(optional) End date YYYY-mm-dd
	 * 
	 * @return Request result
	 */
	public function getMeasureActivity($userid, $date = -1, $startdateymd = -1, $enddateymd = -1)
	{
		// Create args
		$args = array();
		$args['action'] = 'getactivity';
		
		$args['userid'] = $userid;
		if ($date != -1)
		{
			$args['date'] = $date;
		}
		if ($startdateymd != -1)
		{
			$args['startdateymd'] = $startdateymd;
		}
		if ($enddateymd != -1)
		{
			$args['enddateymd'] = $enddateymd;
		}
		
		return $this->sendSignedRequest('GET', self::URL_MEASURE_V2, $args);
	}
	
	
	/**
	 * Get Body Measurements
	 * 
	 * @param userid
	 * 		User id
	 * @param startdateymd
	 * 		(optional) Start date as timestamp
	 * @param enddateymd
	 * 		(optional) End date as timestamp
	 * @param lastupdate
	 * 		(optional) Since Date as timestamp
	 * 					1 => Weight (kg)
	 * 					4 => Height (meter)
	 * 					5 => Fat Free Mass (kg)
	 * 					6 => Fat Ratio (%)
	 * 					8 => Fat Mass Weight (kg)
	 * 					9 => Diastolic Blood Pressure (mmHg)
	 * 					10 => Systolic Blood Pressure (mmHg)
	 * 					11 => Heart Pulse (bpm)
	 * 					54 => SP02 (%)
	 * @param meastype
	 * 		(optional) Type of measurements filter
	 * @param category
	 * 		(optional) Category (1 => measurements | 2 => objectives)
	 * @param limit
	 * 		(optional) Maximum number of measurements to return
	 * @param offset
	 * 		(optional) Skip offset
	 * 
	 * @return Request result
	 */
	public function getMeasureBody($userid, $startdate = -1, $enddate = -1, $lastupdate = -1, $meastype = -1, $category = -1, $limit = -1, $offset = -1)
	{
		// Create args
		$args = array();
		$args['action'] = 'getmeas';
		
		$args['userid'] = $userid;
		if ($startdate != -1)
		{
			$args['startdate'] = $startdate;
		}
		if ($enddate != -1)
		{
			$args['enddate'] = $enddate;
		}
		if ($lastupdate != -1)
		{
			$args['lastupdate'] = $lastupdate;
		}
		if ($meastype != -1)
		{
			$args['meastype'] = $meastype;
		}
		if ($category != -1)
		{
			$args['category'] = $category;
		}
		if ($limit != -1)
		{
			$args['limit'] = $limit;
		}
		if ($offset != -1)
		{
			$args['offset'] = $offset;
		}
		
		return $this->sendSignedRequest('GET', self::URL_MEASURE, $args);
	}	

	/**
	 * Get Intraday Activity Measurements
	 * 
	 * @param userid
	 * 		User id
	 * @param startdate
	 * 		Start date as timestamp
	 * @param enddate
	 * 		End date as timestamp
	 * 
	 * @return Request result
	 */
	public function getMeasureIntraday($userid, $startdate, $enddate)
	{
		// Create args
		$args = array();
		$args['action'] = 'getintradayactivity';
		
		$args['userid'] = $userid;
		$args['startdate'] = $startdate;
		$args['enddate'] = $enddate;
		
		return $this->sendSignedRequest('GET', self::URL_MEASURE_V2, $args);
	}	

	/**
	 * Get Sleep Measurements
	 * 
	 * @param userid
	 * 		User id
	 * @param startdate
	 * 		Start date as timestamp
	 * @param enddate
	 * 		End date as timestamp
	 * 
	 * @return Request result
	 */
	public function getMeasureSleep($userid, $startdate, $enddate)
	{
		// Create args
		$args = array();
		$args['action'] = 'get';
		
		$args['userid'] = $userid;
		$args['startdate'] = $startdate;
		$args['enddate'] = $enddate;
		
		return $this->sendSignedRequest('GET', self::URL_SLEEP, $args);
	}	

	/**
	 * Get Sleep Summary
	 * 
	 * @param userid
	 * 		User id
	 * @param startdate
	 * 		Start date as timestamp
	 * @param enddate
	 * 		End date as timestamp
	 * 
	 * @return Request result
	 */
	public function getMeasureSleepSummary($userid, $startdate, $enddate)
	{
		// Create args
		$args = array();
		$args['action'] = 'getsummary';
		
		$args['userid'] = $userid;
		$args['startdate'] = $startdate;
		$args['enddate'] = $enddate;
		
		return $this->sendSignedRequest('GET', self::URL_SLEEP, $args);
	}
	
	/**
	 * Create a notification
	 * 
	 * @param userid
	 * 		User id
	 * @param callbackurl
	 * 		Callback URL
	 * @param comment
	 * 		Comment shown to user
	 * @param appli
	 * 		(optional) Application
	 * 					1 => Body Scale
	 * 					4 => Blood pressure monitor
	 * 					16 => Withings pulse
	 * 					44 => Sleep monitor
	 * 
	 * @return Request result
	 */
	public function getNotificationSuscribe($userid, $callbackurl, $comment, $appli = -1)
	{
		// Create args
		$args = array();
		$args['action'] = 'subscribe';
		
		$args['userid'] = $userid;
		$args['callbackurl'] = $callbackurl;
		$args['comment'] = $comment;
		if ($appli != -1)
		{
			$args['appli'] = $appli;
		}
		
		return $this->sendSignedRequest('GET', self::URL_NOTIFY, $args);
	}
	
	/**
	 * Get a notification
	 * 
	 * @param userid
	 * 		User id
	 * @param callbackurl
	 * 		Callback URL
	 * @param appli
	 * 		(optional) Application
	 * 					1 => Body Scale
	 * 					4 => Blood pressure monitor
	 * 					16 => Withings pulse
	 * 					44 => Sleep monitor
	 * 
	 * @return Request result
	 */
	public function getNotification($userid, $callbackurl, $appli = -1)
	{
		// Create args
		$args = array();
		$args['action'] = 'get';
		
		$args['userid'] = $userid;
		$args['callbackurl'] = $callbackurl;
		if ($appli != -1)
		{
			$args['appli'] = $appli;
		}
		
		return $this->sendSignedRequest('GET', self::URL_NOTIFY, $args);
	}
		
	/**
	 * Get notification list
	 * 
	 * @param userid
	 * 		User id
	 * @param appli
	 * 		(optional) Application
	 * 					1 => Body Scale
	 * 					4 => Blood pressure monitor
	 * 					16 => Withings pulse
	 * 					44 => Sleep monitor
	 * 
	 * @return Request result
	 */
	public function getNotificationList($userid, $appli = -1)
	{
		// Create args
		$args = array();
		$args['action'] = 'list';
		
		$args['userid'] = $userid;
		if ($appli != -1)
		{
			$args['appli'] = $appli;
		}
		
		return $this->sendSignedRequest('GET', self::URL_NOTIFY, $args);
	}	
		
	/**
	 * Revoke a notification
	 * 
	 * @param userid
	 * 		User id
	 * @param callbackurl
	 * 		Callback URL
	 * @param appli
	 * 		(optional) Application
	 * 					1 => Body Scale
	 * 					4 => Blood pressure monitor
	 * 					16 => Withings pulse
	 * 					44 => Sleep monitor
	 * 
	 * @return Request result
	 */
	public function getNotificationRevoke($userid, $callbackurl, $appli = -1)
	{
		// Create args
		$args = array();
		$args['action'] = 'revoke';
		
		$args['userid'] = $userid;
		$args['callbackurl'] = $callbackurl;
		if ($appli != -1)
		{
			$args['appli'] = $appli;
		}
		
		return $this->sendSignedRequest('GET', self::URL_NOTIFY, $args);
	}	


	// Getters and Setters

	/**
	 * Getter for consumerKey
	 * 
	 * @return consumerKey
	 */
	public function getConsumerKey()
	{
		return $this->_consumerKey;
	}

	/**
	 * Setter for consumerKey
	 * 
	 * @param consumerKey
	 * 		ConsumerKey
	 */
	public function setConsumerKey($consumerKey)
	{
		$this->_consumerKey = $consumerKey;
	}

	/**
	 * Getter for consumerSecret
	 * 
	 * @return consumerSecret
	 */
	public function getConsumerSecret()
	{
		return $this->_consumerSecret;
	}

	/**
	 * Setter for consumerSecret
	 * 
	 * @param consumerSecret
	 * 		consumerSecret
	 */
	public function setConsumerSecret($consumerSecret)
	{
		$this->_consumerSecret = $consumerSecret;
	}	

	/**
	 * Getter for accessToken
	 * 
	 * @return accessToken
	 */
	public function getAccessToken()
	{
		return $this->_accessToken;
	}

	/**
	 * Setter for accessToken
	 * 
	 * @param accessToken
	 * 		accessToken
	 */
	public function setAccessToken($accessToken)
	{
		$this->_accessToken = $accessToken;
	}
	
	/**
	 * Getter for accessTokenSecret
	 * 
	 * @return accessTokenSecret
	 */
	public function getAccessTokenSecret()
	{
		return $this->_accessTokenSecret;
	}

	/**
	 * Setter for accessTokenSecret
	 * 
	 * @param accessTokenSecret
	 * 		accessTokenSecret
	 */
	public function setAccessTokenSecret($accessTokenSecret)
	{
		$this->_accessTokenSecret = $accessTokenSecret;
	}	
}
