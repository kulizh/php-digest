<?php
// RFC 2617: http://www.faqs.org/rfcs/rfc2617.html

include dirname(__FILE__) . '/.functions.php';

$realm = 'Restricted Area';
$filename = '.D79096188B670C2F81B7';
$users = read_auth_data($filename);

if (empty($_SERVER['PHP_AUTH_DIGEST']))
{
	send_header($realm);
	die('Auth canceled');
}

if (!($data = http_digest_parse($_SERVER['PHP_AUTH_DIGEST'])) 
    || 
    !isset($users[$data['username']]))
{	
	send_header($realm);
}

$A1 = md5($data['username'] . ':' . $realm . ':' . $users[$data['username']]);
$A2 = md5($_SERVER['REQUEST_METHOD'] . ':' . $data['uri']);

$valid_response = md5($A1.':'.$data['nonce'].':'.$data['nc'].':'.$data['cnonce'].':'.$data['qop'].':'.$A2);

if ($data['response'] != $valid_response)
{
	send_header($realm);
}
