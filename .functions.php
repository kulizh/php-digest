<?php

function send_header(string $realm)
{
    header('HTTP/1.1 401 Unauthorized');
	header('WWW-Authenticate: Digest realm="' . $realm . 
    '",qop="auth",nonce="' . uniqid() . '",opaque="' . md5($realm) . '"');
}

function http_digest_parse(string $auth_digest_string): string
{
	$needed_parts = [
        'nonce' => 1, 
        'nc' => 1, 
        'cnonce' => 1, 
        'qop' =>  1, 
        'username' => 1, 
        'uri' => 1, 
        'response' => 1
    ];

	$data = array();
	$keys = implode('|', array_keys($needed_parts));

	preg_match_all('@(' . $keys . ')=(?:([\'"])([^\2]+?)\2|([^\s,]+))@', $auth_digest_string, $matches, PREG_SET_ORDER);

	foreach ($matches as $m)
	{
		$data[$m[1]] = $m[3] ? $m[3] : $m[4];

		unset($needed_parts[$m[1]]);
	}

	return $needed_parts
        ? '' 
        : $data;
}

function read_auth_data(string $credits_filename): array
{
	$file = realpath(dirname(__FILE__) . '/' . $credits_filename);

	$handle = fopen($file, 'r');
	$credits = [];

	if ($handle)
	{
		while (($buffer = fgets($handle, 4096)) !== false)
		{
			if (strrpos($buffer, ':') === false)
			{
				continue;
			}

			$exploded = explode(':', $buffer);

			if (empty($exploded[0]))
			{
				continue;
			}

			$pass = trim(str_replace($exploded[0] . ':', '', $buffer));

			$credits[trim($exploded[0])] = $pass;
		}

		if (!feof($handle))
		{
			die('Internal Server Error');
		}

		fclose($handle);
	}

	return $credits;
}