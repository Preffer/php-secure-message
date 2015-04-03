<?php
set_error_handler(function($severity, $message, $file, $line) {
	throw new ErrorException($message, $severity, $severity, $file, $line);
});

try {
	switch ($GLOBALS['argv'][1]) {
		case 'all':
			$names = generate(['alice', 'bob']);
			$signed = sign('sample.pdf', $names[0]);
			$encrypted = encrypt($signed, $names[1]);
			break;

		case 'generate':
			generate(array_slice($GLOBALS['argv'], 2));
			break;

		case 'sign':
			sign($GLOBALS['argv'][2], $GLOBALS['argv'][3]);
			break;

		case 'encrypt':
			encrypt($GLOBALS['argv'][2], $GLOBALS['argv'][3]);
			break;

		case 'decrypt':
			decrypt($GLOBALS['argv'][2], $GLOBALS['argv'][3]);
			break;

		default:
			throw new Exception('Unknown action');
	}
} catch (Exception $e) {
	$filename = $GLOBALS['argv'][0];
	$message = $e->getMessage();

	echo("$message\n");
	echo("Usage: php {$filename} {all|generate|sign|encrypt|decrypt|verify} [arg]\n");
	echo("Example:\n");
	echo("\tphp {$filename} generate alice bob\n");
	echo("\tphp {$filename} sign sample.pdf alice\n");
	echo("\tphp {$filename} encrypt sample.pdf.sign bob\n");
}

function generate($names) {
	if (empty($names)) {
		trigger_error('Missing names');
	} else {
		foreach ($names as $name) {
			$res = openssl_pkey_new();

			//$private and $publc hold the content of the key
			openssl_pkey_export($res, $private);
			$public = openssl_pkey_get_details($res)['key'];

			file_put_contents("{$name}_public.pem", $public);
			file_put_contents("{$name}_private.pem", $private);
			echo("Generated a pair of key: {$name}_public.pem {$name}_private.pem\n");
		}
	}

	return $names;
}

function sign($file, $author) {
	$data = file_get_contents($file);
	$private = file_get_contents("{$author}_private.pem");

	openssl_sign($data, $signature, $private);

	$pack = new PharData("{$file}.sign");
	$pack->addFile($file);
	$pack->addFromString("sign", $signature);

	echo("Signed as {$author}: {$file}.sign\n");
	return "{$file}.sign";
}

function encrypt($file, $recipient) {
	$data = file_get_contents($file);
	$public = file_get_contents("{$recipient}_public.pem");

	openssl_seal($data, $sealed, $keys, [$public]);

	$pack = new PharData("{$file}.encrypt");
	$pack->addFromString("{$file}", $sealed);
	$pack->addFromString("key", $keys[0]);

	echo("Encrypted for ${recipient}: {$file}.encrypt\n");
	return "{$file}.encrypt";
}

?>
