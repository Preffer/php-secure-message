<?php
set_error_handler('errorHandler');

function errorHandler($severity, $message, $filename, $lineno) {
	$filename = $GLOBALS['argv'][0];

	echo("$message\n");
	echo("Usage: php {$filename} {generate|sign|encrypt|decrypt|verify} [arg]\n");
	echo("Example:\n");
	echo("\tphp {$filename} generate alice bob\n");
	echo("\tphp {$filename} sign sample.pdf alice\n");
	echo("\tphp {$filename} encrypt sample.pdf.sign.tar bob\n");
	exit(1);
}

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

	default:
		trigger_error('Unknown action');
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

function sign($file, $name) {
	$data = file_get_contents($file);
	$private = file_get_contents("{$name}_private.pem");

	openssl_sign($data, $signature, $private);
	file_put_contents("{$file}.{$name}", $signature);

	$pack = new PharData("{$file}.{$name}.tar");
	$pack->addFile($file);
	$pack->addFile("{$file}.{$name}");

	echo("Signed pack has saved to {$file}.{$name}.tar\n");
	unlink("{$file}.{$name}");

	return "{$file}.{$name}.tar";
}

function encrypt($file, $name) {
	$data = file_get_contents($file);
	$public = file_get_contents("{$name}_public.pem");

	openssl_seal($data, $sealed, $keys, [$public]);

	file_put_contents("{$file}.${name}", $sealed);
	file_put_contents("{$file}.key", $keys[0]);

	$pack = new PharData("{$file}.${name}.tar");
	$pack->addFile("{$file}.${name}");
	$pack->addFile("{$file}.key");

	echo("Encrypted pack has saved to {$file}.${name}.tar\n");
	unlink("{$file}.${name}");
	unlink("{$file}.key");

	return "{$file}.{$name}.tar";
}

?>
