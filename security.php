<?php

/**
 * OpenSSL based secure message processor
 *
 * @author		Huang Yuzhong
 */

set_error_handler(function($severity, $message, $file, $line) {
	throw new ErrorException($message, $severity, $severity, $file, $line);
});

try {
	switch ($GLOBALS['argv'][1]) {
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

		case 'verify':
			verify($GLOBALS['argv'][2], $GLOBALS['argv'][3]);
			break;

		case 'newname':
			newname($GLOBALS['argv'][2]);
			break;

		case 'send':
			send($GLOBALS['argv'][2], $GLOBALS['argv'][3], $GLOBALS['argv'][4]);
			break;

		case 'receive':
			receive($GLOBALS['argv'][2], $GLOBALS['argv'][3], $GLOBALS['argv'][4]);
			break;

		case 'all':
			all();
			break;

		default:
			throw new Exception('Unknown action');
	}
} catch (Exception $e) {
	$filename = $GLOBALS['argv'][0];

	echo("{$e->getMessage()}\n\n");

	echo("Usage: php {$filename} {all|generate|send|receive|sign|encrypt|decrypt|verify|newname} [arg]\n");
	echo("Example:\n");
	echo("\tphp {$filename} all\n");
	echo("\tphp {$filename} generate alice bob\n");
	echo("\tphp {$filename} send sample.pdf alice bob\n");
	echo("\tphp {$filename} receive sample.pdf.signed.encrypted bob alice\n");
	echo("\tphp {$filename} sign sample.pdf alice\n");
	echo("\tphp {$filename} encrypt sample.pdf.signed bob\n");
	echo("\tphp {$filename} decrypt sample.pdf.signed.encrypted bob\n");
	echo("\tphp {$filename} verify sample.pdf.signed.encrypted.decrypted alice\n");
	echo("\tphp {$filename} newname sample.pdf.signed.encrypted.decrypted.verifyed\n");
}

function generate($names) {
	if (empty($names)) {
		throw new Exception('Missing names');
	} else {
		foreach ($names as $name) {
			$res = openssl_pkey_new();

			//$private and $publc hold the content of the key
			openssl_pkey_export($res, $private);
			$public = openssl_pkey_get_details($res)['key'];

			file_put_contents("{$name}_public.pem", $public);
			file_put_contents("{$name}_private.pem", $private);
			echo("Generate a pair of key: {$name}_public.pem {$name}_private.pem\n");
		}
		return $names;
	}
}

function sign($file, $author) {
	$data = file_get_contents($file);
	$private = file_get_contents("{$author}_private.pem");

	openssl_sign($data, $signature, $private);

	$pack = new PharData("{$file}.signed");
	$pack->addFile($file);
	$pack->addFromString("sign", $signature);

	echo("Signed as {$author}: {$file}.signed\n");
	return "{$file}.signed";
}

function encrypt($file, $recipient) {
	$data = file_get_contents($file);
	$public = file_get_contents("{$recipient}_public.pem");

	openssl_seal($data, $sealed, $keys, [$public]);

	$pack = new PharData("{$file}.encrypted");
	$pack->addFromString("{$file}", $sealed);
	$pack->addFromString("key", $keys[0]);

	echo("Encrypted for ${recipient}: {$file}.encrypted\n");
	return "{$file}.encrypted";
}

function decrypt($file, $recipient) {
	$pack = new PharData($file, Phar::KEY_AS_FILENAME);

	foreach ($pack as $name => $object) {
		if ($name === 'key') {
			$key = $object->getContent();
		} else {
			$sealed = $object->getContent();
		}
	}

	$private = file_get_contents("{$recipient}_private.pem");

	if (openssl_open($sealed, $data, $key, $private)) {
		file_put_contents("{$file}.decrypted", $data);
		echo("Decrypted as for ${recipient}: {$file}.decrypted\n");
		return "{$file}.decrypted";
	} else {
		throw new Exception("## This file isn't for {$recipient}! ##");
	}
}

function verify($file, $author) {
	$pack = new PharData($file, Phar::KEY_AS_FILENAME);

	foreach ($pack as $name => $object) {
		if ($name === 'sign') {
			$sign = $object->getContent();
		} else {
			$data = $object->getContent();
		}
	}

	$public = file_get_contents("{$author}_public.pem");

	if(openssl_verify($data, $sign, $public)) {
		file_put_contents("{$file}.verifyed", $data);
		echo("Verifyed as from ${author}: {$file}.verifyed\n");
		return "{$file}.verifyed";
	} else {
		throw new Exception("## This file isn't from {$author}! ##");
	}
}

function newname($file) {
	$newname = substr($file, 0, strpos($file, '.signed.encrypted.decrypted.verifyed'));

	if (file_exists($newname)) {
		$newname = 'copy_' . $newname;
	}

	copy($file, $newname);
	echo("Newnamed to {$newname}\n");
	echo("Congratulation!\n");

	return $newname;
}

function send($file, $author, $recipient) {
	$signed = sign($file, $author);
	$encrypted = encrypt($signed, $recipient);
	return $encrypted;
}

function receive($file, $recipient, $author) {
	$decrypted = decrypt($file, $recipient);
	$verifyed = verify($decrypted, $author);
	$newnamed = newname($verifyed);
	return $newnamed;
}

function all() {
	$names = generate(['alice', 'bob']);
	$sent = send('sample.pdf', $names[0], $names[1]);
	$received = receive($sent, $names[1], $names[0]);
	return $received;
}

?>
