<?php
/**
 * This file is a part of the phpMussel\Core package.
 * Homepage: https://phpmussel.github.io/
 *
 * PHPMUSSEL COPYRIGHT 2013 AND BEYOND BY THE PHPMUSSEL TEAM.
 */

/**
 * If this file remains intact after deploying the package to production,
 * preventing it from running outside of Composer may be useful as a means of
 * preventing potential attackers from hammering it and needlessly wasting
 * cycles at the server.
 */
if (!isset($_SERVER['COMPOSER_BINARY'])) {
    die;
}

// Suppress unexpected errors from output and exit early as a failure when encountered.
set_error_handler(function ($errno, $errstr, $errfile, $errline) {
    echo 'Error triggered: ' . $errstr . PHP_EOL;
    exit(1);
});

// Need this to find the package's own files (since it isn't installing itself).
spl_autoload_register(function ($Class) {
    $Class = explode('\\', $Class, 3);
    $Count = count($Class);
    if ($Count !== 3 || $Class[0] !== 'phpMussel' || $Class[1] !== 'Core') {
        return;
    }
    $Class = str_replace(['/', '\\'], DIRECTORY_SEPARATOR, $Class[2]);
    $Try = __DIR__ . DIRECTORY_SEPARATOR . 'src' . DIRECTORY_SEPARATOR . $Class . '.php';
    if (is_readable($Try)) {
        require $Try;
    }
});

$Autoloader = __DIR__ . DIRECTORY_SEPARATOR . 'vendor' . DIRECTORY_SEPARATOR . 'autoload.php';
if (!is_readable($Autoloader)) {
    echo 'Autoloader is not readable.' . PHP_EOL;
    exit(2);
}
require $Autoloader;

// Path to all tests data.
$TestsPath = __DIR__ . DIRECTORY_SEPARATOR . '.tests' . DIRECTORY_SEPARATOR;

// Fetch the signatures needed for testing the scanner.
$ZipObj = new \ZipArchive();
if ($ZipObj->open($TestsPath . 'signatures.zip') === true) {
    $SigPath = $TestsPath . 'signatures';
    $ZipObj->extractTo($SigPath . DIRECTORY_SEPARATOR);
    $ZipObj->close();
    unset($ZipObj);
} else {
    echo 'Problem encountered trying to open signatures.zip.' . PHP_EOL;
    exit(3);
}

$Samples = $TestsPath . 'samples';

$Config = $TestsPath . 'phpmussel.yml';
if (!is_readable($Config) || !is_readable($Samples) || !is_readable($SigPath)) {
    echo 'Configuration, samples, or signatures are not readable.' . PHP_EOL;
    exit(4);
}

$Loader = new \phpMussel\Core\Loader($Config, '', '', $SigPath);
$Scanner = new \phpMussel\Core\Scanner($Loader);

// Expected results from scanning the phpMussel test samples.
$Expected = [
    '1043d8e6c0deb7f7264952a163cbfe9f724251064f9c9d2ccbb3996ea79ebe1c:20882:pdf_standard_testfile.pdf' => 'Detected phpMussel-Testfile.PDF.Standard (pdf_standard_testfile.pdf)!',
    '14fb5b708076142cf38131ccc3827ff0a0ff28db1ee5db4583432cadafc8a4bf:658:ole_testfile.bin' => 'Detected phpMussel-Testfile.OLE.Standard (ole_testfile.bin)!',
    '4b4e349e8103d105b8dd0f5fce5ec9be0b263d203597e87abf3644089aea095f:19:hash_testfile_md5.txt' => 'Detected phpMussel-Testfile.HASH.MD5 (hash_testfile_md5.txt)!',
    '8b4413ceca5ba8b33f1af7d1ce82a108f26be2e3de9241ca9969ea47214a180a:5632:pe_sectional_testfile.exe' => 'Detected phpMussel-Testfile.PE.Sectional (pe_sectional_testfile.exe)!',
    '8e39388e6e605902d1192aecc5ea77f9a62547eb164562266c0060cf52cb6ec9:653:embedded.txt' => 'Detected phpMussel-Testfile.General.Standard (embedded.txt)!',
    '8e39388e6e605902d1192aecc5ea77f9a62547eb164562266c0060cf52cb6ec9:653:general_standard_testfile.txt' => 'Detected phpMussel-Testfile.General.Standard (general_standard_testfile.txt)!',
    'a00178f9d85e56c8067c5d6c234a48afd6631c9e3c90fe0717f4b7330360ef3b:5632:exe_standard_testfile.exe' => 'Detected phpMussel-Testfile.EXE.Standard (exe_standard_testfile.exe)!',
    'bf059f3112049d7299f9dc39397fe721c560e790611bfdc163adadbebb4e9ca9:13:hello.txt' => '',
    'c845b950f38399ae7fe4b3107cab5b46ac7c3e184dddfec97d4d164c00cb584a:491:coex_testfile.rtf' => 'Detected phpMussel-Testfile.CoEx (coex_testfile.rtf)!',
    'c8ff1888b2802f8824a59191d4ad0a7f5261840541044ca5313fd4ca0962063b:20:hash_testfile_sha1.txt' => 'Detected phpMussel-Testfile.HASH.SHA1 (hash_testfile_sha1.txt)!',
    'd188d46c87f2174c78ed4aaf8b0d24bfafc684c789df36572110355f59443ff7:632:graphics_standard_testfile.gif' => 'Detected phpMussel-Testfile.Graphics.Standard (graphics_standard_testfile.gif)!',
    'd1e1ec9461e107beee203d2c7f909d0dab026046a89d5b9a84bece02b5b93ca9:31662:swf_standard_testfile.swf' => 'Detected phpMussel-Testfile.SWF.Standard (swf_standard_testfile.swf)!',
    'd45d5d9df433aefeacaece6162b835e6474d6fcb707d24971322ec429707c58f:185:encrypted.zip' => 'Detected encrypted archive; Encrypted archives not permitted (encrypted.zip)!',
    'dcacac499064454218823fbabff7e09b5b011c0c877ee6f215f35bffb195b6e9:654:ascii_standard_testfile.txt' => 'Detected phpMussel-Testfile.ASCII.Standard (ascii_standard_testfile.txt)!',
    'f90054161ed9c4ffcda720769cb1c563eb0fd0e770004db352c4e225522e9a93:22:hash_testfile_sha256.txt' => 'Detected phpMussel-Testfile.HASH.SHA256 (hash_testfile_sha256.txt)!',
    'fbb49f897c8f8310f6c5ecacbd541d6873b18c7119ba71688d1bcdd3d7ea98fe:1488:html_standard_testfile.html' => 'Detected phpMussel-Testfile.HTML.Standard (html_standard_testfile.html)!',
];

// Test scanning against the standard phpMussel test samples.
$Actual = $Scanner->scan($Samples, 3);
ksort($Actual);
if (serialize($Actual) !== serialize($Expected)) {
    echo 'Actual scan results don\'t match the expected scan results.' . PHP_EOL;
    exit(5);
}

// Test the PDF handler directly (embedded files, scripts, and object streams).
$Pdf = "%PDF-1.5\r" .
    "1 0 obj\r<</Type/Catalog/AA<</O<</S/JavaScript/JS(app.alert\\(1\\))>>>>>>\rendobj\r" .
    "2 0 obj\r<</Type/Filespec/UF(a.txt)/EF<</F 3 0 R>>>>\rendobj\r" .
    "3 0 obj\r<</Filter[/ASCII85Decode/ASCIIHexDecode]/Length 38>>\rstream\r" .
    "<~1cRBN2IeXT2J+^S1,(XG2J+m'2IeX%1,1r~>\rendstream\rendobj\r" .
    "4 0 obj\r<</S/JavaScript/JS<68656c6c6f28293b>>>\rendobj\r";
$Handler = new \phpMussel\Core\PdfHandler($Pdf);
$Entries = [];
while ($Handler->EntryNext()) {
    $Entries[] = [$Handler->EntryName(), $Handler->EntryRead(), $Handler->EntryActualSize()];
}
if ($Handler->ErrorState !== 0 || serialize($Entries) !== serialize([
    ['PDFJavaScript.js', 'app.alert(1)', 12],
    ['a.txt', 'Hello, world!', 13],
    ['PDFJavaScript.js', 'hello();', 8]
])) {
    echo 'The PDF handler didn\'t return the expected entries.' . PHP_EOL;
    exit(6);
}
$Handler = new \phpMussel\Core\PdfHandler('Not a PDF.');
if ($Handler->ErrorState !== 2 || $Handler->EntryNext()) {
    echo 'The PDF handler accepted something that isn\'t a PDF.' . PHP_EOL;
    exit(7);
}

// Test the OLE handler directly (PowerPoint embedded objects, and VBA macros within them).
$Fixture = $TestsPath . 'ole_vba_nested.ole';
$Handler = new \phpMussel\Core\OleHandler(is_readable($Fixture) ? file_get_contents($Fixture) : '');
$Outer = [];
while ($Handler->EntryNext()) {
    $Outer[] = [$Handler->EntryName(), $Handler->EntryRead()];
}
$Nested = [];
if (count($Outer) === 1 && $Outer[0][0] === 'ExOleObjStg.bin') {
    $Inner = new \phpMussel\Core\OleHandler($Outer[0][1]);
    while ($Inner->EntryNext()) {
        $Nested[] = [$Inner->EntryName(), $Inner->EntryRead()];
    }
}
if (
    $Handler->ErrorState !== 0 ||
    count($Nested) !== 1 ||
    $Nested[0][0] !== 'Module1.bas' ||
    strpos($Nested[0][1], "Sub action()\r\n") === false ||
    strpos($Nested[0][1], 'eicarPart2 = "C)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"') === false
) {
    echo 'The OLE handler didn\'t return the expected entries.' . PHP_EOL;
    exit(8);
}
$Handler = new \phpMussel\Core\OleHandler('Not an OLE file.');
if ($Handler->ErrorState !== 2 || $Handler->EntryNext()) {
    echo 'The OLE handler accepted something that isn\'t an OLE file.' . PHP_EOL;
    exit(9);
}

// Test that the decompression limits are respected (and that zero or less means "use the default").
$Fixture = file_get_contents($TestsPath . 'ole_vba_nested.ole');
$Count = function (\phpMussel\Core\ArchiveHandler $Handler): array {
    $Out = [];
    while ($Handler->EntryNext()) {
        $Out[] = [$Handler->EntryName(), strlen($Handler->EntryRead())];
    }
    return $Out;
};
if (
    serialize($Count(new \phpMussel\Core\OleHandler($Fixture, 0, 1000))) !== serialize([]) ||
    serialize($Count(new \phpMussel\Core\OleHandler($Fixture, 2000))) !== serialize([['ExOleObjStg.bin', 2000]]) ||
    serialize($Count(new \phpMussel\Core\OleHandler($Fixture, -1, -1))) !== serialize([['ExOleObjStg.bin', 4608]])
) {
    echo 'The OLE handler didn\'t respect its decompression limits.' . PHP_EOL;
    exit(10);
}
$Compressed = gzcompress(str_repeat('A', 2000));
$Pdf = "%PDF-1.5\r2 0 obj\r<</Type/Filespec/UF(b.txt)/EF<</F 3 0 R>>>>\rendobj\r" .
    "3 0 obj\r<</Filter/FlateDecode/Length " . strlen($Compressed) . ">>\rstream\r" . $Compressed . "\rendstream\rendobj\r";
if (
    serialize($Count(new \phpMussel\Core\PdfHandler($Pdf))) !== serialize([['b.txt', 2000]]) ||
    serialize($Count(new \phpMussel\Core\PdfHandler($Pdf, 10))) !== serialize([['b.txt', 10]]) ||
    serialize($Count(new \phpMussel\Core\PdfHandler($Pdf, 0, 500))) !== serialize([['b.txt', 500]]) ||
    serialize($Count(new \phpMussel\Core\PdfHandler($Pdf, -1, -1))) !== serialize([['b.txt', 2000]])
) {
    echo 'The PDF handler didn\'t respect its decompression limits.' . PHP_EOL;
    exit(11);
}
if (
    $Loader->readBytes($Loader->Configuration['files']['max_decompressed_entry_size']) !== 33554432 ||
    $Loader->readBytes($Loader->Configuration['files']['max_decompressed_total_size']) !== 134217728
) {
    echo 'The decompression limit directives don\'t have the expected default values.' . PHP_EOL;
    exit(12);
}

restore_error_handler();

echo 'All tests passed.' . PHP_EOL;
exit(0);
