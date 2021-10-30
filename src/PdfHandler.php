<?php
/**
 * This file is a part of the phpMussel\Core package.
 * Homepage: https://phpmussel.github.io/
 *
 * PHPMUSSEL COPYRIGHT 2013 AND BEYOND BY THE PHPMUSSEL TEAM.
 *
 * License: GNU/GPLv2
 * @see LICENSE.txt
 *
 * This file: Pdf handler (last modified: 2021.10.30).
 */

namespace phpMussel\Core;

class PdfHandler extends ArchiveHandler
{
    /**
     * @var string The PDF format version used.
     */
    private $PDFVersion = '';

    /**
     * @var array The document's object tree.
     */
    private $Objects = [];

    /**
     * @var int The currently selected object (starts at -1).
     */
    private $Index = -1;

    /**
     * Construct the instance.
     *
     * @param string $File
     * @return void
     */
    public function __construct(string $File)
    {
        /** Guard against the wrong type of file being used as pointer. */
        if (substr($File, 0, 4) !== "\x25PDF") {
            $this->ErrorState = 2;
            return;
        }

        /** Determine format version. */
        if (substr($File, 4, 1) === '-' && ($EoL = strpos($File, "\n", 5)) !== false) {
            $this->PDFVersion = preg_replace('~[^\d\.]~', '', substr($File, 5, $EoL - 5));
        }

        /** Data offset for building the object tree. */
        $Offset = 0;

        /**
         * Since there's a high probability of errors occurring here due to the
         * risk of non-PDF files or bad data being supplied here, we'll
         * temporarily suppress those errors.
         */
        set_error_handler(function ($errno, $errstr, $errfile, $errline) {
            return;
        });

        /** Building object tree. */
        $Tree = [];
        $Check = preg_match_all('~\n(\d+) (\d+) obj ?\r?\n(.+?) ?\r?\nendobj ?\r?\n~s', $File, $Matches);
        if ($Check && isset($Matches, $Matches[0], $Matches[0][0])) {
            $Count = count($Matches[0]);
            for ($Iterator = 0; $Iterator < $Count; $Iterator++) {
                $Tree[$Iterator] = [
                    'Object Number' => $Matches[1][$Iterator],
                    'Generation Number' => $Matches[2][$Iterator],
                    'Data' => $Matches[3][$Iterator]
                ];
                if (preg_match('~(.*)stream ?\r?\n(.+) ?\r?\nendstream~s', $Tree[$Iterator]['Data'], $SubMatches)) {
                    $Tree[$Iterator]['Stream'] = trim($SubMatches[2]);
                    $Tree[$Iterator]['Data'] = trim($SubMatches[1]);
                }
                if (preg_match('~<<\s*(.*)\s*>>~s', $Tree[$Iterator]['Data'], $SubMatches)) {
                    $Tree[$Iterator]['Data'] = $SubMatches[1];
                }
                $Params = [];
                $Offset = 0;
                while (($SPos = strpos($Tree[$Iterator]['Data'], '/', $Offset)) !== false) {
                    $Offset = $SPos + 1;
                    $NextSPos = strpos($Tree[$Iterator]['Data'], '/', $Offset);
                    foreach ([['[[', ']]'], ['{{', '}}'], ['((', '))'], ['<<', '>>']] as $Boundary) {
                        $BoundaryOpen = strpos($Tree[$Iterator]['Data'], $Boundary[0], $Offset);
                        $BoundaryWidth = strlen($Boundary[1]);
                        $BoundaryClose = strpos($Tree[$Iterator]['Data'], $Boundary[1], $Offset);
                        $BoundaryOffset = $BoundaryOpen + $BoundaryWidth;
                        while (
                            ($Working = substr($Tree[$Iterator]['Data'], $BoundaryOffset, $BoundaryClose - $BoundaryOffset)) &&
                            ($RPos = strpos($Working, $Boundary[0])) !== false &&
                            ($Try = strpos($Tree[$Iterator]['Data'], $Boundary[1], $BoundaryClose + $BoundaryWidth)) !== false
                        ) {
                            $BoundaryOffset += $RPos + $BoundaryWidth;
                            $BoundaryClose = $Try;
                        }
                        if (
                            $BoundaryOpen !== false &&
                            $BoundaryClose !== false &&
                            $BoundaryClose > $BoundaryOpen &&
                            (
                                $NextSPos === false ||
                                (
                                    $BoundaryOpen < $NextSPos &&
                                    trim(substr($Tree[$Iterator]['Data'], $BoundaryClose + $BoundaryWidth, $NextSPos - $BoundaryClose - $BoundaryWidth)) === ''
                                )
                            )
                        ) {
                            $Label = trim(substr($Tree[$Iterator]['Data'], $Offset, $BoundaryOpen - $Offset));
                            $Property = trim(substr($Tree[$Iterator]['Data'], $BoundaryOpen + $BoundaryWidth, $BoundaryClose - $BoundaryOpen - $BoundaryWidth));
                            if (strlen($Label)) {
                                $Params[$Label] = $Property;
                            }
                            $Offset = $BoundaryClose + $BoundaryWidth;
                            continue 2;
                        }
                    }
                    foreach ([' '] as $Boundary) {
                        $BPos = strpos($Tree[$Iterator]['Data'], $Boundary, $Offset);
                        if ($BPos !== false) {
                            $Label = trim(substr($Tree[$Iterator]['Data'], $Offset, $BPos - $Offset));
                            if ($NextSPos === false) {
                                $Property = trim(substr($Tree[$Iterator]['Data'], $BPos + 1));
                                if (strlen($Label)) {
                                    $Params[$Label] = $Property;
                                }
                            } elseif ($BPos > $NextSPos) {
                                continue;
                            } else {
                                $Property = trim(substr($Tree[$Iterator]['Data'], $BPos + 1, $NextSPos - $BPos - 1));
                                if (strlen($Label)) {
                                    $Params[$Label] = $Property;
                                }
                            }
                            continue 2;
                        }
                    }
                    if ($NextSPos === false) {
                        $Label = trim(substr($Tree[$Iterator]['Data'], $Offset));
                        if (strlen($Label)) {
                            $Params[$Label] = '';
                        }
                        continue;
                    }
                    $Label = trim(substr($Tree[$Iterator]['Data'], $Offset, $NextSPos - $Offset));
                    if (strlen($Label)) {
                        $Params[$Label] = '';
                    }
                }
                $FirstEmpty = '';
                foreach ($Params as $ParamKey => $ParamValue) {
                    if ($ParamValue === '') {
                        if ($FirstEmpty === '') {
                            $FirstEmpty = $ParamKey;
                        } else {
                            $Params[$FirstEmpty] .= '/' . $ParamKey;
                            unset($Params[$ParamKey]);
                        }
                        continue;
                    } else {
                        $FirstEmpty = '';
                    }
                    while (true) {
                        $Changed = false;
                        foreach ([['[', ']'], ['{', '}'], ['((', ')'], ['<', '>']] as $Boundary) {
                            if (substr($ParamValue, 0, 1) === $Boundary[0] && substr($ParamValue, -1) === $Boundary[1]) {
                                $ParamValue = substr($ParamValue, 1, -1);
                                $Changed = true;
                            }
                        }
                        if ($Changed === false) {
                            break;
                        }
                    }
                    $Params[$ParamKey] = $ParamValue;
                }

                /**
                 * See: 7.4 Filters - Table 6 - Standard filters
                 * @link https://www.adobe.com/content/dam/acom/en/devnet/pdf/pdfs/PDF32000_2008.pdf
                 */
                if (!empty($Params['Filter']) && !empty($Tree[$Iterator]['Stream'])) {
                    while (true) {
                        $Changed = false;
                        if (substr($Params['Filter'], 0, 12) === '/FlateDecode') {
                            $Params['Filter'] = trim(substr($Params['Filter'], 12));
                            $Try = gzuncompress($Tree[$Iterator]['Stream']);
                            if ($Try !== false) {
                                $Tree[$Iterator]['Stream'] = $Try;
                                $Changed = true;
                            } else {
                                break;
                            }
                        }
                        if (substr($Params['Filter'], 0, 15) === '/ASCIIHexDecode') {
                            $Params['Filter'] = trim(substr($Params['Filter'], 15));
                            $Try = hex2bin(preg_replace('~[^a-f0-9]~i', '', $Tree[$Iterator]['Stream']));
                            if ($Try !== false) {
                                $Tree[$Iterator]['Stream'] = $Try;
                                $Changed = true;
                            } else {
                                break;
                            }
                        }
                        if (substr($Params['Filter'], 0, 14) === '/ASCII85Decode') {
                            $Params['Filter'] = trim(substr($Params['Filter'], 14));
                            $Tree[$Iterator]['Stream'] = $this->base85_decode($Tree[$Iterator]['Stream']);
                            $Changed = true;
                        }
                        if (substr($Params['Filter'], 0, 10) === '/LZWDecode') {
                            $Params['Filter'] = trim(substr($Params['Filter'], 10));
                            if (function_exists('lzf_decompress')) {
                                $Try = lzf_decompress($Tree[$Iterator]['Stream']);
                                if ($Try !== false) {
                                    $Tree[$Iterator]['Stream'] = $Try;
                                    $Changed = true;
                                } else {
                                    break;
                                }
                            }
                        }
                        if ($Changed === false) {
                            break;
                        }
                    }
                }

                /** Normalise types. */
                if (isset($Params['Type']) && strpos($Params['Type'], '#') !== false) {
                    while (($HPos = strpos($Params['Type'], '#')) !== false) {
                        $Bytes = substr($Params['Type'], $HPos + 1, 2);
                        $Len = strlen($Bytes);
                        if (!$Len || preg_match('/[^\da-f]/i', $Bytes) || ($Len % 2)) {
                            break;
                        }
                        $Params['Type'] = substr($Params['Type'], 0, $HPos) . chr(hexdec($Bytes)) . substr($Params['Type'], $HPos + 3);
                    }
                }

                $Tree[$Iterator]['Data'] = empty($Params) ? [] : $Params;
            }
        }

        /** Total objects. */
        $Counts = count($Tree);

        /** Build references. */
        for ($Iterator = 0; $Iterator < $Counts; $Iterator++) {
            if (isset($Tree[$Iterator]['Data']) && is_array($Tree[$Iterator]['Data'])) {
                foreach ($Tree[$Iterator]['Data'] as $ParamKey => $ParamValue) {
                    $Check = preg_match('~^(\d+) (\d+) R$~', $ParamValue, $Matches);
                    if ($Check) {
                        $Matches[1] = $Matches[1] - 1;
                        $Matches[2] = (int)$Matches[2];
                        if (
                            isset($Tree[$Matches[1]], $Tree[$Matches[1]]['Object Number'], $Tree[$Matches[1]]['Generation Number']) &&
                            $Matches[1] === ($Tree[$Matches[1]]['Object Number'] - 1) &&
                            $Matches[2] === (int)$Tree[$Matches[1]]['Generation Number']
                        ) {
                            if (
                                isset($Tree[$Matches[1]]['Data']['Type'], $Tree[$Matches[1]]['Data']['Count']) &&
                                $Tree[$Matches[1]]['Data']['Type'] === '/' . $ParamKey
                            ) {
                                $Tree[$Iterator]['Data'][$ParamKey] = &$Tree[$Matches[1]]['Data']['Count'];
                            } elseif (isset($Tree[$Matches[1]]['Data']['Length'], $Tree[$Matches[1]]['Stream'])) {
                                $Tree[$Iterator]['Data'][$ParamKey] = &$Tree[$Matches[1]]['Stream'];
                            }
                        }
                    }
                }
            }
        }

        /** Export scannables to final object tree. */
        for ($Iterator = 0; $Iterator < $Counts; $Iterator++) {
            if (isset($Tree[$Iterator]['Data']) && is_array($Tree[$Iterator]['Data'])) {
                if (
                    isset($Tree[$Iterator]['Data']['Type'], $Tree[$Iterator]['Stream']) &&
                    $Tree[$Iterator]['Data']['Type'] === '/EmbeddedFile'
                ) {
                    $Object = [];
                    if (isset($Tree[$Iterator]['Data']['Length'])) {
                        $Object['EntryCompressedSize'] = (int)$Tree[$Iterator]['Data']['Length'];
                    }
                    $Object['EntryActualSize'] = strlen($Tree[$Iterator]['Stream']);
                    $Object['Data'] = $Tree[$Iterator]['Stream'];
                    $this->Objects[] = $Object;
                }
            }
        }

        /** Restore the previous error handler. */
        restore_error_handler();

        /** All is good. */
        $this->ErrorState = 0;
    }

    /**
     * Needed to decode Ascii85 data (since PDF files sometimes use this).
     * This method adapted from the base85 class authored by Scott Baker.
     * @link https://bitbucket.org/scottchiefbaker/php-base85/src/master/
     * @license https://bitbucket.org/scottchiefbaker/php-base85/src/master/LICENSE GNU/GPLv3
     *
     * @param string $In The data to be decoded.
     * @return string The decoded data.
     */
    public function base85_decode(string $In): string
    {
        $In = str_replace(["\t", "\r", "\n", "\f", '/z/', '/y/'], ['', '', '', '', '!!!!!', '+<VdL/'], $In);
        $Len = strlen($In);
        $Padding = ($Len % 5 === 0) ? 0 : 5 - ($Len % 5);
        $In .= str_repeat('u', $Padding);
        $Num = 0;
        $Out = '';
        while ($Chunk = substr($In, $Num * 5, 5)) {
            $Char = 0;
            foreach (unpack('C*', $Chunk) as $ThisChar) {
                $Char *= 85;
                $Char += $ThisChar - 33;
            }
            $Out .= pack('N', $Char);
            $Num++;
        }
        return substr($Out, 0, strlen($Out) - $Padding);
    }

    /**
     * Return the actual entry in the archive at the current entry pointer.
     *
     * @param int $Bytes Optionally, how many bytes to read from the entry.
     * @return string The entry's content, or an empty string if not available.
     */
    public function EntryRead(int $Bytes = -1): string
    {
        if ($Bytes > -1) {
            return isset($this->Objects[$this->Index]['Data']) ? substr($this->Objects[$this->Index]['Data'], 0, $Bytes) : '';
        }
        return $this->Objects[$this->Index]['Data'] ?? '';
    }

    /**
     * Return the compressed size of the entry at the current entry pointer.
     *
     * @return int
     */
    public function EntryCompressedSize(): int
    {
        return (int)($this->Objects[$this->Index]['EntryCompressedSize'] ?? 0);
    }

    /**
     * Return the actual size of the entry at the current entry pointer.
     *
     * @return int
     */
    public function EntryActualSize(): int
    {
        return (int)($this->Objects[$this->Index]['EntryActualSize'] ?? 0);
    }

    /**
     * Return whether the entry at the current entry pointer is a directory.
     *
     * @return false Embedded files aren't directories.
     */
    public function EntryIsDirectory(): bool
    {
        return false;
    }

    /**
     * Return whether the entry at the current entry pointer is encrypted.
     *
     * @return false Pdf encrypts at the document level, not per individual embed.
     */
    public function EntryIsEncrypted(): bool
    {
        return false;
    }

    /**
     * Return the reported internal CRC hash for the entry, if it exists.
     *
     * @return string Empty because Pdf doesn't provide internal CRCs.
     */
    public function EntryCRC(): string
    {
        return '';
    }

    /**
     * Return the name of the entry at the current entry pointer.
     *
     * @return string Using 'PDFStream' because entries here don't have names.
     */
    public function EntryName(): string
    {
        return 'PDFStream';
    }

    /**
     * Move the entry pointer ahead.
     *
     * @return bool False if there aren't any more entries.
     */
    public function EntryNext(): bool
    {
        $this->Index++;
        return isset($this->Objects[$this->Index]);
    }
}
