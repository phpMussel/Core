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
 * This file: Pdf handler (last modified: 2026.11.27).
 */

namespace phpMussel\Core;

/**
 * Treats a PDF document as a pseudo-archive, exposing the content which could
 * carry a threat (embedded files and JavaScript) as individual entries, so that
 * the scanner can recurse into them the same way that it does for archives.
 *
 * The parser is deliberately tolerant and doesn't depend on the document's
 * cross-reference data (which is frequently damaged or forged in malicious
 * files, and which is stored in a different way in every major revision of the
 * PDF specification). Instead, every indirect object present in the file is
 * located by scanning, including superseded revisions left behind by
 * incremental updates and objects stored inside object streams (PDF 1.5+),
 * because anything present in the file is potentially something to scan.
 *
 * @link https://opensource.adobe.com/dc-acrobat-sdk-docs/pdfstandards/PDF32000_2008.pdf
 */
class PdfHandler extends ArchiveHandler
{
    /**
     * @var int Maximum nesting depth when parsing (arrays and dictionaries).
     */
    private const MAX_DEPTH = 32;

    /**
     * @var int Maximum number of indirect objects to look through.
     */
    private const MAX_OBJECTS = 1000000;

    /**
     * @var int Approximate memory (in bytes) to allow per object retained.
     */
    private const MEMORY_PER_OBJECT = 2048;

    /**
     * @var int Maximum number of entries to expose.
     */
    private const MAX_ENTRIES = 10000;

    /**
     * @var int Maximum number of elements to retain per array or dictionary.
     */
    private const MAX_ELEMENTS = 100000;

    /**
     * @var int Default maximum size (in bytes) any single stream may decode to.
     */
    public const DEFAULT_MAX_STREAM_SIZE = 33554432;

    /**
     * @var int Default maximum total size (in bytes) that all streams may decode to.
     */
    public const DEFAULT_MAX_TOTAL_SIZE = 134217728;

    /**
     * @var string Whitespace characters (PDF specification, section 7.2.2).
     */
    private const SPACE = "\x00\t\n\f\r ";

    /**
     * @var string Whitespace and delimiter characters (ends regular tokens).
     */
    private const TERMINATORS = "\x00\t\n\f\r ()<>[]{}/%";

    /**
     * @var bool Whether the document declares that it is encrypted.
     */
    private $Encrypted = false;

    /**
     * @var int How many more bytes may be spent decoding streams.
     */
    private $Budget = 0;

    /**
     * @var int Maximum size (in bytes) any single stream may decode to.
     */
    private $MaxStreamSize = self::DEFAULT_MAX_STREAM_SIZE;

    /**
     * @var int Maximum total size (in bytes) that all streams may decode to.
     */
    private $MaxTotalSize = self::DEFAULT_MAX_TOTAL_SIZE;

    /**
     * @var array Indirect objects found (num, gen, value, and stream bounds).
     */
    private $Records = [];

    /**
     * @var int The maximum number of records to retain (depends on available memory).
     */
    private $MaxRecords = 0;

    /**
     * @var array Maps object numbers to the indexes of their records.
     */
    private $Index = [];

    /**
     * @var array Cache of decoded streams (by record index).
     */
    private $Decoded = [];

    /**
     * @var array The entries to expose (name, data, and sizes).
     */
    private $Entries = [];

    /**
     * @var array Fingerprints of entries already exposed (avoids duplicates).
     */
    private $Fingerprints = [];

    /**
     * @var array Streams already exposed under a given name (avoids repeating work).
     */
    private $Linked = [];

    /**
     * @var array Cache of the hashes of decoded streams (by record index).
     */
    private $Hashes = [];

    /**
     * @var int The currently selected entry (starts at -1).
     */
    private $Cursor = -1;

    /**
     * Construct the instance.
     *
     * @param string $File The PDF data.
     * @param int $MaxStreamSize Maximum size (in bytes) any single stream may decode to (zero or less for the default).
     * @param int $MaxTotalSize Maximum total size (in bytes) all streams may decode to (zero or less for the default).
     * @return void
     */
    public function __construct(string $File, int $MaxStreamSize = 0, int $MaxTotalSize = 0)
    {
        if ($MaxStreamSize > 0) {
            $this->MaxStreamSize = $MaxStreamSize;
        }
        if ($MaxTotalSize > 0) {
            $this->MaxTotalSize = $MaxTotalSize;
        }

        /** Guard against the wrong type of file being used as pointer. */
        if (\substr($File, 0, 4) !== "\x25PDF") {
            $this->ErrorState = 2;
            return;
        }

        /** Don't let decoding streams, or retaining objects, exhaust PHP's memory. */
        $Headroom = self::memoryHeadroom($this->MaxTotalSize * 4);
        $this->Budget = (int)\min($this->MaxTotalSize, \max(1048576, \intdiv($Headroom, 4)));

        /** Scanning an entry needs several times as much memory as the entry itself takes up. */
        $this->MaxStreamSize = (int)\min($this->MaxStreamSize, \max(1048576, \intdiv($Headroom, 8)));
        $this->MaxRecords = (int)\max(1000, \min(self::MAX_OBJECTS, \intdiv($Headroom, self::MEMORY_PER_OBJECT)));

        /** Build the object tree. */
        $this->locateObjects($File);
        $this->detectEncryption($File);
        $this->expandObjectStreams($File);

        /** Export scannables. */
        $this->collect($File);

        /** Free what isn't needed anymore. */
        $this->Records = $this->Index = $this->Decoded = $this->Fingerprints = $this->Linked = $this->Hashes = [];

        /** All is good. */
        $this->ErrorState = 0;
    }

    /**
     * Return the actual entry in the archive at the current entry pointer.
     *
     * @param int $Bytes Optionally, how many bytes to read from the entry.
     * @return string The entry's content, or an empty string if not available.
     */
    public function EntryRead(int $Bytes = -1): string
    {
        if (!isset($this->Entries[$this->Cursor])) {
            return '';
        }
        $Data = $this->Entries[$this->Cursor]['Data'];
        return $Bytes > -1 ? \substr($Data, 0, $Bytes) : $Data;
    }

    /**
     * Return the compressed size of the entry at the current entry pointer.
     *
     * @return int
     */
    public function EntryCompressedSize(): int
    {
        return $this->Entries[$this->Cursor]['CompressedSize'] ?? 0;
    }

    /**
     * Return the actual size of the entry at the current entry pointer.
     *
     * @return int
     */
    public function EntryActualSize(): int
    {
        return isset($this->Entries[$this->Cursor]) ? \strlen($this->Entries[$this->Cursor]['Data']) : 0;
    }

    /**
     * Return whether the entry at the current entry pointer is a directory.
     *
     * @return false Embedded files and scripts aren't directories.
     */
    public function EntryIsDirectory(): bool
    {
        return false;
    }

    /**
     * Return whether the entry at the current entry pointer is encrypted.
     *
     * @return bool True if the document declares that it is encrypted.
     */
    public function EntryIsEncrypted(): bool
    {
        return $this->Encrypted;
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
     * @return string The embedded file's name when it has one, otherwise a
     *      generic name ("PDFJavaScript.js" for scripts, "PDFStream" for
     *      embedded files which don't declare a name).
     */
    public function EntryName(): string
    {
        return $this->Entries[$this->Cursor]['Name'] ?? '';
    }

    /**
     * Move the entry pointer ahead.
     *
     * @return bool False if there aren't any more entries.
     */
    public function EntryNext(): bool
    {
        $this->Cursor++;
        return isset($this->Entries[$this->Cursor]);
    }

    /**
     * Finds every indirect object in the file, in the order that they appear.
     *
     * @param string $D The PDF data.
     * @return void
     */
    private function locateObjects(string &$D): void
    {
        $Len = \strlen($D);
        $Pos = 0;
        $Pattern = '~(?<![0-9])(\d{1,10})[\x00\t\n\f\r ]+(\d{1,5})[\x00\t\n\f\r ]+obj(?![A-Za-z0-9])~';
        $Scanned = 0;
        while (
            $Scanned++ < self::MAX_OBJECTS &&
            $Pos < $Len &&
            \preg_match($Pattern, $D, $Match, \PREG_OFFSET_CAPTURE, $Pos)
        ) {
            $P = $Match[0][1] + \strlen($Match[0][0]);
            $Value = $this->parseTopLevelValue($D, $P, $Len);
            $Record = [
                'Num' => (int)$Match[1][0],
                'Value' => $Value,
                'Start' => -1,
                'Length' => 0
            ];

            /** Check for a stream. */
            $this->skipSpace($D, $P, $Len);
            if ($Value[0] === 'd' && \substr($D, $P, 6) === 'stream') {
                $P += 6;
                if (\substr($D, $P, 2) === "\r\n") {
                    $P += 2;
                } elseif ($P < $Len && ($D[$P] === "\n" || $D[$P] === "\r")) {
                    $P++;
                }
                $Start = $P;
                $Declared = $Value[1]['Length'] ?? null;

                /** Trust the declared length only when "endstream" follows it. */
                if (
                    \is_int($Declared) &&
                    $Declared >= 0 &&
                    $Start + $Declared <= $Len &&
                    \preg_match('~\G[\x00\t\n\f\r ]{0,4}endstream~', $D, $Check, 0, $Start + $Declared)
                ) {
                    $End = $Start + $Declared;
                    $P = $End + \strlen($Check[0]);
                } else {
                    $End = \strpos($D, 'endstream', $Start);
                    if ($End !== false) {
                        $P = $End + 9;
                    } else {
                        /** Damaged: no "endstream". Settle for the end of the object (or the data). */
                        $End = \strpos($D, 'endobj', $Start);
                        $End = $End === false ? $Len : $End;
                        $P = $End;
                    }
                    if ($End - 2 >= $Start && \substr($D, $End - 2, 2) === "\r\n") {
                        $End -= 2;
                    } elseif ($End - 1 >= $Start && ($D[$End - 1] === "\n" || $D[$End - 1] === "\r")) {
                        $End--;
                    }
                }
                $Record['Start'] = $Start;
                $Record['Length'] = $End - $Start;
            }

            $this->retain($Record);
            $Pos = \max($P, $Match[0][1] + 1);
        }
    }

    /**
     * Retains a record, unless it can't possibly matter. Most objects in a
     * typical document (pages, fonts, annotations, and so on) have no bearing on
     * what we're looking for, so they're discarded straight away, which keeps
     * memory use in check, even for documents containing huge numbers of them.
     *
     * @param array $Record The record.
     * @return void
     */
    private function retain(array $Record): void
    {
        if (
            \count($this->Records) >= $this->MaxRecords || (
                $Record['Start'] < 0 &&
                $Record['Value'][0] !== 's' &&
                !$this->isRelevant($Record['Value'], 0)
            )
        ) {
            return;
        }
        $this->Records[] = $Record;
    }

    /**
     * Whether a value is, or contains, something that matters here (a
     * reference to embedded files or to a script, an object stream, and so on).
     *
     * @param mixed $Value The value.
     * @param int $Depth The current depth.
     * @return bool
     */
    private function isRelevant($Value, int $Depth): bool
    {
        if (!\is_array($Value) || $Depth > self::MAX_DEPTH) {
            return false;
        }
        if ($Value[0] === 'a') {
            foreach ($Value[1] as $Item) {
                if ($this->isRelevant($Item, $Depth + 1)) {
                    return true;
                }
            }
            return false;
        }
        if ($Value[0] !== 'd') {
            return false;
        }
        $Dict = $Value[1];
        if (isset($Dict['EF']) || isset($Dict['JS']) || isset($Dict['Encrypt'])) {
            return true;
        }
        if (
            isset($Dict['Type']) &&
            \is_array($Dict['Type']) &&
            $Dict['Type'][0] === 'n' &&
            \in_array($Dict['Type'][1], ['Filespec', 'EmbeddedFile', 'ObjStm', 'XRef'], true)
        ) {
            return true;
        }

        /** The dictionary of an indirect "EF" entry (see "7.11.4 Embedded File Streams"). */
        if ($Dict !== [] && \array_diff(\array_keys($Dict), ['F', 'UF', 'DOS', 'Mac', 'Unix']) === []) {
            return true;
        }
        foreach ($Dict as $Item) {
            if ($this->isRelevant($Item, $Depth + 1)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Determines whether the document declares that it is encrypted.
     *
     * @param string $D The PDF data.
     * @return void
     */
    private function detectEncryption(string &$D): void
    {
        /** Cross-reference streams carry the trailer's entries in their own dictionaries. */
        foreach ($this->Records as $Record) {
            if (
                $Record['Value'][0] === 'd' &&
                isset($Record['Value'][1]['Encrypt']) &&
                ($Record['Value'][1]['Type'] ?? null) === ['n', 'XRef']
            ) {
                $this->Encrypted = true;
                return;
            }
        }

        /** Classic trailers. */
        $Len = \strlen($D);
        $Pos = 0;
        for ($Tries = 0; $Tries < 64 && ($Pos = \strpos($D, 'trailer', $Pos)) !== false; $Tries++) {
            $Pos += 7;
            $P = $Pos;
            $Value = $this->parseTopLevelValue($D, $P, $Len);
            if ($Value[0] === 'd' && isset($Value[1]['Encrypt'])) {
                $this->Encrypted = true;
                return;
            }
        }
    }

    /**
     * Adds the objects stored inside object streams to the list of records,
     * and builds the index used for resolving references.
     *
     * @param string $D The PDF data.
     * @return void
     */
    private function expandObjectStreams(string &$D): void
    {
        $Count = \count($this->Records);
        for ($K = 0; $K < $Count; $K++) {
            $Dict = $this->Records[$K]['Value'];
            if (
                $Dict[0] !== 'd' ||
                $this->Records[$K]['Start'] < 0 ||
                ($Dict[1]['Type'] ?? null) !== ['n', 'ObjStm'] ||
                !isset($Dict[1]['N'], $Dict[1]['First']) ||
                !\is_int($Dict[1]['N']) ||
                !\is_int($Dict[1]['First']) ||
                $Dict[1]['N'] < 1 ||
                $Dict[1]['First'] < 0
            ) {
                continue;
            }

            /** Can't read it if it's encrypted. */
            if ($this->Encrypted) {
                continue;
            }

            $Decoded = $this->streamData($K, $D);
            $Len = \strlen($Decoded);
            $First = $Dict[1]['First'];
            if ($First > $Len || !\preg_match_all(
                '~(\d{1,10})[\x00\t\n\f\r ]+(\d{1,10})~',
                \substr($Decoded, 0, $First),
                $Pairs,
                \PREG_SET_ORDER
            )) {
                continue;
            }
            $Pairs = \array_slice($Pairs, 0, \min($Dict[1]['N'], self::MAX_OBJECTS));
            foreach ($Pairs as $Pair) {
                $P = $First + (int)$Pair[2];
                if ($P >= $Len) {
                    continue;
                }
                $this->retain([
                    'Num' => (int)$Pair[1],
                    'Value' => $this->parseTopLevelValue($Decoded, $P, $Len),
                    'Start' => -1,
                    'Length' => 0
                ]);
            }
        }

        foreach ($this->Records as $K => $Record) {
            $this->Index[$Record['Num']][] = $K;
        }
    }

    /**
     * Walks every object, and exposes embedded files and JavaScript.
     *
     * @param string $D The PDF data.
     * @return void
     */
    private function collect(string &$D): void
    {
        $Used = [];

        /** Embedded files and scripts, found wherever they're nested. */
        foreach ($this->Records as $Record) {
            $this->walk($D, $Record['Value'], 0, $Used);
        }

        /** Streams which declare themselves to be embedded files, but which nothing refers to. */
        foreach ($this->Records as $K => $Record) {
            if (
                !isset($Used[$K]) &&
                $Record['Start'] >= 0 &&
                $Record['Value'][0] === 'd' &&
                ($Record['Value'][1]['Type'] ?? null) === ['n', 'EmbeddedFile']
            ) {
                $this->addStream($D, $K, 'PDFStream', $Used);
            }
        }
    }

    /**
     * Recursive worker for collect.
     *
     * @param string $D The PDF data.
     * @param mixed $Value The value to look through.
     * @param int $Depth Current depth.
     * @param array $Used Records already exposed.
     * @return void
     */
    private function walk(string &$D, $Value, int $Depth, array &$Used): void
    {
        if (!\is_array($Value) || $Depth > self::MAX_DEPTH || \count($this->Entries) >= self::MAX_ENTRIES) {
            return;
        }
        if ($Value[0] === 'a') {
            foreach ($Value[1] as $Item) {
                $this->walk($D, $Item, $Depth + 1, $Used);
            }
            return;
        }
        if ($Value[0] !== 'd') {
            return;
        }

        /** A file specification with embedded files. */
        if (isset($Value[1]['EF'])) {
            $Name = $this->textOf($Value[1]['UF'] ?? $Value[1]['F'] ?? null);
            $Name = $Name === '' ? 'PDFStream' : $Name;
            foreach ($this->dictionariesOf($Value[1]['EF']) as $EF) {
                foreach ($EF as $Reference) {
                    if (\is_array($Reference) && $Reference[0] === 'r') {
                        foreach ($this->Index[$Reference[1]] ?? [] as $K) {
                            $this->addStream($D, $K, $Name, $Used);
                        }
                    }
                }
            }
        }

        /** JavaScript. */
        if (isset($Value[1]['JS'])) {
            $JS = $Value[1]['JS'];
            if (\is_array($JS) && $JS[0] === 's') {
                $this->addEntry('PDFJavaScript.js', $this->unicodeText($JS[1]), \strlen($JS[1]));
            } elseif (\is_array($JS) && $JS[0] === 'r') {
                foreach ($this->Index[$JS[1]] ?? [] as $K) {
                    if ($this->Records[$K]['Start'] >= 0) {
                        if (!isset($this->Linked[$K . '|js'])) {
                            $this->Linked[$K . '|js'] = true;
                            $Data = $this->unicodeText($this->streamData($K, $D));
                            $this->addEntry('PDFJavaScript.js', $Data, $this->Records[$K]['Length']);
                        }
                    } elseif ($this->Records[$K]['Value'][0] === 's') {
                        $Data = $this->unicodeText($this->Records[$K]['Value'][1]);
                        $this->addEntry('PDFJavaScript.js', $Data, \strlen($Data));
                    }
                }
            }
        }

        foreach ($Value[1] as $Item) {
            $this->walk($D, $Item, $Depth + 1, $Used);
        }
    }

    /**
     * Exposes the decoded content of a stream as an entry.
     *
     * @param string $D The PDF data.
     * @param int $K The record's index.
     * @param string $Name The name to expose it under.
     * @param array $Used Records already exposed.
     * @return void
     */
    private function addStream(string &$D, int $K, string $Name, array &$Used): void
    {
        if ($this->Records[$K]['Start'] < 0) {
            return;
        }
        $Used[$K] = true;
        if (isset($this->Linked[$K . '|' . $Name])) {
            return;
        }
        $this->Linked[$K . '|' . $Name] = true;
        $Data = $this->streamData($K, $D);
        if (!isset($this->Hashes[$K])) {
            $this->Hashes[$K] = \hash('sha256', $Data);
        }
        $this->addEntry($Name, $Data, $this->Records[$K]['Length'], $this->Hashes[$K]);
    }

    /**
     * Adds an entry (unless it's a duplicate of one that was already added).
     *
     * @param string $Name The name to expose it under.
     * @param string $Data The content.
     * @param int $CompressedSize The size before decoding.
     * @param string $Hash The content's hash (calculated if not supplied).
     * @return void
     */
    private function addEntry(string $Name, string $Data, int $CompressedSize, string $Hash = ''): void
    {
        if ($Data === '' || \count($this->Entries) >= self::MAX_ENTRIES) {
            return;
        }

        /** The same content, with the same extension, is only worth scanning once. */
        $Dot = \strrpos($Name, '.');
        $Fingerprint = ($Hash === '' ? \hash('sha256', $Data) : $Hash) . '|' . ($Dot === false ? '' : \strtolower(\substr($Name, $Dot)));
        if (isset($this->Fingerprints[$Fingerprint])) {
            return;
        }
        $this->Fingerprints[$Fingerprint] = true;
        $this->Entries[] = ['Name' => $Name, 'Data' => $Data, 'CompressedSize' => $CompressedSize];
    }

    /**
     * Resolves a value to the dictionaries it represents (a direct dictionary,
     * or a reference to one; every revision of the referenced object).
     *
     * @param mixed $Value A dictionary or a reference.
     * @return array The dictionaries (name => value).
     */
    private function dictionariesOf($Value): array
    {
        if (!\is_array($Value)) {
            return [];
        }
        if ($Value[0] === 'd') {
            return [$Value[1]];
        }
        $Out = [];
        if ($Value[0] === 'r') {
            foreach ($this->Index[$Value[1]] ?? [] as $K) {
                if ($this->Records[$K]['Value'][0] === 'd') {
                    $Out[] = $this->Records[$K]['Value'][1];
                }
            }
        }
        return $Out;
    }

    /**
     * Resolves a value to a text string.
     *
     * @param mixed $Value A string or a reference to a string.
     * @return string The string, as UTF-8 where possible (empty if not a string).
     */
    private function textOf($Value): string
    {
        if (\is_array($Value) && $Value[0] === 'r') {
            foreach ($this->Index[$Value[1]] ?? [] as $K) {
                if ($this->Records[$K]['Value'][0] === 's') {
                    $Value = $this->Records[$K]['Value'];
                    break;
                }
            }
        }
        return \is_array($Value) && $Value[0] === 's' ? $this->unicodeText($Value[1]) : '';
    }

    /**
     * Converts PDF text (UTF-16BE with a byte order mark) to UTF-8. Other text
     * is returned as it is, minus any UTF-8 byte order mark.
     *
     * @param string $In The text.
     * @return string The converted text.
     */
    private function unicodeText(string $In): string
    {
        if (\substr($In, 0, 3) === "\xEF\xBB\xBF") {
            return \substr($In, 3);
        }
        if (\substr($In, 0, 2) !== "\xFE\xFF") {
            return $In;
        }
        $In = \substr($In, 2);
        $In = \substr($In, 0, \strlen($In) - (\strlen($In) % 2));
        if ($In === '') {
            return '';
        }
        $Out = '';
        $Units = \array_values(\unpack('n*', $In));
        $Count = \count($Units);
        for ($I = 0; $I < $Count; $I++) {
            $Code = $Units[$I];
            if ($Code >= 0xD800 && $Code <= 0xDBFF && isset($Units[$I + 1]) && $Units[$I + 1] >= 0xDC00 && $Units[$I + 1] <= 0xDFFF) {
                $Code = 0x10000 + (($Code - 0xD800) << 10) + ($Units[++$I] - 0xDC00);
            }
            if ($Code < 0x80) {
                $Out .= \chr($Code);
            } elseif ($Code < 0x800) {
                $Out .= \chr(0xC0 | ($Code >> 6)) . \chr(0x80 | ($Code & 0x3F));
            } elseif ($Code < 0x10000) {
                $Out .= \chr(0xE0 | ($Code >> 12)) . \chr(0x80 | (($Code >> 6) & 0x3F)) . \chr(0x80 | ($Code & 0x3F));
            } else {
                $Out .= \chr(0xF0 | ($Code >> 18)) . \chr(0x80 | (($Code >> 12) & 0x3F)) .
                    \chr(0x80 | (($Code >> 6) & 0x3F)) . \chr(0x80 | ($Code & 0x3F));
            }
        }
        return $Out;
    }

    /**
     * Skips whitespace and comments.
     *
     * @param string $D The data.
     * @param int $P The position (updated).
     * @param int $Len The length of the data.
     * @return void
     */
    private function skipSpace(string &$D, int &$P, int $Len): void
    {
        while ($P < $Len) {
            $P += \strspn($D, self::SPACE, $P);
            if ($P < $Len && $D[$P] === '%') {
                $P += \strcspn($D, "\r\n", $P);
                continue;
            }
            return;
        }
    }

    /**
     * Parses a single PDF object from the data.
     *
     * Values are represented as follows: Integers and floats as they are,
     * booleans as they are, null as null, names as ['n', name], strings as
     * ['s', bytes], arrays as ['a', [...]], dictionaries as ['d', [...]],
     * references as ['r', object number, generation], and anything else
     * (keywords, stray delimiters, running out of data) as ['k', token].
     *
     * Always advances the position when there's data left to be read.
     *
     * @param string $D The data.
     * @param int $P The position (updated).
     * @param int $Len The length of the data.
     * @param int $Depth The current nesting depth.
     * @return mixed The value.
     */
    private function parseValue(string &$D, int &$P, int $Len, int $Depth)
    {
        $this->skipSpace($D, $P, $Len);
        if ($P >= $Len) {
            return ['k', ''];
        }
        $C = $D[$P];

        /** Name. */
        if ($C === '/') {
            $P++;
            $E = \strcspn($D, self::TERMINATORS, $P);
            $Name = \substr($D, $P, $E);
            $P += $E;
            if (\strpos($Name, '#') !== false) {
                $Name = \preg_replace_callback('~#([0-9A-Fa-f]{2})~', function (array $M): string {
                    return \chr(\hexdec($M[1]));
                }, $Name);
            }
            return ['n', $Name];
        }

        /** Literal string. */
        if ($C === '(') {
            return ['s', $this->parseLiteralString($D, $P, $Len)];
        }

        /** Dictionary or hexadecimal string. */
        if ($C === '<') {
            if (\substr($D, $P, 2) !== '<<') {
                $P++;
                $E = \strpos($D, '>', $P);
                $E = $E === false ? $Len : $E;
                $Hex = \preg_replace('~[^0-9A-Fa-f]~', '', \substr($D, $P, $E - $P));
                $P = \min($E + 1, $Len);
                if (\strlen($Hex) % 2) {
                    $Hex .= '0';
                }
                return ['s', $Hex === '' ? '' : (string)\hex2bin($Hex)];
            }
            $P += 2;
            if ($Depth >= self::MAX_DEPTH) {
                return ['k', ''];
            }
            $Dict = [];
            while (true) {
                $this->skipSpace($D, $P, $Len);
                if ($P >= $Len) {
                    break;
                }
                if ($D[$P] === '>') {
                    $P += \substr($D, $P, 2) === '>>' ? 2 : 1;
                    break;
                }
                $Before = $P;
                $Key = $this->parseValue($D, $P, $Len, $Depth + 1);
                if (!\is_array($Key)) {
                    continue;
                }
                if ($Key[0] === 'k') {
                    if ($this->isStructural($Key[1])) {
                        $P = $Before;
                        break;
                    }
                    continue;
                }
                if ($Key[0] !== 'n') {
                    continue;
                }
                $Before = $P;
                $Item = $this->parseValue($D, $P, $Len, $Depth + 1);
                if (\is_array($Item) && $Item[0] === 'k' && $this->isStructural($Item[1])) {
                    $P = $Before;
                    break;
                }
                if (\count($Dict) < self::MAX_ELEMENTS) {
                    $Dict[$Key[1]] = $Item;
                }
            }
            return ['d', $Dict];
        }

        /** Array. */
        if ($C === '[') {
            $P++;
            if ($Depth >= self::MAX_DEPTH) {
                return ['k', ''];
            }
            $Array = [];
            while (true) {
                $this->skipSpace($D, $P, $Len);
                if ($P >= $Len) {
                    break;
                }
                if ($D[$P] === ']') {
                    $P++;
                    break;
                }
                $Before = $P;
                $Item = $this->parseValue($D, $P, $Len, $Depth + 1);
                if (\is_array($Item) && $Item[0] === 'k') {
                    if ($this->isStructural($Item[1])) {
                        $P = $Before;
                        break;
                    }
                    continue;
                }
                if (\count($Array) < self::MAX_ELEMENTS) {
                    $Array[] = $Item;
                }
            }
            return ['a', $Array];
        }

        /** Numbers, references, booleans, null, and keywords. */
        $E = \strcspn($D, self::TERMINATORS, $P);
        if ($E === 0) {
            $P++;
            return ['k', $C];
        }
        $Token = \substr($D, $P, $E);
        $P += $E;
        if (\preg_match('~^[+-]?\d+$~', $Token)) {
            $Int = (int)$Token;
            if (
                $Int >= 0 &&
                $Token[0] !== '+' &&
                \preg_match('~\G[\x00\t\n\f\r ]+(\d{1,5})[\x00\t\n\f\r ]+R(?![^\x00\t\n\f\r ()<>\[\]{}/%])~', $D, $Ref, 0, $P)
            ) {
                $P += \strlen($Ref[0]);
                return ['r', $Int, (int)$Ref[1]];
            }
            return $Int;
        }
        if (\preg_match('~^[+-]?(?:\d+\.\d*|\.\d+)$~', $Token)) {
            return (float)$Token;
        }
        if ($Token === 'true') {
            return true;
        }
        if ($Token === 'false') {
            return false;
        }
        if ($Token === 'null') {
            return null;
        }
        return ['k', $Token];
    }

    /**
     * Parses the value of an indirect object (or of a trailer). Unlike
     * parseValue, always returns an array (numbers, booleans, and null are
     * wrapped as ['x', value]), so that the type can always be read from [0].
     *
     * @param string $D The data.
     * @param int $P The position (updated).
     * @param int $Len The length of the data.
     * @return array The value.
     */
    private function parseTopLevelValue(string &$D, int &$P, int $Len): array
    {
        $Value = $this->parseValue($D, $P, $Len, 0);
        return \is_array($Value) ? $Value : ['x', $Value];
    }

    /**
     * Whether a keyword marks the end of an object (meaning a parse of a
     * damaged dictionary or array should stop and hand control back).
     *
     * @param string $Token The keyword.
     * @return bool
     */
    private function isStructural(string $Token): bool
    {
        return $Token === 'endobj' || $Token === 'stream' || $Token === 'endstream' || $Token === 'obj';
    }

    /**
     * Parses a literal string (handling escapes and balanced parentheses).
     *
     * @param string $D The data.
     * @param int $P The position of the opening parenthesis (updated).
     * @param int $Len The length of the data.
     * @return string The string's bytes.
     */
    private function parseLiteralString(string &$D, int &$P, int $Len): string
    {
        $P++;
        $Out = '';
        $Nesting = 1;
        $Escapes = ['n' => "\n", 'r' => "\r", 't' => "\t", 'b' => "\x08", 'f' => "\f"];
        while ($P < $Len) {
            $E = \strcspn($D, '()\\', $P);
            $Out .= \substr($D, $P, $E);
            $P += $E;
            if ($P >= $Len) {
                break;
            }
            $C = $D[$P++];
            if ($C === '(') {
                $Nesting++;
                $Out .= '(';
            } elseif ($C === ')') {
                if (--$Nesting === 0) {
                    break;
                }
                $Out .= ')';
            } elseif ($P < $Len) {
                $N = $D[$P++];
                if (isset($Escapes[$N])) {
                    $Out .= $Escapes[$N];
                } elseif ($N >= '0' && $N <= '7') {
                    $Octal = $N;
                    while (\strlen($Octal) < 3 && $P < $Len && $D[$P] >= '0' && $D[$P] <= '7') {
                        $Octal .= $D[$P++];
                    }
                    $Out .= \chr(\octdec($Octal) & 0xFF);
                } elseif ($N === "\r") {
                    if ($P < $Len && $D[$P] === "\n") {
                        $P++;
                    }
                } elseif ($N !== "\n") {
                    $Out .= $N;
                }
            }
        }
        return $Out;
    }

    /**
     * Returns the decoded content of a stream.
     *
     * @param int $K The record's index.
     * @param string $D The PDF data (or the data that the record's bounds apply to).
     * @return string The content (as far as it could be decoded).
     */
    private function streamData(int $K, string &$D): string
    {
        if (isset($this->Decoded[$K])) {
            return $this->Decoded[$K];
        }
        $Record = $this->Records[$K];
        $Raw = \substr($D, $Record['Start'], $Record['Length']);
        $Dict = $Record['Value'][1];

        /** Streams in encrypted documents can't be decoded without decrypting them. */
        if ($this->Encrypted || !isset($Dict['Filter'])) {
            return $this->Decoded[$K] = $Raw;
        }

        $Filters = $this->namesOf($Dict['Filter']);
        $Parameters = $Dict['DecodeParms'] ?? $Dict['DP'] ?? null;
        $Parameters = \is_array($Parameters) ? ($Parameters[0] === 'a' ? $Parameters[1] : [$Parameters]) : [];
        foreach ($Filters as $I => $Filter) {
            $Params = isset($Parameters[$I]) && \is_array($Parameters[$I]) && $Parameters[$I][0] === 'd' ? $Parameters[$I][1] : [];
            $Max = \min($this->MaxStreamSize, $this->Budget);
            if ($Max < 1) {
                break;
            }
            if ($Filter === 'FlateDecode' || $Filter === 'Fl') {
                $Raw = $this->applyPredictor($this->inflate($Raw, $Max), $Params);
            } elseif ($Filter === 'LZWDecode' || $Filter === 'LZW') {
                $Early = isset($Params['EarlyChange']) && $Params['EarlyChange'] === 0 ? 0 : 1;
                $Raw = $this->applyPredictor($this->decodeLZW($Raw, $Early, $Max), $Params);
            } elseif ($Filter === 'ASCIIHexDecode' || $Filter === 'AHx') {
                $Raw = $this->decodeAsciiHex($Raw);
            } elseif ($Filter === 'ASCII85Decode' || $Filter === 'A85') {
                $Raw = $this->decodeAscii85($Raw);
            } elseif ($Filter === 'RunLengthDecode' || $Filter === 'RL') {
                $Raw = $this->decodeRunLength($Raw, $Max);
            } elseif ($Filter === 'Crypt' && (!isset($Params['Name']) || $Params['Name'] === ['n', 'Identity'])) {
                continue;
            } else {
                /** Image filters, and anything which can't be handled. Leave as it is. */
                break;
            }
            $this->Budget -= \strlen($Raw);
        }
        return $this->Decoded[$K] = $Raw;
    }

    /**
     * Returns the names listed by a filter entry (either a name or an array of names).
     *
     * @param mixed $Value The value.
     * @return array The names.
     */
    private function namesOf($Value): array
    {
        if (!\is_array($Value)) {
            return [];
        }
        if ($Value[0] === 'n') {
            return [$Value[1]];
        }
        $Out = [];
        if ($Value[0] === 'a') {
            foreach ($Value[1] as $Item) {
                $Out[] = \is_array($Item) && $Item[0] === 'n' ? $Item[1] : '';
            }
        }
        return $Out;
    }

    /**
     * Inflates data; tolerant of truncated and damaged data (returns whatever
     * could be recovered) and limits the size of the output.
     *
     * @param string $In The compressed data.
     * @param int $Max The maximum size of the output.
     * @return string The inflated data.
     */
    private function inflate(string $In, int $Max): string
    {
        if (!\function_exists('inflate_init')) {
            return $In;
        }
        $Len = \strlen($In);
        $Out = '';

        /**
         * Damaged data is expected here (and inflate_add warns about it), so
         * warnings are silenced for the duration, regardless of the error
         * handler that the caller has installed.
         */
        \set_error_handler(function (): bool {
            return true;
        });
        foreach ([\ZLIB_ENCODING_DEFLATE, \ZLIB_ENCODING_RAW] as $Encoding) {
            $Context = \inflate_init($Encoding);
            if ($Context === false) {
                continue;
            }
            $Out = '';
            for ($Offset = 0; $Offset < $Len; $Offset += 8192) {
                $Piece = \inflate_add($Context, \substr($In, $Offset, 8192));
                if ($Piece === false) {
                    break;
                }
                $Out .= $Piece;
                if (\strlen($Out) >= $Max) {
                    $Out = \substr($Out, 0, $Max);
                    break 2;
                }
                if (\inflate_get_status($Context) === \ZLIB_STREAM_END) {
                    break;
                }
            }
            if ($Out !== '') {
                break;
            }
        }
        \restore_error_handler();
        return $Out;
    }

    /**
     * Decodes ASCIIHex data.
     *
     * @param string $In The data.
     * @return string The decoded data.
     */
    private function decodeAsciiHex(string $In): string
    {
        if (($E = \strpos($In, '>')) !== false) {
            $In = \substr($In, 0, $E);
        }
        $In = \preg_replace('~[^0-9A-Fa-f]~', '', $In);
        if (\strlen($In) % 2) {
            $In .= '0';
        }
        return $In === '' ? '' : (string)\hex2bin($In);
    }

    /**
     * Decodes Ascii85 data.
     *
     * @param string $In The data.
     * @return string The decoded data.
     */
    private function decodeAscii85(string $In): string
    {
        $In = \preg_replace('~[\x00\t\n\f\r ]+~', '', $In);
        if (\substr($In, 0, 2) === '<~') {
            $In = \substr($In, 2);
        }
        if (($E = \strpos($In, '~')) !== false) {
            $In = \substr($In, 0, $E);
        }
        $Len = \strlen($In);
        $Out = '';
        $Value = 0;
        $Count = 0;
        for ($I = 0; $I < $Len; $I++) {
            $C = \ord($In[$I]);
            if ($C === 122 && $Count === 0) {
                $Out .= "\0\0\0\0";
                continue;
            }
            if ($C < 33 || $C > 117) {
                continue;
            }
            $Value = $Value * 85 + ($C - 33);
            if (++$Count === 5) {
                $Out .= \pack('N', $Value & 0xFFFFFFFF);
                $Value = 0;
                $Count = 0;
            }
        }
        if ($Count > 1) {
            for ($I = $Count; $I < 5; $I++) {
                $Value = $Value * 85 + 84;
            }
            $Out .= \substr(\pack('N', $Value & 0xFFFFFFFF), 0, $Count - 1);
        }
        return $Out;
    }

    /**
     * Decodes RunLength data.
     *
     * @param string $In The data.
     * @param int $Max The maximum size of the output.
     * @return string The decoded data.
     */
    private function decodeRunLength(string $In, int $Max): string
    {
        $Len = \strlen($In);
        $Out = '';
        $I = 0;
        while ($I < $Len && \strlen($Out) < $Max) {
            $L = \ord($In[$I++]);
            if ($L === 128) {
                break;
            }
            if ($L < 128) {
                $Out .= \substr($In, $I, $L + 1);
                $I += $L + 1;
            } elseif ($I < $Len) {
                $Out .= \str_repeat($In[$I++], 257 - $L);
            }
        }
        return \substr($Out, 0, $Max);
    }

    /**
     * Decodes LZW data (the variant used by PDF; most significant bit first).
     *
     * @param string $In The data.
     * @param int $Early The EarlyChange parameter (0 or 1).
     * @param int $Max The maximum size of the output.
     * @return string The decoded data.
     */
    private function decodeLZW(string $In, int $Early, int $Max): string
    {
        $Len = \strlen($In);
        $Table = [];
        $Next = 258;
        $Bits = 9;
        $Previous = null;
        $Accumulator = 0;
        $Held = 0;
        $Offset = 0;
        $Out = '';
        $OutLen = 0;
        while (true) {
            while ($Held < $Bits) {
                if ($Offset >= $Len) {
                    break 2;
                }
                $Accumulator = ($Accumulator << 8) | \ord($In[$Offset++]);
                $Held += 8;
            }
            $Code = ($Accumulator >> ($Held - $Bits)) & ((1 << $Bits) - 1);
            $Held -= $Bits;
            $Accumulator &= (1 << $Held) - 1;
            if ($Code === 256) {
                $Table = [];
                $Next = 258;
                $Bits = 9;
                $Previous = null;
                continue;
            }
            if ($Code === 257) {
                break;
            }
            if ($Code < 256) {
                $Entry = \chr($Code);
            } elseif (isset($Table[$Code])) {
                $Entry = $Table[$Code];
            } elseif ($Code === $Next && $Previous !== null) {
                $Entry = $Previous . $Previous[0];
            } else {
                break;
            }
            $Out .= $Entry;
            $OutLen += \strlen($Entry);
            if ($OutLen >= $Max) {
                return \substr($Out, 0, $Max);
            }
            if ($Previous !== null && $Next < 4096) {
                $Table[$Next++] = $Previous . $Entry[0];
            }
            $Previous = $Entry;
            if ($Next + $Early >= (1 << $Bits) && $Bits < 12) {
                $Bits++;
            }
        }
        return $Out;
    }

    /**
     * Reverses a predictor (PNG predictors, and the TIFF predictor for 8 bit data).
     *
     * @param string $Data The decoded data.
     * @param array $Params The filter's decode parameters.
     * @return string The data with the predictor reversed.
     */
    private function applyPredictor(string $Data, array $Params): string
    {
        $Predictor = isset($Params['Predictor']) && \is_int($Params['Predictor']) ? $Params['Predictor'] : 1;
        if ($Predictor < 2 || $Data === '') {
            return $Data;
        }
        $Colors = isset($Params['Colors']) && \is_int($Params['Colors']) ? \max(1, \min(32, $Params['Colors'])) : 1;
        $Depth = isset($Params['BitsPerComponent']) && \is_int($Params['BitsPerComponent']) ? $Params['BitsPerComponent'] : 8;
        $Columns = isset($Params['Columns']) && \is_int($Params['Columns']) ? \max(1, \min(1048576, $Params['Columns'])) : 1;
        if (!\in_array($Depth, [1, 2, 4, 8, 16], true)) {
            return $Data;
        }
        $RowSize = (int)\ceil($Colors * $Depth * $Columns / 8);
        $Step = \max(1, (int)\ceil($Colors * $Depth / 8));
        $Len = \strlen($Data);
        $Out = '';

        /** TIFF predictor (only for 8 bit components; others are left as they are). */
        if ($Predictor === 2) {
            if ($Depth !== 8) {
                return $Data;
            }
            for ($Offset = 0; $Offset < $Len; $Offset += $RowSize) {
                $Row = \array_values(\unpack('C*', \substr($Data, $Offset, $RowSize)));
                for ($I = $Step, $N = \count($Row); $I < $N; $I++) {
                    $Row[$I] = ($Row[$I] + $Row[$I - $Step]) & 0xFF;
                }
                $Out .= \pack('C*', ...$Row);
            }
            return $Out;
        }

        /** PNG predictors. */
        $Previous = [];
        for ($Offset = 0; $Offset < $Len; $Offset += $RowSize + 1) {
            $Tag = \ord($Data[$Offset]);
            $Slice = \substr($Data, $Offset + 1, $RowSize);
            if ($Slice === '') {
                break;
            }
            $Row = \array_values(\unpack('C*', $Slice));
            for ($I = 0, $N = \count($Row); $I < $N; $I++) {
                $A = $I >= $Step ? $Row[$I - $Step] : 0;
                $B = $Previous[$I] ?? 0;
                if ($Tag === 1) {
                    $Row[$I] = ($Row[$I] + $A) & 0xFF;
                } elseif ($Tag === 2) {
                    $Row[$I] = ($Row[$I] + $B) & 0xFF;
                } elseif ($Tag === 3) {
                    $Row[$I] = ($Row[$I] + (($A + $B) >> 1)) & 0xFF;
                } elseif ($Tag === 4) {
                    $C = $I >= $Step ? ($Previous[$I - $Step] ?? 0) : 0;
                    $P = $A + $B - $C;
                    $PA = \abs($P - $A);
                    $PB = \abs($P - $B);
                    $PC = \abs($P - $C);
                    $Row[$I] = ($Row[$I] + ($PA <= $PB && $PA <= $PC ? $A : ($PB <= $PC ? $B : $C))) & 0xFF;
                }
            }
            $Out .= \pack('C*', ...$Row);
            $Previous = $Row;
        }
        return $Out;
    }
}
