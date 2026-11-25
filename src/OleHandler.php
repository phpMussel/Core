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
 * This file: OLE handler (last modified: 2026.11.26).
 */

namespace phpMussel\Core;

/**
 * Treats an OLE2 compound file (the binary format used by legacy Office
 * documents, and by the "vbaProject.bin" parts of modern ones) as a
 * pseudo-archive.
 *
 * The compound file itself is mostly uninteresting to expose, because its
 * streams are stored as they are, and the scanner has already looked at those
 * bytes by looking at the file as a whole. What this handler exposes is the
 * content which is stored in a transformed form, and which therefore can't be
 * seen by scanning the file as a whole:
 *
 * - VBA macros. The source code of every VBA module is stored compressed
 *   (MS-OVBA), so each module is decompressed and exposed as "<Module>.bas".
 * - Embedded OLE objects within PowerPoint presentations. These are stored
 *   deflated within "ExOleObjStg" records, so each is inflated and exposed as
 *   "ExOleObjStg.bin" (it's usually another compound file, which the scanner
 *   then recurses into, reaching any macros inside of it).
 *
 * @link https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/
 * @link https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-ovba/
 * @link https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-ppt/
 */
class OleHandler extends ArchiveHandler
{
    /** The magic number identifying a compound file. */
    public const SIGNATURE = "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1";

    /** The maximum number of entries that will be exposed. */
    private const MAX_ENTRIES = 10000;

    /** The maximum number of directory entries that will be considered. */
    private const MAX_DIRECTORY_ENTRIES = 100000;

    /** The maximum number of PowerPoint records that will be visited. */
    private const MAX_RECORDS = 500000;

    /** The maximum size of any one exposed entry. */
    private const MAX_ENTRY_SIZE = 33554432;

    /** The maximum combined size of all exposed entries. */
    private const MAX_TOTAL_SIZE = 134217728;

    /** Sector values with special meanings. */
    private const MAX_REGULAR_SECTOR = 0xFFFFFFFA;
    private const END_OF_CHAIN = 0xFFFFFFFE;

    /** @var array The entries to expose (each with Name, Data and CompressedSize). */
    private $Entries = [];

    /** @var int The entry pointer. */
    private $Cursor = -1;

    /** @var int Running total of exposed data. */
    private $Total = 0;

    /** @var string The compound file. */
    private $D = '';

    /** @var int Sector size. */
    private $SectorSize = 512;

    /** @var int Mini sector size. */
    private $MiniSectorSize = 64;

    /** @var int Streams smaller than this live in the mini stream. */
    private $MiniCutoff = 4096;

    /** @var int The number of sectors the file can contain. */
    private $SectorCount = 0;

    /** @var int[] The file allocation table. */
    private $Fat = [];

    /** @var int[] The mini file allocation table. */
    private $MiniFat = [];

    /** @var string The mini stream. */
    private $MiniStream = '';

    /** @var array Directory entries. */
    private $Directory = [];

    /**
     * Construct the object.
     *
     * @param string $Data The content of the compound file.
     */
    public function __construct(string $Data)
    {
        if (\substr($Data, 0, 8) !== self::SIGNATURE || \strlen($Data) < 512) {
            $this->ErrorState = 2;
            return;
        }
        $this->D = $Data;
        $this->ErrorState = 0;
        if (!$this->parse()) {
            /** Not a usable compound file. Nothing to expose, but it isn't a scanning failure. */
            $this->Entries = [];
        }
        $this->D = '';
        $this->Fat = $this->MiniFat = $this->Directory = [];
        $this->MiniStream = '';
    }

    /**
     * Return the content of the entry at the current entry pointer.
     *
     * @param int $Bytes Optional number of bytes to read.
     * @return string The entry's content.
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
     * @return false Exposed entries are never directories.
     */
    public function EntryIsDirectory(): bool
    {
        return false;
    }

    /**
     * Return whether the entry at the current entry pointer is encrypted.
     *
     * @return false Encrypted content can't be told apart from other content here.
     */
    public function EntryIsEncrypted(): bool
    {
        return false;
    }

    /**
     * Return the reported internal CRC hash for the entry, if it exists.
     *
     * @return string Empty because compound files don't provide CRCs for streams.
     */
    public function EntryCRC(): string
    {
        return '';
    }

    /**
     * Return the name of the entry at the current entry pointer.
     *
     * @return string
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
     * Adds an entry, subject to the limits.
     *
     * @param string $Name The entry's name.
     * @param string $Data The entry's content.
     * @param int $CompressedSize The size of the entry before it was decoded.
     * @return bool False when a limit has been reached (nothing more should be added).
     */
    private function addEntry(string $Name, string $Data, int $CompressedSize): bool
    {
        $Len = \strlen($Data);
        if ($Len === 0) {
            return true;
        }
        if (\count($this->Entries) >= self::MAX_ENTRIES || $this->Total + $Len > self::MAX_TOTAL_SIZE) {
            return false;
        }
        $this->Total += $Len;
        $this->Entries[] = ['Name' => $Name, 'Data' => $Data, 'CompressedSize' => $CompressedSize];
        return true;
    }

    /**
     * Reads a little-endian unsigned 32-bit integer.
     *
     * @param string $Data The data to read from.
     * @param int $Offset Where to read it from.
     * @return int
     */
    private static function u32(string $Data, int $Offset): int
    {
        return \unpack('V', \substr($Data, $Offset, 4) . "\0\0\0\0")[1];
    }

    /**
     * Reads a little-endian unsigned 16-bit integer.
     *
     * @param string $Data The data to read from.
     * @param int $Offset Where to read it from.
     * @return int
     */
    private static function u16(string $Data, int $Offset): int
    {
        return \unpack('v', \substr($Data, $Offset, 2) . "\0\0")[1];
    }

    /**
     * Parses the compound file's structure and looks for content to expose.
     *
     * @return bool False if the structure isn't usable.
     */
    private function parse(): bool
    {
        $D = $this->D;
        $Len = \strlen($D);
        if (self::u16($D, 28) !== 0xFFFE) {
            return false;
        }
        $SectorShift = self::u16($D, 30);
        $MiniShift = self::u16($D, 32);
        if (($SectorShift !== 9 && $SectorShift !== 12) || $MiniShift !== 6) {
            return false;
        }
        $this->SectorSize = 1 << $SectorShift;
        $this->MiniSectorSize = 1 << $MiniShift;
        $this->SectorCount = \intdiv($Len, $this->SectorSize);
        $DirStart = self::u32($D, 48);
        $this->MiniCutoff = self::u32($D, 56);
        $MiniFatStart = self::u32($D, 60);
        $MiniFatCount = self::u32($D, 64);
        $DifatStart = self::u32($D, 68);
        $DifatCount = self::u32($D, 72);
        $FatCount = self::u32($D, 44);
        if ($FatCount > $this->SectorCount || $MiniFatCount > $this->SectorCount || $DifatCount > $this->SectorCount) {
            return false;
        }

        /** Locate the FAT's sectors (109 in the header, then the DIFAT chain). */
        $FatSectors = [];
        for ($I = 0; $I < 109; $I++) {
            $FatSectors[] = self::u32($D, 76 + $I * 4);
        }
        $Per = \intdiv($this->SectorSize, 4) - 1;
        $Next = $DifatStart;
        for ($I = 0; $I < $DifatCount && $Next < self::MAX_REGULAR_SECTOR; $I++) {
            $Offset = ($Next + 1) * $this->SectorSize;
            if ($Offset + $this->SectorSize > $Len) {
                break;
            }
            for ($J = 0; $J < $Per; $J++) {
                $FatSectors[] = self::u32($D, $Offset + $J * 4);
            }
            $Next = self::u32($D, $Offset + $Per * 4);
        }
        $Used = 0;
        foreach ($FatSectors as $Sector) {
            if ($Sector >= self::MAX_REGULAR_SECTOR || $Used >= $FatCount) {
                continue;
            }
            $Offset = ($Sector + 1) * $this->SectorSize;
            if ($Offset + $this->SectorSize > $Len) {
                continue;
            }
            $Used++;
            $Chunk = \unpack('V*', \substr($D, $Offset, $this->SectorSize));
            foreach ($Chunk as $Value) {
                $this->Fat[] = $Value;
            }
        }
        if (!$this->Fat) {
            return false;
        }

        /** Directory. */
        $DirData = $this->readChain($DirStart, $this->Fat, $this->SectorSize, $D, 1, self::MAX_DIRECTORY_ENTRIES * 128);
        $Count = \min(\intdiv(\strlen($DirData), 128), self::MAX_DIRECTORY_ENTRIES);
        for ($I = 0; $I < $Count; $I++) {
            $E = \substr($DirData, $I * 128, 128);
            $NameLen = \min(\max(self::u16($E, 64) - 2, 0), 62);
            $Raw = \substr($E, 0, $NameLen);
            $Name = '';
            for ($J = 0; $J + 1 < $NameLen; $J += 2) {
                $Lo = \ord($Raw[$J]);
                $Name .= (\ord($Raw[$J + 1]) === 0 && $Lo > 0) ? \chr($Lo) : '_';
            }
            $this->Directory[$I] = [
                'Name' => $Name,
                'Type' => \ord($E[66]),
                'Left' => self::u32($E, 68),
                'Right' => self::u32($E, 72),
                'Child' => self::u32($E, 76),
                'Start' => self::u32($E, 116),
                'Size' => self::u32($E, 120)
            ];
        }
        if (!isset($this->Directory[0]) || $this->Directory[0]['Type'] !== 5) {
            return false;
        }

        /** Mini FAT and mini stream. */
        if ($MiniFatCount > 0 && $MiniFatStart < self::MAX_REGULAR_SECTOR) {
            $Raw = $this->readChain($MiniFatStart, $this->Fat, $this->SectorSize, $D, 1, $MiniFatCount * $this->SectorSize);
            $Words = \strlen($Raw) >= 4 ? \unpack('V*', \substr($Raw, 0, \strlen($Raw) - (\strlen($Raw) % 4))) : [];
            $this->MiniFat = \array_values($Words);
        }
        $this->MiniStream = $this->readChain(
            $this->Directory[0]['Start'],
            $this->Fat,
            $this->SectorSize,
            $D,
            1,
            \min($this->Directory[0]['Size'], $Len)
        );

        /** Walk the directory tree, collecting each stream with its storage. */
        $Streams = [];
        $Seen = [];
        $Stack = [[$this->Directory[0]['Child'], 0]];
        while ($Stack) {
            [$Index, $Parent] = \array_pop($Stack);
            if ($Index >= self::MAX_REGULAR_SECTOR || !isset($this->Directory[$Index]) || isset($Seen[$Index])) {
                continue;
            }
            $Seen[$Index] = true;
            $E = $this->Directory[$Index];
            $Stack[] = [$E['Left'], $Parent];
            $Stack[] = [$E['Right'], $Parent];
            if ($E['Type'] === 2) {
                $Streams[$Parent][\strtolower($E['Name'])] = $Index;
            } elseif ($E['Type'] === 1) {
                $Stack[] = [$E['Child'], $Index];
            }
        }

        /** VBA projects: any storage with a stream named "dir" and a storage named "VBA". */
        foreach ($Streams as $Storage => $Members) {
            if (!isset($Members['dir']) || \strtolower($this->Directory[$Storage]['Name'] ?? '') !== 'vba') {
                continue;
            }
            if (!$this->extractVba($Storage, $Members)) {
                return true;
            }
        }

        /** PowerPoint embedded objects. */
        if (isset($Streams[0]['powerpoint document'])) {
            $this->extractPowerPoint($this->streamData($Streams[0]['powerpoint document']));
        }
        return true;
    }

    /**
     * Follows a chain of sectors.
     *
     * @param int $Start The first sector.
     * @param array $Table The allocation table to follow.
     * @param int $Size The size of each sector.
     * @param string $Source The data the sectors are in.
     * @param int $Shift Offset (in sectors) between sector numbers and positions (1 for regular sectors, 0 for the mini stream).
     * @param int $Max The maximum number of bytes to return.
     * @return string The data.
     */
    private function readChain(int $Start, array $Table, int $Size, string $Source, int $Shift, int $Max): string
    {
        $Out = '';
        $Steps = 0;
        $Limit = \count($Table) + 1;
        $Sector = $Start;
        $SourceLen = \strlen($Source);
        while ($Sector < self::MAX_REGULAR_SECTOR && $Steps++ < $Limit && \strlen($Out) < $Max) {
            $Offset = ($Sector + $Shift) * $Size;
            if ($Offset < 0 || $Offset >= $SourceLen) {
                break;
            }
            $Out .= \substr($Source, $Offset, $Size);
            $Sector = $Table[$Sector] ?? self::END_OF_CHAIN;
        }
        return \substr($Out, 0, $Max);
    }

    /**
     * Reads a stream's content.
     *
     * @param int $Index The directory entry.
     * @return string
     */
    private function streamData(int $Index): string
    {
        $E = $this->Directory[$Index];
        $Size = \min($E['Size'], self::MAX_ENTRY_SIZE);
        if ($E['Size'] < $this->MiniCutoff) {
            return $this->readChain($E['Start'], $this->MiniFat, $this->MiniSectorSize, $this->MiniStream, 0, $Size);
        }
        return $this->readChain($E['Start'], $this->Fat, $this->SectorSize, $this->D, 1, $Size);
    }

    /**
     * Decompresses MS-OVBA compressed data.
     *
     * @param string $In The compressed data (including the leading signature byte).
     * @return string The decompressed data (as much as could be recovered).
     */
    public static function decompressVba(string $In): string
    {
        $Len = \strlen($In);
        if ($Len < 1 || $In[0] !== "\x01") {
            return '';
        }
        $Out = '';
        $I = 1;
        while ($I + 2 <= $Len && \strlen($Out) < self::MAX_ENTRY_SIZE) {
            $Header = self::u16($In, $I);
            $End = \min($I + ($Header & 0x0FFF) + 3, $Len);
            $Flag = ($Header >> 15) & 1;
            $J = $I + 2;
            $I = $End;
            $Start = \strlen($Out);
            if (!$Flag) {
                $Out .= \substr($In, $J, \min($End - $J, 4096));
                continue;
            }
            while ($J < $End) {
                $Token = \ord($In[$J++]);
                for ($Bit = 0; $Bit < 8 && $J < $End; $Bit++) {
                    if (!(($Token >> $Bit) & 1)) {
                        $Out .= $In[$J++];
                        continue;
                    }
                    if ($J + 2 > $End) {
                        break 2;
                    }
                    $Copy = self::u16($In, $J);
                    $J += 2;
                    $Decompressed = \strlen($Out) - $Start;
                    $Bits = 4;
                    while ($Bits < 12 && (1 << $Bits) < $Decompressed) {
                        $Bits++;
                    }
                    $Offset = ($Copy >> (16 - $Bits)) + 1;
                    $Length = ($Copy & (0xFFFF >> $Bits)) + 3;
                    if ($Offset > $Decompressed) {
                        break 2;
                    }
                    for ($K = 0; $K < $Length; $K++) {
                        $Out .= $Out[\strlen($Out) - $Offset];
                    }
                }
            }
        }
        return $Out;
    }

    /**
     * Exposes the source code of a VBA project's modules.
     *
     * @param int $Storage The "VBA" storage's directory entry.
     * @param array $Members Its streams (lowercase name => directory entry).
     * @return bool False when a limit has been reached.
     */
    private function extractVba(int $Storage, array $Members): bool
    {
        $Dir = self::decompressVba($this->streamData($Members['dir']));
        $Len = \strlen($Dir);
        $I = 0;
        $Modules = [];
        $Current = -1;
        while ($I + 6 <= $Len) {
            $Id = self::u16($Dir, $I);
            $Size = self::u32($Dir, $I + 2);
            if ($Id === 0x0009) {
                /** PROJECTVERSION is the one record with a different layout (the size field is fixed at 4, but 2 more bytes follow). */
                $Size = 4;
            }
            $Body = \substr($Dir, $I + 6, $Size);
            $I += 6 + $Size + ($Id === 0x0009 ? 2 : 0);
            if ($Id === 0x0019) {
                $Modules[++$Current] = ['Name' => $Body, 'Stream' => $Body, 'Offset' => 0];
            } elseif ($Id === 0x001A && $Current >= 0) {
                $Modules[$Current]['Stream'] = $Body;
            } elseif ($Id === 0x0031 && $Current >= 0 && \strlen($Body) >= 4) {
                $Modules[$Current]['Offset'] = self::u32($Body, 0);
            } elseif ($Id === 0x0010) {
                break;
            }
            if ($Current >= 1000) {
                break;
            }
        }
        foreach ($Modules as $Module) {
            $Key = \strtolower($Module['Stream']);
            if (!isset($Members[$Key])) {
                continue;
            }
            $Raw = $this->streamData($Members[$Key]);
            $Source = self::decompressVba(\substr($Raw, $Module['Offset']));
            $Name = \preg_replace('~[^\x20-\x7E]|[\\\\/]~', '_', $Module['Name']);
            if (!$this->addEntry($Name . '.bas', $Source, \strlen($Raw))) {
                return false;
            }
        }
        return true;
    }

    /**
     * Exposes the embedded objects of a PowerPoint presentation.
     *
     * @param string $Data The content of the "PowerPoint Document" stream.
     * @return void
     */
    private function extractPowerPoint(string $Data): void
    {
        $Len = \strlen($Data);
        $Stack = [[0, $Len]];
        $Visited = 0;
        while ($Stack) {
            [$Offset, $End] = \array_pop($Stack);
            while ($Offset + 8 <= $End) {
                if (++$Visited > self::MAX_RECORDS) {
                    return;
                }
                $VerInstance = self::u16($Data, $Offset);
                $Type = self::u16($Data, $Offset + 2);
                $Size = self::u32($Data, $Offset + 4);
                $Body = $Offset + 8;
                $BodyEnd = \min($Body + $Size, $End);
                $Offset = $BodyEnd;
                if (($VerInstance & 0xF) === 0xF) {
                    $Stack[] = [$Body, $BodyEnd];
                    continue;
                }
                if ($Type !== 0x1011 || $BodyEnd - $Body < 4) {
                    continue;
                }
                $Stored = \substr($Data, $Body + 4, $BodyEnd - $Body - 4);
                if (($VerInstance >> 4) === 1) {
                    $Declared = self::u32($Data, $Body);
                    $Stored = $this->inflate($Stored, \min(\max($Declared, 1), self::MAX_ENTRY_SIZE));
                }
                if (!$this->addEntry('ExOleObjStg.bin', $Stored, $BodyEnd - $Body - 4)) {
                    return;
                }
            }
        }
    }

    /**
     * Inflates zlib data, tolerating damage (returns what could be recovered).
     *
     * @param string $In The deflated data.
     * @param int $Max The maximum number of bytes to return.
     * @return string The inflated data.
     */
    private function inflate(string $In, int $Max): string
    {
        if (!\function_exists('inflate_init')) {
            return '';
        }
        \set_error_handler(function (): bool {
            return true;
        });
        $Out = '';
        $Context = \inflate_init(\ZLIB_ENCODING_DEFLATE);
        if ($Context !== false) {
            for ($Offset = 0, $Len = \strlen($In); $Offset < $Len; $Offset += 8192) {
                $Piece = \inflate_add($Context, \substr($In, $Offset, 8192));
                if ($Piece === false) {
                    break;
                }
                $Out .= $Piece;
                if (\strlen($Out) >= $Max) {
                    $Out = \substr($Out, 0, $Max);
                    break;
                }
                if (\inflate_get_status($Context) === \ZLIB_STREAM_END) {
                    break;
                }
            }
        }
        \restore_error_handler();
        return $Out;
    }
}
