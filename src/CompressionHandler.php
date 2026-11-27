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
 * This file: Compression handler (last modified: 2026.11.27).
 */

namespace phpMussel\Core;

/**
 * Decompresses data (GZ, BZ, and LZF), while limiting how large the result of
 * decompressing can be, so that decompression bombs (small amounts of data
 * which expand into enormous amounts of data) can't exhaust the system's
 * memory. Data which would decompress to more than the limit is cut off at the
 * limit (what's within the limit is still decompressed, and can be scanned).
 */
class CompressionHandler
{
    /**
     * @var int Default maximum size (in bytes) that decompressing may produce.
     */
    public const DEFAULT_MAX_SIZE = 33554432;

    /**
     * @var int Maximum number of times data will be decompressed in a row
     *      (each layer of compression within compression counts as one).
     */
    private const MAX_LAYERS = 16;

    /**
     * @var int How much to read or decompress at a time (in bytes).
     */
    private const CHUNK = 8192;

    /**
     * @var int Maximum size (in bytes) that decompressing may produce.
     */
    private $MaxSize = self::DEFAULT_MAX_SIZE;

    /**
     * @var string Where temporary files may be written (needed for BZ).
     */
    private $TempPath = '';

    /**
     * @var string The data to be worked upon.
     */
    public $Data = '';

    /**
     * Constructor.
     *
     * @param string $Data The data to be worked upon.
     * @param int $MaxSize Maximum size (in bytes) that decompressing may produce (zero or less for the default).
     * @param string $TempPath Where temporary files may be written (empty for the system's default location).
     * @return void
     */
    public function __construct(string $Data, int $MaxSize = 0, string $TempPath = '')
    {
        $this->Data = $Data;
        if ($MaxSize > 0) {
            $this->MaxSize = $MaxSize;
        }
        $this->TempPath = $TempPath;
    }

    /**
     * Try to decompress using GZ.
     *
     * @return int 0 = Success. 1 = Missing prerequisite. 2 = Failure.
     */
    public function TryGz(): int
    {
        /** Guard. */
        if (\substr($this->Data, 0, 2) !== "\x1f\x8b") {
            return 2;
        }

        /** Continue. */
        return $this->decompressGz();
    }

    /**
     * Try to decompress using BZ.
     *
     * @return int 0 = Success. 1 = Missing prerequisite. 2 = Failure.
     */
    public function TryBz(): int
    {
        /** Guard. */
        if (\substr($this->Data, 0, 3) !== "\x42\x5a\x68") {
            return 2;
        }

        /** Continue. */
        return $this->decompressBz();
    }

    /**
     * Try to decompress using LZF.
     *
     * @return int 0 = Success. 1 = Missing prerequisite. 2 = Failure.
     */
    public function TryLzf(): int
    {
        /** Guard. */
        if (!\function_exists('lzf_decompress')) {
            return 1;
        }

        /** LZF doesn't tell us how large the result will be, so work it out first. */
        $Length = self::lzfPrefixLength($this->Data, $this->effectiveMaxSize());
        if ($Length < 1) {
            return 2;
        }
        $Try = \lzf_decompress($Length < \strlen($this->Data) ? \substr($this->Data, 0, $Length) : $this->Data);

        /** Success. */
        if ($Try !== false && \is_string($Try)) {
            $this->Data = $Try;
            return 0;
        }

        /** Failure. */
        return 2;
    }

    /**
     * Try everything.
     *
     * @return bool The state of the data before and after trying is the same when true is
     *      returned, different when false is returned.
     */
    public function TryEverything(): bool
    {
        /** Fetch original data state. */
        $Original = $this->Data;

        /**
         * Seeing as we're effectively guessing which compression format has
         * been used, and possibly it mightn't be compressed at all, there'll
         * definitely be useless warnings and notices generated. So, let's
         * silence them.
         */
        \set_error_handler(function ($errno, $errstr, $errfile, $errline) {
        });

        /** Loop until data state doesn't change anymore (or until we've gone far enough). */
        for ($Layer = 0; $Layer < self::MAX_LAYERS; $Layer++) {
            if ($this->TryGz() === 0) {
                continue;
            }
            if ($this->TryBz() === 0) {
                continue;
            }
            if ($this->TryLzf() === 0) {
                continue;
            }
            break;
        }

        /** We're done guessing, so we'll restore the previous error handler. */
        \restore_error_handler();

        /**
         * Compare original data state against current data state, and return
         * whether they're the same or different. If the same, then data
         * probably wasn't compressed to begin with.
         */
        return ($Original === $this->Data);
    }

    /**
     * Works out the maximum size (in bytes) that decompressing may produce.
     *
     * Scanning data needs several times as much memory as the data itself
     * takes up, so on systems where PHP is allowed relatively little memory,
     * the limit is reduced accordingly (otherwise, a decompression bomb could
     * still exhaust the memory available, even with a limit in place).
     *
     * @return int The maximum size.
     */
    private function effectiveMaxSize(): int
    {
        $Headroom = ArchiveHandler::memoryHeadroom(\PHP_INT_MAX);
        return \min($this->MaxSize, \max(1048576, \intdiv($Headroom, 8)));
    }

    /**
     * Decompresses GZ data (every member), up to the size limit.
     *
     * @return int 0 = Success. 1 = Missing prerequisite. 2 = Failure.
     */
    private function decompressGz(): int
    {
        /** Guard. */
        if (!\function_exists('inflate_init')) {
            return 1;
        }

        /** Damaged data is expected (and inflate_add warns about it), so silence the warnings. */
        $Max = $this->effectiveMaxSize();
        \set_error_handler(function (): bool {
            return true;
        });
        $Out = '';
        $Finished = false;
        $Start = 0;
        $Len = \strlen($this->Data);

        /** GZ data can consist of several members in a row (decompressing all of them is what gunzip, 7-Zip, etc would do). */
        while ($Start < $Len && \strlen($Out) < $Max && ($Context = \inflate_init(\ZLIB_ENCODING_GZIP)) !== false) {
            $Ended = false;
            for ($Offset = $Start; $Offset < $Len; $Offset += self::CHUNK) {
                $Piece = \inflate_add($Context, \substr($this->Data, $Offset, self::CHUNK));
                if ($Piece === false) {
                    break;
                }
                $Out .= \strlen($Out) + \strlen($Piece) > $Max ? \substr($Piece, 0, $Max - \strlen($Out)) : $Piece;
                if (\inflate_get_status($Context) === \ZLIB_STREAM_END) {
                    $Ended = true;
                    break;
                }
                if (\strlen($Out) >= $Max) {
                    break;
                }
            }
            if (!$Ended) {
                break;
            }
            $Finished = true;
            $Start += \inflate_get_read_len($Context);
            if (\substr($this->Data, $Start, 2) !== "\x1F\x8B") {
                break;
            }
        }
        \restore_error_handler();
        if (!$Finished && $Out === '') {
            return 2;
        }
        $this->Data = $Out;
        return 0;
    }

    /**
     * Decompresses BZ data, up to the size limit.
     *
     * @return int 0 = Success. 1 = Missing prerequisite. 2 = Failure.
     */
    private function decompressBz(): int
    {
        /** Guard. */
        if (!\function_exists('bzopen')) {
            return 1;
        }

        /**
         * PHP can only limit how much BZ data is decompressed at once when reading
         * from a file, so we need a temporary file for this.
         */
        $TempPath = $this->TempPath !== '' ? $this->TempPath : \sys_get_temp_dir();
        $Temp = new TemporaryFileHandler($this->Data, $TempPath);
        if ($Temp->Filename === '') {
            return 2;
        }

        $Max = $this->effectiveMaxSize();
        \set_error_handler(function (): bool {
            return true;
        });
        $Out = '';
        $Failed = false;
        if (($Handle = \bzopen($Temp->Filename, 'r')) !== false) {
            while (\strlen($Out) < $Max) {
                $Piece = \bzread($Handle, self::CHUNK);
                if (!\is_string($Piece)) {
                    $Failed = true;
                    break;
                }
                if ($Piece === '') {
                    break;
                }
                $Out .= \strlen($Out) + \strlen($Piece) > $Max ? \substr($Piece, 0, $Max - \strlen($Out)) : $Piece;
            }
            \bzclose($Handle);
        } else {
            $Failed = true;
        }
        \restore_error_handler();
        unset($Temp);
        if ($Failed && $Out === '') {
            return 2;
        }
        $this->Data = $Out;
        return 0;
    }

    /**
     * Works out how much of some LZF data can be decompressed without exceeding
     * a size limit, without decompressing it (LZF data doesn't say how large it
     * will be when decompressed, and a decompression bomb can't otherwise be
     * told apart from legitimate data).
     *
     * LZF data is a sequence of tokens: either a literal run (the control byte
     * is below 32, and says how many literal bytes follow it), or a back
     * reference (the top three bits of the control byte say how many bytes to
     * copy, a value of 7 meaning that another byte follows to add to it, and
     * the rest of the control byte, together with the byte that follows it, say
     * how far back to copy them from).
     *
     * @param string $Data The LZF data.
     * @param int $Max The maximum size that decompressing may produce.
     * @return int The number of bytes (from the start of the data) that can be
     *      decompressed, or -1 if the data isn't valid LZF data.
     */
    public static function lzfPrefixLength(string $Data, int $Max): int
    {
        $Len = \strlen($Data);
        $Position = 0;
        $Produced = 0;
        $Usable = 0;
        while ($Position < $Len) {
            $Control = \ord($Data[$Position]);
            if ($Control < 32) {
                $Step = $Control + 2;
                $Output = $Control + 1;
                if ($Position + $Step > $Len) {
                    return -1;
                }
            } else {
                $Copy = $Control >> 5;
                $Step = 2;
                if ($Copy === 7) {
                    $Step = 3;
                    if ($Position + 1 >= $Len) {
                        return -1;
                    }
                    $Copy += \ord($Data[$Position + 1]);
                }
                if ($Position + $Step > $Len) {
                    return -1;
                }
                $Distance = (($Control & 31) << 8) + \ord($Data[$Position + $Step - 1]) + 1;
                if ($Distance > $Produced) {
                    return -1;
                }
                $Output = $Copy + 2;
            }
            if ($Produced + $Output > $Max) {
                return $Usable;
            }
            $Produced += $Output;
            $Position += $Step;
            $Usable = $Position;
        }
        return $Usable;
    }
}
