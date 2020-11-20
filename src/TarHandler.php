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
 * This file: Tar handler (last modified: 2020.11.19).
 */

namespace phpMussel\Core;

class TarHandler extends ArchiveHandler
{
    /**
     * @var int Archive seek offset.
     */
    private $Offset = 0;

    /**
     * @var int The total size of the archive.
     */
    private $TotalSize = 0;

    /**
     * @var string The archive's actual content.
     */
    private $Data = '';

    /**
     * @var bool Whether we've initialised an entry yet.
     */
    private $Initialised = false;

    /**
     * Construct the tar archive object.
     *
     * @param string $File
     */
    public function __construct($File)
    {
        /** Guard against the wrong type of file being used as pointer. */
        if (substr($File, 257, 6) !== "ustar\0") {
            $this->ErrorState = 2;
            return;
        }

        /** Set total size. */
        $this->TotalSize = strlen($File);

        /** Set archive data. */
        $this->Data = $File;

        /** All is good. */
        $this->ErrorState = 0;
    }

    /**
     * Return the actual entry in the archive at the current entry pointer.
     *
     * @param int $Bytes Optionally, how many bytes to read from the entry.
     * @return string The entry's content or an empty string.
     */
    public function EntryRead(int $Bytes = -1)
    {
        $Actual = $this->EntryActualSize();
        if ($Bytes < 0 || $Bytes > $Actual) {
            $Bytes = $Actual;
        }
        return substr($this->Data, $this->Offset + 512, $Bytes);
    }

    /**
     * Return the compressed size of the entry at the current entry pointer.
     * Note: Tar doesn't compress, so in this case, it's the same as the uncompressed size.
     */
    public function EntryCompressedSize()
    {
        return octdec(preg_replace('/\D/', '', substr($this->Data, $this->Offset + 124, 12))) ?: 0;
    }

    /**
     * Return the actual size of the entry at the current entry pointer.
     */
    public function EntryActualSize()
    {
        return octdec(preg_replace('/\D/', '', substr($this->Data, $this->Offset + 124, 12))) ?: 0;
    }

    /**
     * Return whether the entry at the current entry pointer is a directory.
     *
     * @return bool True = Is a directory. False = Isn't a directory.
     */
    public function EntryIsDirectory(): bool
    {
        $Name = $this->EntryName();
        $Separator = substr($Name, -1, 1);
        return (($Separator === "\\" || $Separator === '/') && $this->EntryActualSize() === 0);
    }

    /**
     * Return whether the entry at the current entry pointer is encrypted.
     *
     * @return false Tar doesn't use encryption.
     */
    public function EntryIsEncrypted(): bool
    {
        return false;
    }

    /**
     * Return the reported internal CRC hash for the entry, if it exists.
     *
     * @return false Tar doesn't provide internal CRCs.
     */
    public function EntryCRC()
    {
        return false;
    }

    /**
     * Return the name of the entry at the current entry pointer.
     */
    public function EntryName()
    {
        return preg_replace('/[^\x20-\xff]/', '', substr($this->Data, $this->Offset, 100));
    }

    /**
     * Move the entry pointer ahead.
     *
     * @return bool False if there aren't any more entries.
     */
    public function EntryNext(): bool
    {
        if (($this->Offset + 1024) > $this->TotalSize) {
            return false;
        }
        if (!$this->Initialised) {
            return ($this->Initialised = true);
        }
        $Actual = $this->EntryActualSize();
        $Blocks = $Actual > 0 ? ceil($Actual / 512) + 1 : 1;
        $this->Offset += $Blocks * 512;
        return true;
    }
}
