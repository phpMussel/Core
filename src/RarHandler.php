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
 * This file: Rar handler (last modified: 2021.07.10).
 */

namespace phpMussel\Core;

class RarHandler extends ArchiveHandler
{
    /**
     * @var \RarArchive The rar object.
     */
    private $RarObject;

    /**
     * @var string A copy of the original pointer used.
     */
    private $PointerSelf;

    /**
     * @var \RarEntry|false The current rar entry.
     */
    private $RarEntry;

    /**
     * @var array|false A list of all Rar entries.
     */
    private $RarEntries;

    /**
     * Construct the rar archive object.
     *
     * @param string $Pointer
     * @return void
     */
    public function __construct($Pointer)
    {
        /** Rar class requirements guard. */
        if (!class_exists('\RarArchive') || !class_exists('\RarEntry')) {
            $this->ErrorState = 1;
            return;
        }

        /** Bad pointer guard. */
        if (!is_readable($Pointer)) {
            $this->ErrorState = 2;
            return;
        }

        $this->RarObject = \RarArchive::open($Pointer);
        $this->ErrorState = is_object($this->RarObject) ? 0 : 2;
        $this->PointerSelf = $Pointer;
    }

    /**
     * Destruct the Rar archive object.
     *
     * @return void
     */
    public function __destruct()
    {
        if (is_object($this->RarObject) && $this->ErrorState === 0) {
            $this->RarObject->close();
        }
    }

    /**
     * Return the actual entry in the archive at the current entry pointer.
     *
     * @param int $Bytes Optionally, how many bytes to read from the entry.
     * @return string The entry's content, or an empty string if not available.
     */
    public function EntryRead(int $Bytes = -1): string
    {
        $Actual = $this->EntryActualSize();
        if ($Bytes < 0 || $Bytes > $Actual) {
            $Bytes = $Actual;
        }
        $Output = '';
        if ($Bytes > 0 && ($Stream = $this->RarEntry->getStream())) {
            $Output .= fread($Stream, $this->RarEntry->getUnpackedSize());
            fclose($Stream);
        }
        return $Output;
    }

    /**
     * Return the compressed size of the entry at the current entry pointer.
     *
     * @return int
     */
    public function EntryCompressedSize(): int
    {
        return is_object($this->RarEntry) ? (int)$this->RarEntry->getPackedSize() : 0;
    }

    /**
     * Return the actual size of the entry at the current entry pointer.
     *
     * @return int
     */
    public function EntryActualSize(): int
    {
        return is_object($this->RarEntry) ? (int)$this->RarEntry->getUnpackedSize() : 0;
    }

    /**
     * Return whether the entry at the current entry pointer is a directory.
     *
     * @return bool True = Is a directory. False = Isn't a directory.
     */
    public function EntryIsDirectory(): bool
    {
        return is_object($this->RarEntry) ? $this->RarEntry->isDirectory() : false;
    }

    /**
     * Return whether the entry at the current entry pointer is encrypted.
     *
     * @return bool True = Is encrypted. False = Isn't encrypted.
     */
    public function EntryIsEncrypted(): bool
    {
        return is_object($this->RarEntry) ? $this->RarEntry->isEncrypted() : false;
    }

    /**
     * Return the reported internal CRC hash for the entry, if it exists.
     *
     * @return string
     */
    public function EntryCRC(): string
    {
        return is_object($this->RarEntry) ? (string)$this->RarEntry->getCrc() : '';
    }

    /**
     * Return the name of the entry at the current entry pointer.
     *
     * @return string The name of the entry at the current entry pointer, or an
     *      empty string if there's no entry or if the entry pointer is invalid.
     */
    public function EntryName(): string
    {
        if (is_object($this->RarEntry)) {
            $Try = $this->RarEntry->getName();
            if (is_string($Try)) {
                return $Try;
            }
        }
        return '';
    }

    /**
     * Move the entry pointer ahead.
     *
     * @return bool False if there aren't any more entries.
     */
    public function EntryNext(): bool
    {
        if (!is_array($this->RarEntries)) {
            $this->RarEntries = scandir('rar://' . $this->PointerSelf);
        }
        if (is_array($this->RarEntries) && !empty($this->RarEntries)) {
            $this->RarEntry = $this->RarObject->getEntry(array_shift($this->RarEntries));
            return true;
        }
        return false;
    }
}
