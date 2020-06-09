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
 * This file: Archive handler (last modified: 2020.06.12).
 */

namespace phpMussel\Core;

/**
 * Defines the methods that the archive handler expects should exist within all
 * archive handler classes. Anyone wanting to build new archive handler classes
 * or extend functionality should check this over.
 */
interface ArchiveHandlerInterface
{
    /**
     * Return the actual entry in the archive at the current entry pointer.
     *
     * @param int $Bytes Optionally, how many bytes to read from the entry.
     */
    public function EntryRead(int $Bytes = -1);

    /**
     * Return the compressed size of the entry at the current entry pointer.
     */
    public function EntryCompressedSize();

    /**
     * Return the actual size of the entry at the current entry pointer.
     */
    public function EntryActualSize();

    /**
     * Return whether the entry at the current entry pointer is a directory.
     *
     * @return bool True = Is a directory. False = Isn't a directory.
     */
    public function EntryIsDirectory(): bool;

    /**
     * Return whether the entry at the current entry pointer is encrypted.
     *
     * @return bool True = Is encrypted. False = Isn't encrypted.
     */
    public function EntryIsEncrypted(): bool;

    /**
     * Return the reported internal CRC hash for the entry, if it exists.
     */
    public function EntryCRC();

    /**
     * Return the name of the entry at the current entry pointer.
     */
    public function EntryName();

    /**
     * Move the entry pointer ahead.
     *
     * @return bool False if there aren't any more entries.
     */
    public function EntryNext(): bool;
}
