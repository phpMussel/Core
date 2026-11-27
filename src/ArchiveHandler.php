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
 * This file: Archive handler (last modified: 2026.11.27).
 */

namespace phpMussel\Core;

/**
 * Defines common members that should be utilised by all archive handler
 * classes. Each member should be commented with its purpose and usage.
 */
abstract class ArchiveHandler implements ArchiveHandlerInterface
{
    /**
     * @var int The instance's error state (in case something goes wrong).
     *
     * -1: Object not constructed (default state; shouldn't normally be seen).
     * 0: Object constructed successfully. No problems, as far as we know.
     * 1: Necessary prerequisites/extensions aren't installed/available.
     * 2: Pointer isn't valid, isn't accessible, or failed to open/stream.
     */
    public $ErrorState = -1;

    /**
     * Works out how much memory PHP has left to work with.
     *
     * @param int $Unlimited What to return when PHP's memory isn't limited.
     * @return int The number of bytes.
     */
    public static function memoryHeadroom(int $Unlimited = 536870912): int
    {
        $Limit = \trim((string)\ini_get('memory_limit'));
        $Bytes = (int)$Limit;
        if ($Limit === '' || $Bytes <= 0) {
            return $Unlimited;
        }
        $Unit = \strtolower(\substr($Limit, -1));
        if ($Unit === 'g') {
            $Bytes *= 1073741824;
        } elseif ($Unit === 'm') {
            $Bytes *= 1048576;
        } elseif ($Unit === 'k') {
            $Bytes *= 1024;
        }
        return \max(0, $Bytes - \memory_get_usage());
    }
}
