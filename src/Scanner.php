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
 * This file: The scanner (last modified: 2020.07.06).
 */

namespace phpMussel\Core;

class Scanner
{
    /**
     * @var \phpMussel\Core\Loader The instantiated loader object.
     */
    private $Loader;

    /**
     * @var string The path to the core asset files.
     */
    private $AssetsPath = __DIR__ . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'assets' . DIRECTORY_SEPARATOR;

    /**
     * @var string If called from another class, useful as an internal
     *      indicator in some specific situations.
     */
    public $CalledFrom = '';

    /**
     * @var string Crx public key (only populated if the scanned file is Crx).
     */
    private $CrxPubKey = '';

    /**
     * @var string Crx signature (only populated if the scanned file is Crx).
     */
    private $CrxSignature = '';

    /**
     * Construct the scanner.
     */
    public function __construct(\phpMussel\Core\Loader &$Loader)
    {
        /** Link the loader to this instance. */
        $this->Loader = &$Loader;

        /**
         * Writes to the serialized logs upon scan completion.
         *
         * @return bool True on success; False on failure.
         */
        $this->Loader->Events->addHandler('writeToSerialLog', function (): bool {
            /** Guard. */
            if (
                !$this->Loader->Configuration['core']['scan_log_serialized'] ||
                !($File = $this->Loader->buildPath($this->Loader->Configuration['core']['scan_log_serialized']))
            ) {
                return false;
            }

            /** Determine SAPI/origin. */
            if (isset($this->BinaryPath)) {
                $Origin = 'CLI';
            } elseif ($this->Loader->Configuration['legal']['pseudonymise_ip_addresses']) {
                $Origin = $this->Loader->pseudonymiseIP($_SERVER[$this->Loader->Configuration['core']['ipaddr']]);
            } else {
                $Origin = $_SERVER[$this->Loader->Configuration['core']['ipaddr']];
            }

            $ScanData = empty($this->Loader->WhyFlagged) ? $this->Loader->L10N->getString('data_not_available') : trim($this->Loader->WhyFlagged);
            if (!isset($this->Loader->InstanceCache['objects_scanned'])) {
                $this->Loader->InstanceCache['objects_scanned'] = 0;
            }
            if (!isset($this->Loader->InstanceCache['detections_count'])) {
                $this->Loader->InstanceCache['detections_count'] = 0;
            }
            if (!isset($this->Loader->InstanceCache['scan_errors'])) {
                $this->Loader->InstanceCache['scan_errors'] = 1;
            }
            $Data = serialize([
                    'start_time' => $this->Loader->InstanceCache['StartTime'] ?? '-',
                    'end_time' => $this->Loader->InstanceCache['EndTime'] ?? '-',
                    'origin' => $Origin,
                    'objects_scanned' => $this->Loader->InstanceCache['objects_scanned'] ?? 0,
                    'detections_count' => $this->Loader->InstanceCache['detections_count'] ?? 0,
                    'scan_errors' => $this->Loader->InstanceCache['scan_errors'] ?? 0,
                    'detections' => $ScanData
                ]) . "\n";
            $WriteMode = (!file_exists($File) || ($this->Loader->Configuration['core']['truncate'] > 0 &&
                    filesize($File) >= $this->Loader->readBytes($this->Loader->Configuration['core']['truncate']))) ? 'wb' : 'ab';

            $Stream = fopen($File, $WriteMode);
            fwrite($Stream, $Data);
            fclose($Stream);
            $this->Loader->logRotation($this->Loader->Configuration['core']['scan_log_serialized']);
            return true;
        });

        /**
         * Writes to the standard scan log upon scan completion.
         *
         * @param string $Data What to write.
         * @return bool True on success; False on failure.
         */
        $this->Loader->Events->addHandler('writeToScanLog', function (string $Data): bool {
            /** Guard. */
            if (
                !$this->Loader->Configuration['core']['scan_log'] ||
                !($File = $this->Loader->buildPath($this->Loader->Configuration['core']['scan_log']))
            ) {
                return false;
            }

            if (!file_exists($File)) {
                $Data = \phpMussel\Core\Loader::SAFETY . "\n" . $Data;
                $WriteMode = 'wb';
            } else {
                $WriteMode = ($this->Loader->Configuration['core']['truncate'] > 0 &&
                    filesize($File) >= $this->Loader->readBytes($this->Loader->Configuration['core']['truncate'])) ? 'wb' : 'ab';
            }

            $Handle = fopen($File, 'ab');
            fwrite($Handle, $Data);
            fclose($Handle);
            $this->Loader->logRotation($this->Loader->Configuration['core']['scan_log']);
            return true;
        });
    }

    /**
     * The method to call to scan something.
     * @link https://github.com/phpMussel/Docs/blob/master/readme.en.md#SECTION3
     *
     * @param string|array $Files What to scan (can be string indicating a
     *      specific file or directory, or an array of such strings to specify
     *      multiple files and/or directories).
     * @param bool $Format The format to return the scan results as. False
     *      instructs the function to return the results as an integer; True
     *      instructs the function to return the results as human-readable
     *      text. Optional (false by default).
     * @param bool $Flatness Whether arrayed results should be imploded prior
     *      to being returned. Use false to return the array as verbatim; Use
     *      true to return the results imploded as an string. Optional (false
     *      by default).
     * @param int $Depth The recursion depth of the current method call (you
     *      should never set this parameter manually).
     * @param string $OriginalFilename When dealing with uploads, this
     *      parameter is meant to represent the "original filename" of the file
     *      being scanned, as per supplied by the client. In other contexts, it
     *      should generally be the same as $Files.
     * @return mixed The scan results (an array when $Files is an array, as
     *      long as at least one of either $Format or $Flatness is false;
     *      otherwise, an integer or boolean value).
     */
    public function scan($Files, bool $Format = false, bool $Flatness = false, int $Depth = 0, string $OriginalFilename = '')
    {
        /** Fire event: "atStartOf_scan". */
        $this->Loader->Events->fireEvent('atStartOf_scan');

        /** Useful counters for CLI and plugins. */
        $this->Loader->InstanceCache['ThisScanTotal'] = 0;
        $this->Loader->InstanceCache['ThisScanDone'] = 0;
        $this->Loader->Events->fireEvent('countersChanged');

        /** Prepare signature files for the scan process. */
        if (empty($this->Loader->InstanceCache['OrganisedSigFiles'])) {
            $this->organiseSigFiles();
            $this->Loader->InstanceCache['OrganisedSigFiles'] = true;
        }

        /** Initialise statistics if they've been enabled. */
        $this->statsInitialise();

        /** Fall back to $Files if $OriginalFilename wasn't supplied. */
        if (!$OriginalFilename) {
            $OriginalFilename = $Files;
        }

        $this->Loader->InstanceCache['StartTime'] = time() + ($this->Loader->Configuration['core']['time_offset'] * 60);
        $this->Loader->InstanceCache['start_time_2822'] = $this->Loader->timeFormat(
            $this->Loader->InstanceCache['StartTime'],
            $this->Loader->Configuration['core']['time_format']
        );
        $Results = $this->recursor($Files, $Format, $Flatness, $Depth, $OriginalFilename);
        $this->Loader->InstanceCache['EndTime'] = time() + ($this->Loader->Configuration['core']['time_offset'] * 60);
        $this->Loader->InstanceCache['end_time_2822'] = $this->Loader->timeFormat(
            $this->Loader->InstanceCache['EndTime'],
            $this->Loader->Configuration['core']['time_format']
        );

        if ($Format && !is_array($Results)) {
            $Results = sprintf(
                "%s %s%s\n%s%s %s%s\n",
                $this->Loader->InstanceCache['start_time_2822'],
                $this->Loader->L10N->getString('started'),
                $this->Loader->L10N->getString('_fullstop_final'),
                $Results,
                $this->Loader->InstanceCache['end_time_2822'],
                $this->Loader->L10N->getString('finished'),
                $this->Loader->L10N->getString('_fullstop_final')
            );
            $this->Loader->Events->fireEvent('writeToScanLog', $Results);
        }
        if (!isset($this->Loader->InstanceCache['SkipSerial'])) {
            $this->Loader->Events->fireEvent('writeToSerialLog');
        }

        /** Register scan event. */
        $this->statsIncrement($this->CalledFrom === 'Web' ? 'Web-Events' : ($this->CalledFrom === 'CLI' ? 'CLI-Events' : 'API-Events'), 1);

        /** Update statistics. */
        if (!empty($this->Loader->InstanceCache['StatisticsModified'])) {
            $this->Loader->InstanceCache['Statistics'] = $this->Loader->Cache->setEntry(
                'Statistics',
                serialize($this->Loader->InstanceCache['Statistics']),
                0
            );
        }

        /** Exit scan process. */
        return $Results;
    }

    /**
     * Responsible for recursing through any files given to it to be scanned, which
     * may be necessary for the case of archives and directories. It performs the
     * preparations necessary for scanning files using the "data handler" and the
     * "meta data scan" closures. Additionally, it performs some necessary
     * whitelist, blacklist and greylist checks, filesize and file extension checks,
     * and handles the processing and extraction of files from archives, fetching
     * the files contained in archives being scanned in order to process those
     * contained files as so that they, too, may be scanned.
     *
     * When phpMussel is instructed to scan a directory or an array of multiple
     * files, the recursor is the closure function responsible for iterating through
     * that directory and/or array queued for scanning, and if necessary, will
     * recurse itself (such as for when scanning a directory containing
     * sub-directories or when scanning a multidimensional array of multiple files
     * and/or directories).
     *
     * @param string|array $Files In the context of the initial file upload scanning
     *      that phpMussel performs when operating via a server, this parameter (a
     *      string) represents the "temporary filename" of the file being scanned
     *      (the temporary filename, in this context, referring to the name
     *      temporarily assigned to the file by the server upon the file being
     *      uploaded to the temporary uploads location assigned to the server). When
     *      operating in the context of CLI mode, both $Files and $OriginalFilename
     *      represent the scan target, as per specified by the CLI operator; The
     *      only difference between the two is when the scan target is a directory,
     *      rather than a single file; $Files will represent the full path to the
     *      file (so, directory plus filename), whereas $OriginalFilename will
     *      represent only the filename. This parameter can also accept an array of
     *      filenames.
     * @param bool $n This optional parameter is a boolean (defaults to false, but
     *      set to true during the initial scan of file uploads), indicating the
     *      format for returning the scan results. False instructs the function to
     *      return results as an integer; True instructs the function to return
     *      results as human readable text (refer to Section 3A of the README
     *      documentation, "HOW TO USE (FOR WEB SERVERS)", for more information).
     * @param bool $Flatness This optional parameter is a boolean (defaults to
     *      false, but set to true during the initial scan of file uploads),
     *      indicating to the function whether or not arrayed results should be
     *      imploded prior to being returned to the calling function. False
     *      instructs the function to return the arrayed results as verbatim; True
     *      instructs the function to return the arrayed results as an imploded
     *      string.
     * @param int $Depth Represents the current depth of recursion from which the
     *      function has been called. This information is used for determining how
     *      far to indent any entries generated for logging and for the display of
     *      scan results in CLI (you should never manually set this parameter
     *      yourself).
     * @param string $OriginalFilename For the file upload scanning that phpMussel
     *      normally performs by default, this parameter represents the "original
     *      filename" of the file being scanned (the original filename, in this
     *      context, referring to the name supplied by the upload client, as
     *      opposed to the temporary filename assigned by the server or anything
     *      else). When operating in the context of CLI mode, both $Files and
     *      $OriginalFilename represent the scan target, as per specified by the CLI
     *      operator; The only difference between the two is when the scan target is
     *      a directory, rather than a single file; $Files will represent the full
     *      path to the file (so, directory plus filename), whereas
     *      $OriginalFilename will represent only the filename.
     * @return mixed The scan results, returned as an array when the $Files
     *      parameter is an array and when $n and/or $Flatness is/are false, and
     *      otherwise returned as per described by the README documentation. The
     *      function may also die the script and return nothing, if something goes
     *      wrong, such as if the function is triggered in the absence of the
     *      required $this->Loader->InstanceCache variable being set.
     */
    public function recursor($Files = '', bool $n = false, bool $Flatness = false, int $Depth = 0, string $OriginalFilename = '')
    {
        /** Fire event: "atStartOf_recursor". */
        $this->Loader->Events->fireEvent('atStartOf_recursor');

        /** Prepare signature files for the scan process. */
        if (empty($this->Loader->InstanceCache['OrganisedSigFiles'])) {
            $this->organiseSigFiles();
            $this->Loader->InstanceCache['OrganisedSigFiles'] = true;
        }

        if ($this->CalledFrom !== 'Web') {
            $this->Loader->WhyFlagged = $this->Loader->HashReference = $this->Loader->PEData = '';
            if ($Depth === 0 || !isset($this->Loader->InstanceCache['objects_scanned'],
                    $this->Loader->InstanceCache['detections_count'],
                    $this->Loader->InstanceCache['scan_errors'])) {
                $this->Loader->InstanceCache['objects_scanned'] = 0;
                $this->Loader->InstanceCache['detections_count'] = 0;
                $this->Loader->InstanceCache['scan_errors'] = 0;
            }
        } else {
            if (!isset($this->Loader->HashReference)) {
                $this->Loader->HashReference = '';
            }
            if (!isset($this->Loader->WhyFlagged)) {
                $this->Loader->WhyFlagged = '';
            }
            if (!isset($this->Loader->PEData)) {
                $this->Loader->PEData = '';
            }
            if (!isset($this->Loader->InstanceCache['objects_scanned'],
                $this->Loader->InstanceCache['detections_count'],
                $this->Loader->InstanceCache['scan_errors'])) {
                $this->Loader->InstanceCache['objects_scanned'] = 0;
                $this->Loader->InstanceCache['detections_count'] = 0;
                $this->Loader->InstanceCache['scan_errors'] = 0;
            }
        }

        /** Increment scan depth. */
        $Depth++;

        /** Controls indenting relating to scan depth for normal logging and for CLI-mode scanning. */
        $lnap = str_pad('> ', ($Depth + 1), '-', STR_PAD_LEFT);

        /**
         * If the scan target is an array, iterate through the array and recurse
         * the recursor with each array element.
         */
        if (is_array($Files)) {
            $SizeOfDir = count($Files);
            if ($this->Loader->InstanceCache['ThisScanTotal'] === 0) {
                $this->Loader->InstanceCache['ThisScanTotal'] = $SizeOfDir;
            } else {
                $this->Loader->InstanceCache['ThisScanTotal'] += $SizeOfDir - 1;
            }
            $this->Loader->Events->fireEvent('countersChanged');
            foreach ($Files as &$Current) {
                $Current = $this->recursor($Current, $n, false, $Depth, $Current);
            }
            return ($n && $Flatness) ? $this->implodeMd($Files) : $Files;
        }

        $OriginalFilename = $this->prescanDecode($OriginalFilename);
        $OriginalFilenameSafe = urlencode($OriginalFilename);

        /**
         * If the scan target is a directory, iterate through the directory
         * contents and recurse the recursor with these contents.
         */
        if (is_dir($Files)) {
            if (!is_readable($Files)) {
                $this->Loader->InstanceCache['scan_errors']++;
                return !$n ? 0 : [
                    'flagged' => false,
                    'file' => $OriginalFilename,
                    'reason' => sprintf($this->Loader->L10N->getString('failed_to_access'), $OriginalFilename),
                ];
            }
            $Dir = $this->directoryRecursiveList($Files);
            $SizeOfDir = count($Dir);
            if ($this->Loader->InstanceCache['ThisScanTotal'] === 0) {
                $this->Loader->InstanceCache['ThisScanTotal'] = $SizeOfDir;
            } else {
                $this->Loader->InstanceCache['ThisScanTotal'] += $SizeOfDir - 1;
            }
            $this->Loader->Events->fireEvent('countersChanged');
            foreach ($Dir as &$Sub) {
                $Sub = $this->recursor($Files . DIRECTORY_SEPARATOR . $Sub, $n, false, $Depth, $Sub);
            }
            return ($n && $Flatness) ? $this->implodeMd($Dir) : $Dir;
        }

        /** Increment counter. */
        if ($this->Loader->InstanceCache['ThisScanTotal'] === 0) {
            $this->Loader->InstanceCache['ThisScanTotal'] = 1;
            $this->Loader->Events->fireEvent('countersChanged');
        }

        /** Define file phase. */
        $this->Loader->InstanceCache['phase'] = 'file';

        /** Indicates whether the scan target is a part of a container. */
        $this->Loader->InstanceCache['container'] = 'none';

        /** Indicates whether the scan target is an OLE object. */
        $this->Loader->InstanceCache['file_is_ole'] = false;

        /** Fetch the greylist if it hasn't already been fetched. */
        if (!isset($this->Loader->InstanceCache['Greylist'])) {
            if (!is_readable($this->Loader->GreylistPath)) {
                $this->Loader->InstanceCache['Greylist'] = ',';
                if (is_writable($this->Loader->GreylistPath)) {
                    $Handle = fopen($this->Loader->GreylistPath, 'wb');
                    fwrite($Handle, ',');
                    fclose($Handle);
                }
            } else {
                $this->Loader->InstanceCache['Greylist'] = $this->Loader->readFile($this->Loader->GreylistPath);
            }
        }

        /** Fire event: "before_scan". */
        $this->Loader->Events->fireEvent('before_scan');

        $fnCRC = hash('crc32b', $OriginalFilename);

        /** Kill it here if the scan target isn't a valid file. */
        if (!$Files || !$d = is_file($Files)) {
            $this->Loader->InstanceCache['ThisScanDone']++;
            $this->Loader->Events->fireEvent('countersChanged');
            return !$n ? 0 :
                [
                    'flagged' => false,
                    'file' => $OriginalFilename,
                    'reason' => $this->Loader->L10N->getString('invalid_file'),
                ];

        }

        $fS = filesize($Files);
        if ($this->Loader->Configuration['files']['filesize_limit'] > 0) {
            if ($fS > $this->Loader->readBytes($this->Loader->Configuration['files']['filesize_limit'])) {
                if (!$this->Loader->Configuration['files']['filesize_response']) {
                    $this->Loader->InstanceCache['ThisScanDone']++;
                    $this->Loader->Events->fireEvent('countersChanged');
                    return !$n ? 1 :
                        [
                            'flagged' => false,
                            'file' => $OriginalFilename,
                            'reason' => $this->Loader->L10N->getString('ok') . ' (' . $this->Loader->L10N->getString('filesize_limit_exceeded') . ")"
                        ];
                }
                $this->Loader->HashReference .= str_repeat('-', 64) . ':' . $fS . ':' . $OriginalFilename . "\n";
                $this->Loader->WhyFlagged .= sprintf(
                    $this->Loader->L10N->getString('_exclamation'),
                    $this->Loader->L10N->getString('filesize_limit_exceeded') . ' (' . $OriginalFilenameSafe . ')'
                );
                if ($this->Loader->Configuration['core']['delete_on_sight'] && is_readable($Files)) {
                    unlink($Files);
                }
                $this->Loader->InstanceCache['ThisScanDone']++;
                $this->Loader->Events->fireEvent('countersChanged');
                return !$n ? 2 :
                    [
                        'flagged' => false,
                        'file' => $OriginalFilename,
                        'reason' => $this->Loader->L10N->getString('filesize_limit_exceeded')
                    ];

            }
        }
        if (!$this->Loader->Configuration['files']['allow_leading_trailing_dots'] && (substr($OriginalFilename, 0, 1) === '.' || substr($OriginalFilename, -1) === '.')) {
            $this->Loader->HashReference .= str_repeat('-', 64) . ':' . $fS . ':' . $OriginalFilename . "\n";
            $this->Loader->WhyFlagged .= sprintf(
                $this->Loader->L10N->getString('_exclamation'),
                $this->Loader->L10N->getString('scan_filename_manipulation_detected') . ' (' . $OriginalFilenameSafe . ')'
            );
            if ($this->Loader->Configuration['core']['delete_on_sight'] && is_readable($Files)) {
                unlink($Files);
            }
            $this->Loader->InstanceCache['ThisScanDone']++;
            $this->Loader->Events->fireEvent('countersChanged');
            return !$n ? 2 :
                [
                    'flagged' => false,
                    'file' => $OriginalFilename,
                    'reason' => sprintf(
                        $this->Loader->L10N->getString('_exclamation_final'),
                        $this->Loader->L10N->getString('scan_filename_manipulation_detected')
                    )
                ];

        }

        /** Get file extensions. */
        [$xt, $xts, $gzxt, $gzxts] = $this->fetchExtension($OriginalFilename);

        /** Process filetype whitelisting. */
        if ($this->containsMustAssert([
            $this->Loader->Configuration['files']['filetype_whitelist']
        ], [$xt, $xts, $gzxt, $gzxts], ',', true, true)) {
            $this->Loader->InstanceCache['ThisScanDone']++;
            $this->Loader->Events->fireEvent('countersChanged');
            return !$n ? 1 : [
                'flagged' => false,
                'file' => $OriginalFilename,
                'reason' => $this->Loader->L10N->getString('scan_no_problems_found')
            ];

        }

        /** Process filetype blacklisting. */
        if ($this->containsMustAssert([
            $this->Loader->Configuration['files']['filetype_blacklist']
        ], [$xt, $xts, $gzxt, $gzxts], ',', true, true)) {
            $this->Loader->HashReference .= str_repeat('-', 64) . ':' . $fS . ':' . $OriginalFilename . "\n";
            $this->Loader->WhyFlagged .= sprintf(
                $this->Loader->L10N->getString('_exclamation'),
                $this->Loader->L10N->getString('filetype_blacklisted') . ' (' . $OriginalFilenameSafe . ')'
            );
            if ($this->Loader->Configuration['core']['delete_on_sight'] && is_readable($Files)) {
                unlink($Files);
            }
            $this->Loader->InstanceCache['ThisScanDone']++;
            $this->Loader->Events->fireEvent('countersChanged');
            return !$n ? 2 :
                [
                    'flagged' => false,
                    'file' => $OriginalFilename,
                    'reason' => $this->Loader->L10N->getString('filetype_blacklisted') .
                        $this->Loader->L10N->getString('_fullstop_final')
                ];

        }

        /** Process filetype greylisting (when relevant). */
        if (!empty($this->Loader->Configuration['files']['filetype_greylist']) && $this->containsMustAssert([
                $this->Loader->Configuration['files']['filetype_greylist']
            ], [$xt, $xts, $gzxt, $gzxts])) {
            $this->Loader->HashReference .= str_repeat('-', 64) . ':' . $fS . ':' . $OriginalFilename . "\n";
            $this->Loader->WhyFlagged .= sprintf(
                $this->Loader->L10N->getString('_exclamation'),
                $this->Loader->L10N->getString('filetype_blacklisted') . ' (' . $OriginalFilenameSafe . ')'
            );
            if ($this->Loader->Configuration['core']['delete_on_sight'] && is_readable($Files)) {
                unlink($Files);
            }
            $this->Loader->InstanceCache['ThisScanDone']++;
            $this->Loader->Events->fireEvent('countersChanged');
            return !$n ? 2 : [
                'flagged' => false,
                'file' => $OriginalFilename,
                'reason' => $this->Loader->L10N->getString('filetype_blacklisted') .
                    $this->Loader->L10N->getString('_fullstop_final')
            ];

        }

        /** Read in the file to be scanned. */
        $in = $this->Loader->readFileBlocks($Files, ($this->Loader->Configuration['files']['scannable_threshold'] > 0 &&
            $fS > $this->Loader->readBytes($this->Loader->Configuration['files']['scannable_threshold'])) ? $this->Loader->readBytes($this->Loader->Configuration['files']['scannable_threshold']) : $fS, true);

        /** Generate CRC for the file to be scanned. */
        $fdCRC = hash('crc32b', $in);

        /** Check for non-image items. */
        if (!empty($in) && $this->Loader->Configuration['files']['only_allow_images'] && !$this->imageIndicators($xt, bin2hex(substr($in, 0, 16)))) {
            $this->Loader->HashReference .= hash('sha256', $in) . ':' . $fS . ':' . $OriginalFilename . "\n";
            $this->Loader->WhyFlagged .= sprintf(
                $this->Loader->L10N->getString('_exclamation'),
                $this->Loader->L10N->getString('only_allow_images') . ' (' . $OriginalFilenameSafe . ')'
            );
            if ($this->Loader->Configuration['core']['delete_on_sight'] && is_readable($Files)) {
                unlink($Files);
            }
            $this->Loader->InstanceCache['ThisScanDone']++;
            $this->Loader->Events->fireEvent('countersChanged');
            return !$n ? 2 :
                [
                    'flagged' => false,
                    'file' => $OriginalFilename,
                    'reason' => $this->Loader->L10N->getString('only_allow_images') .
                        $this->Loader->L10N->getString('_fullstop_final')
                ];

        }

        /** Increment objects scanned count. */
        $this->Loader->InstanceCache['objects_scanned']++;

        /** Send the scan target to the data handler. */
        $z = $this->dataHandler($in, $Depth, $OriginalFilename);

        /**
         * Check whether the file is compressed. If it's compressed, attempt to
         * decompress it, and then scan the decompressed version of the file. We'll
         * only bother doing this if the file hasn't already been flagged though.
         */
        if ($z[0] === 1) {

            /** Create a new compression object. */
            $CompressionObject = new CompressionHandler($in);

            /** Now we'll try to decompress the file. */
            if (!$CompressionResults = $CompressionObject->TryEverything()) {

                /** Success! Now we'll send it to the data handler. */
                $z = $this->dataHandler($CompressionObject->Data, $Depth, $this->dropTrailingCompressionExtension($OriginalFilename));

                /**
                 * Replace originally scanned data with decompressed data in case
                 * needed by the archive handler.
                 */
                $in = $CompressionObject->Data;
            }

            /** Cleanup. */
            unset($CompressionResults, $CompressionObject);
        }

        /** Executed if there were any problems or if anything was detected. */
        if ($z[0] !== 1) {

            /** Quarantine if necessary. */
            if ($z[0] === 2) {
                if (
                    $this->Loader->Configuration['quarantine']['quarantine_key'] &&
                    strlen($in) < $this->Loader->readBytes($this->Loader->Configuration['quarantine']['quarantine_max_filesize'])
                ) {
                    /** Note: "qfu" = "Quarantined File Upload". */
                    $qfu = $this->Loader->Time . '-' . hash('md5', $this->Loader->Configuration['quarantine']['quarantine_key'] . $fdCRC . $this->Loader->Time);
                    $this->quarantine(
                        $in,
                        $this->Loader->Configuration['quarantine']['quarantine_key'],
                        $_SERVER[$this->Loader->Configuration['core']['ipaddr']],
                        $qfu
                    );
                    $this->Loader->HashReference .= sprintf($this->Loader->L10N->getString('quarantined_as'), $qfu) . "\n";
                }
            }

            /** Delete if necessary. */
            if ($this->Loader->Configuration['core']['delete_on_sight'] && is_readable($Files)) {
                unlink($Files);
            }

            /** Exit. */
            $this->Loader->InstanceCache['ThisScanDone']++;
            $this->Loader->Events->fireEvent('countersChanged');
            return !$n ? $z[0] :
                [
                    'flagged' => false,
                    'file' => $OriginalFilename,
                    'reason' => $z[1]
                ];
//            sprintf(
//                '%s%s \'%s\' (FN: %s; FD: %s):%s%s',
//                $lnap,
//                $this->Loader->L10N->getString('scan_checking'),
//                $OriginalFilename,
//                $fnCRC,
//                $fdCRC,
//                "\n",
//                $z[1]
//            );
        }

        $x = sprintf(
            '%1$s%2$s \'%3$s\' (FN: %4$s; FD: %5$s):%6$s-%1$s%7$s%6$s',
            $lnap,
            $this->Loader->L10N->getString('scan_checking'),
            $OriginalFilename,
            $fnCRC,
            $fdCRC,
            "\n",
            $this->Loader->L10N->getString('scan_no_problems_found')
        );

        /** Results. */
        $Results = 1;

        /**
         * Begin archive phase.
         * Note: Archive phase will only occur when "check_archives" is enabled and
         * when no problems were detected with the scan target by this point.
         */
        if (
            $this->Loader->Configuration['files']['check_archives'] &&
            !empty($in) &&
            $this->Loader->Configuration['files']['max_recursion'] > 1
        ) {
            /** Define archive phase. */
            $this->Loader->InstanceCache['phase'] = 'archive';

            /** In case there's any temporary files we need to delete afterwards. */
            $this->Loader->InstanceCache['tempfilesToDelete'] = [];

            /** Begin processing archives. */
            $this->archiveRecursor($x, $Results, $in, (isset($CompressionResults) && !$CompressionResults) ? '' : $Files, 0, urlencode($OriginalFilename));

            /** Begin deleting any temporary files that snuck through. */
            foreach ($this->Loader->InstanceCache['tempfilesToDelete'] as $DeleteThis) {
                if (file_exists($DeleteThis)) {
                    unlink($DeleteThis);
                }
            }

            /** Add hash cache entry here if necessary (e.g., because of encryption). */
            if (
                $Results === -4 &&
                $this->Loader->Configuration['core']['scan_cache_expiry'] > 0 &&
                ($HashCacheID = hash('sha256', $in) . hash('sha256', $OriginalFilename))
            ) {
                /** 0: (int) {-4...2}; 1: For CLI+API; 2: For Web. */
                $HashCacheEntry = json_encode([$Results, $x, $this->Loader->WhyFlagged]);
                $this->Loader->Cache->setEntry($HashCacheID, $HashCacheEntry, $this->Loader->Configuration['core']['scan_cache_expiry']);
            }
        }

        /** Quarantine if necessary. */
        if ($Results === 2) {
            if (
                $this->Loader->Configuration['quarantine']['quarantine_key'] &&
                strlen($in) < $this->Loader->readBytes($this->Loader->Configuration['quarantine']['quarantine_max_filesize'])
            ) {
                /** Note: "qfu" = "Quarantined File Upload". */
                $qfu = $this->Loader->Time . '-' . hash('md5', $this->Loader->Configuration['quarantine']['quarantine_key'] . $fdCRC . $this->Loader->Time);
                $this->quarantine(
                    $in,
                    $this->Loader->Configuration['quarantine']['quarantine_key'],
                    $_SERVER[$this->Loader->Configuration['core']['ipaddr']],
                    $qfu
                );
                $this->Loader->HashReference .= sprintf($this->Loader->L10N->getString('quarantined_as'), $qfu);
            }
        }

        /** Delete if necessary. */
        if ($Results !== 1 && $this->Loader->Configuration['core']['delete_on_sight'] && is_readable($Files)) {
            unlink($Files);
        }

        /** Exit. */
        $this->Loader->InstanceCache['ThisScanDone']++;
        $this->Loader->Events->fireEvent('countersChanged');
        return !$n ? $Results : [
            'flagged' => false,
            'file' => $OriginalFilename,
            'reason' => $x
        ];
    }

    /**
     * Responsible for handling any data fed to it from the recursor. It shouldn't
     * be called manually nor from any other contexts. It takes the data given to
     * it from the recursor and checks that data against the various signatures of
     * phpMussel, before returning the results of those checks back to the
     * recursor.
     *
     * @param string $str Raw binary data to be checked, supplied by the parent
     *      closure (generally, the contents of the files to be scanned).
     * @param int $Depth Represents the current depth of recursion from which the
     *      closure has been called, used for determining how far to indent any
     *      entries generated for logging and for the display of scan results in
     *      CLI.
     * @param string $OriginalFilename Represents the "original filename" of the file being
     *      scanned (in this context, referring to the name supplied by the upload
     *      client or CLI operator, as opposed to the temporary filename assigned
     *      by the server or anything else).
     * @return array|bool Returns an array containing the results of the scan as
     *      both an integer (the first element) and as human-readable text (the
     *      second element), or returns false if any problems occur preventing the
     *      data handler from completing its normal process.
     */
    public function dataHandler(string $str = '', int $Depth = 0, string $OriginalFilename = '')
    {
        /** Fire event: "atStartOf_dataHandler". */
        $this->Loader->Events->fireEvent('atStartOf_dataHandler');

        /** Identifies whether the scan target has been flagged for any reason yet. */
        $Flagged = false;

        /** Increment scan depth. */
        $Depth++;

        /** Controls indenting relating to scan depth for normal logging and for CLI-mode scanning. */
        $lnap = str_pad('> ', ($Depth + 1), '-', STR_PAD_LEFT);

        /** Output variable (for when the output is a string). */
        $Out = '';

        /** There's no point bothering to scan zero-byte files. */
        if (!$StringLength = strlen($str)) {
            return [1, ''];
        }

        /** Generate hash variables. */
        foreach (['md5', 'sha1', 'sha256', 'crc32b'] as $Algo) {
            $$Algo = hash($Algo, $str);
        }

        /** $fourcc: First four bytes of the scan target in hexadecimal notation. */
        $fourcc = strtolower(bin2hex(substr($str, 0, 4)));

        /** $twocc: First two bytes of the scan target in hexadecimal notation. */
        $twocc = substr($fourcc, 0, 4);

        /**
         * $CoExMeta: Contains metadata pertaining to the scan target, intended to
         * be used by the "complex extended" signatures.
         */
        $CoExMeta = '';
        foreach (['OriginalFilename', 'Depth', 'StringLength', 'md5', 'sha1', 'sha256', 'crc32b', 'fourcc', 'twocc'] as $AppendToCoExMeta) {
            if (!empty($$$AppendToCoExMeta)) {
                $CoExMeta .= '$' . $AppendToCoExMeta . ':' . $$AppendToCoExMeta . ';';
            }
        }
        unset($AppendToCoExMeta);

        /** Indicates whether a signature is considered a "weighted" signature. */
        $this->Loader->InstanceCache['weighted'] = false;

        /** Variables used for weighted signatures and for heuristic analysis. */
        $heur = ['detections' => 0, 'weight' => 0, 'cli' => '', 'web' => ''];

        /** Scan target has no name? That's a little suspicious. */
        if (!$OriginalFilename) {
            $this->Loader->HashReference .= $sha256 . ':' . $StringLength . ":\n";
            $this->Loader->InstanceCache['detections_count']++;
            $Out .= $lnap . sprintf(
                    $this->Loader->L10N->getString('_exclamation_final'),
                    $this->Loader->L10N->getString('scan_missing_filename')
                ) . "\n";
            $this->Loader->WhyFlagged .= sprintf(
                $this->Loader->L10N->getString('_exclamation'),
                $this->Loader->L10N->getString('scan_missing_filename')
            );
            return [2, $Out];
        }

        /** URL-encoded version of the scan target name. */
        $OriginalFilenameSafe = urlencode($OriginalFilename);

        /**
         * Check whether the file being scanned has already been recently
         * scanned before, to reduce needless work.
         */
        if (
            $this->Loader->Configuration['core']['scan_cache_expiry'] > 0 &&
            ($HashCacheID = $sha256 . hash('sha256', $OriginalFilename)) &&
            ($HashCacheEntry = $this->Loader->Cache->getEntry($HashCacheID)) &&
            preg_match('~^\[\-?\d,".*",".*"\]$~', $HashCacheEntry)
        ) {
            /** 0: (int) {-4...2}; 1: For CLI+API; 2: For Web. */
            if (($HashCacheEntry = json_decode($HashCacheEntry, true, 2)) === false) {
                $HashCacheEntry = [
                    -2, $lnap . sprintf(
                        $this->Loader->L10N->getString('_exclamation_final'),
                        $this->Loader->L10N->getString('corrupted')
                    ) . "\n",
                    sprintf(
                        $this->Loader->L10N->getString('_exclamation'),
                        $this->Loader->L10N->getString('corrupted') . ' (' . $OriginalFilenameSafe . ')'
                    )
                ];
            }

            /** Add to hash references if something was detected. */
            if ($HashCacheEntry[0] !== 1) {
                $this->Loader->HashReference .= $sha256 . ':' . $StringLength . ':' . $OriginalFilename . "\n";
                $this->Loader->InstanceCache['detections_count']++;
                $this->Loader->WhyFlagged .= $HashCacheEntry[2];
            }

            /** Set debug values, if this has been enabled. */
            if (isset($this->debugArr)) {
                $this->Loader->InstanceCache['DebugArrKey'] = count($this->debugArr);
                $this->debugArr[$this->Loader->InstanceCache['DebugArrKey']] = [
                    'Filename' => $OriginalFilename,
                    'FromCache' => true,
                    'Depth' => $Depth,
                    'Size' => $StringLength,
                    'MD5' => $md5,
                    'SHA1' => $sha1,
                    'SHA256' => $sha256,
                    'CRC32B' => $crc32b,
                    '2CC' => $twocc,
                    '4CC' => $fourcc,
                    'ScanPhase' => $this->Loader->InstanceCache['phase'],
                    'Container' => $this->Loader->InstanceCache['container'],
                    'Results' => $HashCacheEntry[0],
                    'Output' => $ForHumans
                ];
            }

            /** Register object flagged. */
            if ($HashCacheEntry[0] !== 1) {
                $this->statsIncrement($this->CalledFrom === 'Web' ? 'Web-Blocked' : ($this->CalledFrom === 'CLI' ? 'CLI-Flagged' : 'API-Flagged'), 1);
            }

            /** Exit data handler. */
            return [$HashCacheEntry[0], $HashCacheEntry[1]];
        }

        /** Register object scanned. */
        if ($this->CalledFrom === 'CLI') {
            $this->statsIncrement('CLI-Scanned', 1);
        } elseif ($this->CalledFrom === 'Web') {
            $this->statsIncrement('Web-Scanned', 1);
        } else {
            $this->statsIncrement('API-Scanned', 1);
        }

        /** Indicates whether we're in CLI-mode. */
        $climode = isset($this->BinaryPath) ? 1 : 0;

        if (
            $this->Loader->Configuration['files']['scannable_threshold'] > 0 &&
            $StringLength > $this->Loader->readBytes($this->Loader->Configuration['files']['scannable_threshold'])
        ) {
            $StringLength = $this->Loader->readBytes($this->Loader->Configuration['files']['scannable_threshold']);
            $str = substr($str, 0, $StringLength);
            $str_cut = 1;
        } else {
            $str_cut = 0;
        }

        /** Indicates whether we need to decode the contents of the scan target. */
        $decode_or_not = (($this->Loader->Configuration['files']['decode_threshold'] > 0 &&
                $StringLength > $this->Loader->readBytes($this->Loader->Configuration['files']['decode_threshold'])) || $StringLength < 16) ? 0 : 1;

        /** These are sometimes used by the "CoEx" ("complex extended") signatures. */
        $len_kb = ($StringLength > 1024) ? 1 : 0;
        $len_hmb = ($StringLength > 524288) ? 1 : 0;
        $len_mb = ($StringLength > 1048576) ? 1 : 0;
        $len_hgb = ($StringLength > 536870912) ? 1 : 0;
        $phase = $this->Loader->InstanceCache['phase'];
        $container = $this->Loader->InstanceCache['container'];
        $pdf_magic = ($fourcc === '25504446');

        /** CoEx flags for configuration directives related to signatures. */
        foreach ([
                     'detect_adware',
                     'detect_joke_hoax',
                     'detect_pua_pup',
                     'detect_packer_packed',
                     'detect_shell',
                     'detect_deface',
                     'detect_encryption'
                 ] as $Flag) {
            $$Flag = $this->Loader->Configuration['signatures'][$Flag] ? 1 : 0;
        }

        /** Cleanup. */
        unset($Flag);

        /** Get file extensions. */
        [$xt, $xts, $gzxt, $gzxts] = $this->fetchExtension($OriginalFilename);

        $CoExMeta .= '$xt:' . $xt . ';$xts:' . $xts . ';';

        /** Input ($str) as hexadecimal data. */
        $str_hex = bin2hex($str);
        $str_hex_len = $StringLength * 2;

        /** Input ($str) normalised. */
        $str_norm = $this->normalise($str, false, $decode_or_not);
        $str_norm_len = strlen($str_norm);

        /** Normalised input ($str_norm) as hexadecimal data. */
        $str_hex_norm = bin2hex($str_norm);
        $str_hex_norm_len = $str_norm_len * 2;

        /** Input ($str) normalised for HTML. */
        $str_html = $this->normalise($str, true, $decode_or_not);
        $str_html_len = strlen($str_html);

        /** HTML normalised input ($str_html) as hexadecimal data. */
        $str_hex_html = bin2hex($str_html);
        $str_hex_html_len = $str_html_len * 2;

        /** Look for potential Linux/ELF indicators. */
        $is_elf = ($fourcc === '7f454c46' || $xt === 'elf');

        /** Look for potential graphics/image indicators. */
        $is_graphics = empty($str) ? false : $this->imageIndicators($xt, substr($str_hex, 0, 32));

        /** Look for potential HTML indicators. */
        $is_html = (strpos(
                ',asp*,dht*,eml*,hta*,htm*,jsp*,php*,sht*,',
                ',' . $xts . ','
            ) !== false || preg_match(
                '/3c(?:21646f6374797065|6(?:120|26f6479|8656164|8746d6c|96672616d65|96d67|f626a656374)|7(?:36372697074|461626c65|469746c65))/i',
                $str_hex_norm
            ) || preg_match(
                '/(?:6(?:26f6479|8656164|8746d6c)|7(?:36372697074|461626c65|469746c65))3e/i',
                $str_hex_norm
            ));

        /** Look for potential email indicators. */
        $is_email = (strpos(
                ',htm*,ema*,eml*,',
                ',' . $xts . ','
            ) !== false || preg_match(
                '/0a(?:4(?:36f6e74656e742d54797065|4617465|6726f6d|d6573736167652d4944|d4' .
                '94d452d56657273696f6e)|5(?:265706c792d546f|2657475726e2d50617468|3656e64' .
                '6572|375626a656374|46f|82d4d61696c6572))3a20/i',
                $str_hex
            ) || preg_match('/0a2d2d.{32}(?:2d2d)?(?:0d)?0a/i', $str_hex));

        /** Look for potential Mach-O indicators. */
        $is_macho = preg_match('/^(?:cafe(?:babe|d00d)|c[ef]faedfe|feedfac[ef])$/', $fourcc);

        /** Look for potential PDF indicators. */
        $is_pdf = ($pdf_magic || $xt === 'pdf');

        /** Look for potential Shockwave/SWF indicators. */
        $is_swf = (strpos(',435753,465753,5a5753,', ',' . substr($str_hex, 0, 6) . ',') !== false ||
            strpos(',swf,swt,', ',' . $xt . ',') !== false);

        /** "Infectable"? Used by ClamAV General and ClamAV ASCII signatures. */
        $infectable = true;

        /** "Asciiable"? Used by all ASCII signatures. */
        $asciiable = (bool)$str_hex_norm_len;

        /** Used to identify whether to check against OLE signatures. */
        $is_ole = !empty($this->Loader->InstanceCache['file_is_ole']) && (!empty($this->Loader->InstanceCache['file_is_macro']) ||
                strpos(',bin,ole,xml,rels,', ',' . $xt . ',') !== false);

        /** Worked by the switch file. */
        $fileswitch = 'unassigned';
        if (!isset($this->Loader->InstanceCache['switch.dat'])) {
            $this->Loader->InstanceCache['switch.dat'] = $this->Loader->readFileAsArray($this->AssetsPath . 'switch.dat', FILE_IGNORE_NEW_LINES);
        }
        foreach ($this->Loader->InstanceCache['switch.dat'] as $ThisRule) {
            $Switch = (strpos($ThisRule, ';') === false) ? $ThisRule : $this->Loader->substrAfterLast($ThisRule, ';');
            if (strpos($Switch, '=') === false) {
                continue;
            }
            $Switch = explode('=', preg_replace('/[^\x20-\xff]/', '', $Switch));
            if (empty($Switch[0])) {
                continue;
            }
            if (empty($Switch[1])) {
                $Switch[1] = false;
            }
            $theSwitch = $Switch[0];
            $ThisRule = (strpos($ThisRule, ';') === false) ? [$ThisRule] : explode(';', $this->Loader->substrBeforeLast($ThisRule, ';'));
            foreach ($ThisRule as $Fragment) {
                $Fragment = (strpos($Fragment, ':') === false) ? false : $this->splitSigParts($Fragment, 7);
                if (empty($Fragment[0])) {
                    continue 2;
                }
                if ($Fragment[0] === 'LV') {
                    if (!isset($Fragment[1]) || substr($Fragment[1], 0, 1) !== '$') {
                        continue 2;
                    }
                    $lv_haystack = substr($Fragment[1], 1);
                    if (!isset($$lv_haystack) || is_array($$lv_haystack)) {
                        continue 2;
                    }
                    $lv_haystack = $$lv_haystack;
                    if ($climode) {
                        $lv_haystack = $this->Loader->substrAfterLast($this->Loader->substrAfterLast($lv_haystack, '/'), "\\");
                    }
                    $lv_needle = $Fragment[2] ?? '';
                    $pos_A = $Fragment[3] ?? 0;
                    $pos_Z = $Fragment[4] ?? 0;
                    $lv_min = $Fragment[5] ?? 0;
                    $lv_max = $Fragment[6] ?? -1;
                    if (!$this->lvMatch($lv_needle, $lv_haystack, $pos_A, $pos_Z, $lv_min, $lv_max)) {
                        continue 2;
                    }
                } elseif (isset($Fragment[2])) {
                    if (isset($Fragment[3])) {
                        if ($Fragment[2] === 'A') {
                            if (
                                strpos(',FD,FD-RX,FD-NORM,FD-NORM-RX,', ',' . $Fragment[0] . ',') === false || ($Fragment[0] === 'FD' &&
                                    strpos("\x01" . substr($str_hex, 0, $Fragment[3] * 2), "\x01" . $Fragment[1]) === false) || ($Fragment[0] === 'FD-RX' &&
                                    !preg_match('/\A(?:' . $Fragment[1] . ')/i', substr($str_hex, 0, $Fragment[3] * 2))) || ($Fragment[0] === 'FD-NORM' &&
                                    strpos("\x01" . substr($str_hex_norm, 0, $Fragment[3] * 2), "\x01" . $Fragment[1]) === false) || ($Fragment[0] === 'FD-NORM-RX' &&
                                    !preg_match('/\A(?:' . $Fragment[1] . ')/i', substr($str_hex_norm, 0, $Fragment[3] * 2)))
                            ) {
                                continue 2;
                            }
                        } elseif (
                            strpos(',FD,FD-RX,FD-NORM,FD-NORM-RX,', ',' . $Fragment[0] . ',') === false || ($Fragment[0] === 'FD' &&
                                strpos(substr($str_hex, $Fragment[2] * 2, $Fragment[3] * 2), $Fragment[1]) === false) || ($Fragment[0] === 'FD-RX' &&
                                !preg_match('/(?:' . $Fragment[1] . ')/i', substr($str_hex, $Fragment[2] * 2, $Fragment[3] * 2))) || ($Fragment[0] === 'FD-NORM' &&
                                strpos(substr($str_hex_norm, $Fragment[2] * 2, $Fragment[3] * 2), $Fragment[1]) === false) || ($Fragment[0] === 'FD-NORM-RX' &&
                                !preg_match('/(?:' . $Fragment[1] . ')/i', substr($str_hex_norm, $Fragment[2] * 2, $Fragment[3] * 2)))
                        ) {
                            continue 2;
                        }
                    } else {
                        if ($Fragment[2] === 'A') {
                            if (
                                strpos(',FN,FD,FD-RX,FD-NORM,FD-NORM-RX,', ',' . $Fragment[0] . ',') === false || ($Fragment[0] === 'FN' &&
                                    !preg_match('/\A(?:' . $Fragment[1] . ')/i', $OriginalFilename)) || ($Fragment[0] === 'FD' &&
                                    strpos("\x01" . $str_hex, "\x01" . $Fragment[1]) === false) || ($Fragment[0] === 'FD-RX' &&
                                    !preg_match('/\A(?:' . $Fragment[1] . ')/i', $str_hex)) || ($Fragment[0] === 'FD-NORM' &&
                                    strpos("\x01" . $str_hex_norm, "\x01" . $Fragment[1]) === false) || ($Fragment[0] === 'FD-NORM-RX' &&
                                    !preg_match('/\A(?:' . $Fragment[1] . ')/i', $str_hex_norm))
                            ) {
                                continue 2;
                            }
                        } elseif (
                            strpos(',FD,FD-RX,FD-NORM,FD-NORM-RX,', ',' . $Fragment[0] . ',') === false || ($Fragment[0] === 'FD' &&
                                strpos(substr($str_hex, $Fragment[2] * 2), $Fragment[1]) === false) || ($Fragment[0] === 'FD-RX' &&
                                !preg_match('/(?:' . $Fragment[1] . ')/i', substr($str_hex, $Fragment[2] * 2))) || ($Fragment[0] === 'FD-NORM' &&
                                strpos(substr($str_hex_norm, $Fragment[2] * 2), $Fragment[1]) === false) || ($Fragment[0] === 'FD-NORM-RX' &&
                                !preg_match('/(?:' . $Fragment[1] . ')/i', substr($str_hex_norm, $Fragment[2] * 2)))
                        ) {
                            continue 2;
                        }
                    }
                } elseif (
                    ($Fragment[0] === 'FN' && !preg_match('/(?:' . $Fragment[1] . ')/i', $OriginalFilename)) ||
                    ($Fragment[0] === 'FS-MIN' && $StringLength < $Fragment[1]) ||
                    ($Fragment[0] === 'FS-MAX' && $StringLength > $Fragment[1]) ||
                    ($Fragment[0] === 'FD' && strpos($str_hex, $Fragment[1]) === false) ||
                    ($Fragment[0] === 'FD-RX' && !preg_match('/(?:' . $Fragment[1] . ')/i', $str_hex)) ||
                    ($Fragment[0] === 'FD-NORM' && strpos($str_hex_norm, $Fragment[1]) === false) ||
                    ($Fragment[0] === 'FD-NORM-RX' && !preg_match('/(?:' . $Fragment[1] . ')/i', $str_hex_norm))
                ) {
                    continue 2;
                } elseif (substr($Fragment[0], 0, 1) === '$') {
                    $VarInSigFile = substr($Fragment[0], 1);
                    if (!isset($$VarInSigFile) || is_array($$VarInSigFile) || $$VarInSigFile != $Fragment[1]) {
                        continue 2;
                    }
                } elseif (substr($Fragment[0], 0, 2) === '!$') {
                    $VarInSigFile = substr($Fragment[0], 2);
                    if (!isset($$VarInSigFile) || is_array($$VarInSigFile) || $$VarInSigFile == $Fragment[1]) {
                        continue 2;
                    }
                } elseif (strpos(',FN,FS-MIN,FS-MAX,FD,FD-RX,FD-NORM,FD-NORM-RX,', ',' . $Fragment[0] . ',') === false) {
                    continue 2;
                }
            }
            if (count($Switch) > 1) {
                if ($Switch[1] === 'true') {
                    $$theSwitch = true;
                    continue;
                }
                if ($Switch[1] === 'false') {
                    $$theSwitch = false;
                    continue;
                }
                $$theSwitch = $Switch[1];
            } else {
                if (!isset($$theSwitch)) {
                    $$theSwitch = true;
                    continue;
                }
                $$theSwitch = (!$$theSwitch);
            }
        }
        unset($theSwitch, $Switch, $ThisRule);

        /** Section offsets. */
        $SectionOffsets = [];

        /** Confirmation of whether or not the file is a valid PE file. */
        $is_pe = false;

        /** Number of PE sections in the file. */
        $NumOfSections = 0;

        $PEFileDescription = '';
        $PEFileVersion = '';
        $PEProductName = '';
        $PEProductVersion = '';
        $PECopyright = '';
        $PEOriginalFilename = '';
        $PECompanyName = '';
        if (
            !empty($this->Loader->InstanceCache['PE_Sectional']) ||
            !empty($this->Loader->InstanceCache['PE_Extended']) ||
            $this->Loader->Configuration['files']['corrupted_exe']
        ) {
            $PEArr = ['SectionArr' => []];
            if ($twocc === '4d5a') {
                $PEArr['Offset'] = $this->Loader->unpackSafe('S', substr($str, 60, 4));
                $PEArr['Offset'] = isset($PEArr['Offset'][1]) ? $PEArr['Offset'][1] : 0;
                while (true) {
                    $PEArr['DoScan'] = true;
                    if ($PEArr['Offset'] < 1 || $PEArr['Offset'] > 16384 || $PEArr['Offset'] > $StringLength) {
                        $PEArr['DoScan'] = false;
                        break;
                    }
                    $PEArr['Magic'] = substr($str, $PEArr['Offset'], 2);
                    if ($PEArr['Magic'] !== 'PE') {
                        $PEArr['DoScan'] = false;
                        break;
                    }
                    $PEArr['Proc'] = $this->Loader->unpackSafe('S', substr($str, $PEArr['Offset'] + 4, 2));
                    $PEArr['Proc'] = $PEArr['Proc'][1];
                    if ($PEArr['Proc'] != 0x14c && $PEArr['Proc'] != 0x8664) {
                        $PEArr['DoScan'] = false;
                        break;
                    }
                    $PEArr['NumOfSections'] = $this->Loader->unpackSafe('S', substr($str, $PEArr['Offset'] + 6, 2));
                    $NumOfSections = $PEArr['NumOfSections'] = $PEArr['NumOfSections'][1];
                    $CoExMeta .= 'PE_Offset:' . $PEArr['Offset'] . ';PE_Proc:' . $PEArr['Proc'] . ';NumOfSections:' . $NumOfSections . ';';
                    if ($NumOfSections < 1 || $NumOfSections > 40) {
                        $PEArr['DoScan'] = false;
                    }
                    break;
                }
                if (!$PEArr['DoScan']) {
                    if ($this->Loader->Configuration['files']['corrupted_exe']) {
                        if (!$Flagged) {
                            $this->Loader->HashReference .= $sha256 . ':' . $StringLength . ':' . $OriginalFilename . "\n";
                            $Flagged = true;
                        }
                        $heur['detections']++;
                        $this->Loader->InstanceCache['detections_count']++;
                        $Out .= $lnap . sprintf(
                                $this->Loader->L10N->getString('_exclamation_final'),
                                $this->Loader->L10N->getString('corrupted')
                            ) . "\n";
                        $this->Loader->WhyFlagged .= sprintf(
                            $this->Loader->L10N->getString('_exclamation'),
                            $this->Loader->L10N->getString('corrupted') . ' (' . $OriginalFilenameSafe . ')'
                        );
                    }
                } else {
                    $is_pe = true;
                    $asciiable = false;
                    $PEArr['OptHdrSize'] = $this->Loader->unpackSafe('S', substr($str, $PEArr['Offset'] + 20, 2));
                    $PEArr['OptHdrSize'] = $PEArr['OptHdrSize'][1];
                    for ($PEArr['k'] = 0; $PEArr['k'] < $NumOfSections; $PEArr['k']++) {
                        $PEArr['SectionArr'][$PEArr['k']] = [
                            'SectionHead' => substr($str, $PEArr['Offset'] + 24 + $PEArr['OptHdrSize'] + ($PEArr['k'] * 40), $NumOfSections * 40)
                        ];
                        $PEArr['SectionArr'][$PEArr['k']]['SectionName'] =
                            str_ireplace("\x00", '', substr($PEArr['SectionArr'][$PEArr['k']]['SectionHead'], 0, 8));
                        $PEArr['SectionArr'][$PEArr['k']]['VirtualSize'] =
                            $this->Loader->unpackSafe('S', substr($PEArr['SectionArr'][$PEArr['k']]['SectionHead'], 8, 4));
                        $PEArr['SectionArr'][$PEArr['k']]['VirtualSize'] =
                            $PEArr['SectionArr'][$PEArr['k']]['VirtualSize'][1];
                        $PEArr['SectionArr'][$PEArr['k']]['VirtualAddress'] =
                            $this->Loader->unpackSafe('S', substr($PEArr['SectionArr'][$PEArr['k']]['SectionHead'], 12, 4));
                        $PEArr['SectionArr'][$PEArr['k']]['VirtualAddress'] =
                            $PEArr['SectionArr'][$PEArr['k']]['VirtualAddress'][1];
                        $SizeOfRawData = $this->Loader->unpackSafe('S', substr($PEArr['SectionArr'][$PEArr['k']]['SectionHead'], 16, 4));
                        $SizeOfRawData = $SizeOfRawData[1];
                        $PointerToRawData = $this->Loader->unpackSafe('S', substr($PEArr['SectionArr'][$PEArr['k']]['SectionHead'], 20, 4));
                        $PointerToRawData = $PointerToRawData[1];
                        $PEArr['SectionArr'][$PEArr['k']]['SectionData'] = substr($str, $PointerToRawData, $SizeOfRawData);
                        $SectionOffsets[$PEArr['k']] = [$PointerToRawData, $SizeOfRawData];
                        foreach (['md5', 'sha1', 'sha256'] as $TryHash) {
                            $PEArr['SectionArr'][$PEArr['k']][$TryHash] = hash($TryHash, $PEArr['SectionArr'][$PEArr['k']]['SectionData']);
                        }
                        $this->Loader->PEData .=
                            $SizeOfRawData . ':' .
                            $PEArr['SectionArr'][$PEArr['k']]['sha256'] . ':' . $OriginalFilename . '-' .
                            $PEArr['SectionArr'][$PEArr['k']]['SectionName'] . "\n";
                        $CoExMeta .= sprintf(
                            'SectionName:%s;VirtualSize:%s;VirtualAddress:%s;SizeOfRawData:%s;SHA256:%s;',
                            $PEArr['SectionArr'][$PEArr['k']]['SectionName'],
                            $PEArr['SectionArr'][$PEArr['k']]['VirtualSize'],
                            $PEArr['SectionArr'][$PEArr['k']]['VirtualAddress'],
                            $SizeOfRawData,
                            $PEArr['SectionArr'][$PEArr['k']]['sha256']
                        );
                        $PEArr['SectionArr'][$PEArr['k']] = [
                            $SizeOfRawData . ':' . $PEArr['SectionArr'][$PEArr['k']]['md5'] . ':',
                            $SizeOfRawData . ':' . $PEArr['SectionArr'][$PEArr['k']]['sha1'] . ':',
                            $SizeOfRawData . ':' . $PEArr['SectionArr'][$PEArr['k']]['sha256'] . ':'
                        ];
                    }
                    if (strpos($str, "V\x00a\x00r\x00F\x00i\x00l\x00e\x00I\x00n\x00f\x00o\x00\x00\x00\x00\x00\x24") !== false) {
                        $PEArr['Parts'] = $this->Loader->substrAfterLast($str, "V\x00a\x00r\x00F\x00i\x00l\x00e\x00I\x00n\x00f\x00o\x00\x00\x00\x00\x00\x24");
                        $PEArr['FINFO'] = [];
                        foreach ([
                                     ["F\x00i\x00l\x00e\x00D\x00e\x00s\x00c\x00r\x00i\x00p\x00t\x00i\x00o\x00n\x00\x00\x00", 'PEFileDescription'],
                                     ["F\x00i\x00l\x00e\x00V\x00e\x00r\x00s\x00i\x00o\x00n\x00\x00\x00", 'PEFileVersion'],
                                     ["P\x00r\x00o\x00d\x00u\x00c\x00t\x00N\x00a\x00m\x00e\x00\x00\x00", 'PEProductName'],
                                     ["P\x00r\x00o\x00d\x00u\x00c\x00t\x00V\x00e\x00r\x00s\x00i\x00o\x00n\x00\x00\x00", 'PEProductVersion'],
                                     ["L\x00e\x00g\x00a\x00l\x00C\x00o\x00p\x00y\x00r\x00i\x00g\x00h\x00t\x00\x00\x00", 'PECopyright'],
                                     ["O\x00r\x00i\x00g\x00i\x00n\x00a\x00l\x00F\x00i\x00l\x00e\x00n\x00a\x00m\x00e\x00\x00\x00", 'PEOriginalFilename'],
                                     ["C\x00o\x00m\x00p\x00a\x00n\x00y\x00N\x00a\x00m\x00e\x00\x00\x00", 'PECompanyName'],
                                 ] as $PEVars) {
                            if (strpos($PEArr['Parts'], $PEVars[0]) !== false && (${$PEVars[1]} = trim(str_ireplace("\x00", '', $this->Loader->substrBeforeFirst(
                                    $this->Loader->substrAfterLast($PEArr['Parts'], $PEVars[0]),
                                    "\x00\x00\x00"
                                ))))) {
                                foreach (['md5', 'sha1', 'sha256'] as $TryHash) {
                                    $PEArr['FINFO'][] = sprintf(
                                        '$%s:%s:%d:',
                                        $PEVars[1],
                                        $TryHash = hash($TryHash, ${$PEVars[1]}),
                                        strlen(${$PEVars[1]})
                                    );
                                }
                            }
                        }
                        unset($PEVars, $PEArr['Parts']);
                    }
                    unset($PointerToRawData, $SizeOfRawData);
                }
            }
        }

        /** Look for potential indicators of not being HTML. */
        $is_not_html = (!$is_html && ($is_macho || $is_elf || $is_pe));

        /** Look for potential indicators of not being PHP. */
        $is_not_php = ((strpos(',phar,', ',' . $xt . ',') === false &&
                strpos(',php*,', ',' . $xts . ',') === false &&
                strpos(',phar,', ',' . $gzxt . ',') === false &&
                strpos(',php*,', ',' . $gzxts . ',') === false &&
                strpos($str_hex_norm, '3c3f706870') === false) || $is_pe);

        /** Set debug values, if this has been enabled. */
        if (isset($this->debugArr)) {
            $this->Loader->InstanceCache['DebugArrKey'] = count($this->debugArr);
            $this->debugArr[$this->Loader->InstanceCache['DebugArrKey']] = [
                'Filename' => $OriginalFilename,
                'FromCache' => false,
                'Depth' => $Depth,
                'Size' => $StringLength,
                'MD5' => $md5,
                'SHA1' => $sha1,
                'SHA256' => $sha256,
                'CRC32B' => $crc32b,
                '2CC' => $twocc,
                '4CC' => $fourcc,
                'ScanPhase' => $phase,
                'Container' => $container,
                'FileSwitch' => $fileswitch,
                'Is_ELF' => $is_elf,
                'Is_Graphics' => $is_graphics,
                'Is_HTML' => $is_html,
                'Is_Email' => $is_email,
                'Is_MachO' => $is_macho,
                'Is_PDF' => $is_pdf,
                'Is_SWF' => $is_swf,
                'Is_PE' => $is_pe,
                'Is_Not_HTML' => $is_not_html,
                'Is_Not_PHP' => $is_not_php
            ];
            if ($is_pe) {
                $this->debugArr[$this->Loader->InstanceCache['DebugArrKey']] += [
                    'NumOfSections' => $NumOfSections,
                    'PEFileDescription' => $PEFileDescription,
                    'PEFileVersion' => $PEFileVersion,
                    'PEProductName' => $PEProductName,
                    'PEProductVersion' => $PEProductVersion,
                    'PECopyright' => $PECopyright,
                    'PEOriginalFilename' => $PEOriginalFilename,
                    'PECompanyName' => $PECompanyName
                ];
            }
        }

        /** Fire event: "beforeURLScanner". */
        $this->Loader->Events->fireEvent('beforeURLScanner');

        /** Begin URL scanner. */
        if (
            isset($this->Loader->InstanceCache['URL_Scanner']) ||
            !empty($this->Loader->Configuration['urlscanner']['lookup_hphosts']) ||
            !empty($this->Loader->Configuration['urlscanner']['google_api_key'])
        ) {
            $this->Loader->InstanceCache['LookupCount'] = 0;
            $URLScanner = [
                'FixedSource' => preg_replace('~(data|f(ile|tps?)|https?|sftp):~i', "\x01\\1:", str_replace("\\", '/', $str_norm)) . "\x01",
                'DomainsNoLookup' => [],
                'DomainsCount' => 0,
                'Domains' => [],
                'DomainPartsNoLookup' => [],
                'DomainParts' => [],
                'Queries' => [],
                'URLsNoLookup' => [],
                'URLsCount' => 0,
                'URLs' => [],
                'URLPartsNoLookup' => [],
                'URLParts' => [],
                'TLDs' => [],
                'Iterable' => 0,
                'Matches' => []
            ];
            if (preg_match_all(
                '~(?:data|f(?:ile|tps?)|https?|sftp)://(?:www\d{0,3}\.)?([\da-z.-]{1,512})[^\da-z.-]~i',
                $URLScanner['FixedSource'],
                $URLScanner['Matches']
            )) {
                foreach ($URLScanner['Matches'][1] as $ThisURL) {
                    $URLScanner['DomainParts'][$URLScanner['Iterable']] = $ThisURL;
                    if (strpos($URLScanner['DomainParts'][$URLScanner['Iterable']], '.') !== false) {
                        $URLScanner['TLDs'][$URLScanner['Iterable']] = 'TLD:' . $this->Loader->substrAfterLast(
                                $URLScanner['DomainParts'][$URLScanner['Iterable']],
                                '.'
                            ) . ':';
                    }
                    $ThisURL = hash('md5', $ThisURL) . ':' . strlen($ThisURL) . ':';
                    $URLScanner['Domains'][$URLScanner['Iterable']] = 'DOMAIN:' . $ThisURL;
                    $URLScanner['DomainsNoLookup'][$URLScanner['Iterable']] = 'DOMAIN-NOLOOKUP:' . $ThisURL;
                    $URLScanner['Iterable']++;
                }
            }
            $URLScanner['DomainsNoLookup'] = array_unique($URLScanner['DomainsNoLookup']);
            $URLScanner['Domains'] = array_unique($URLScanner['Domains']);
            $URLScanner['DomainParts'] = array_unique($URLScanner['DomainParts']);
            $URLScanner['TLDs'] = array_unique($URLScanner['TLDs']);
            sort($URLScanner['DomainsNoLookup']);
            sort($URLScanner['Domains']);
            sort($URLScanner['DomainParts']);
            sort($URLScanner['TLDs']);
            $URLScanner['Iterable'] = 0;
            $URLScanner['Matches'] = '';
            if (preg_match_all(
                '~(?:data|f(?:ile|tps?)|https?|sftp)://(?:www\d{0,3}\.)?([!#$&-;=?@-\[\]_a-z\~]+)[^!#$&-;=?@-\[\]_a-z\~]~i',
                $URLScanner['FixedSource'],
                $URLScanner['Matches']
            )) {
                foreach ($URLScanner['Matches'][1] as $ThisURL) {
                    if (strlen($ThisURL) > 4096) {
                        $ThisURL = substr($ThisURL, 0, 4096);
                    }
                    $URLHash = hash('md5', $ThisURL) . ':' . strlen($ThisURL) . ':';
                    $URLScanner['URLsNoLookup'][$URLScanner['Iterable']] = 'URL-NOLOOKUP:' . $URLHash;
                    $URLScanner['URLParts'][$URLScanner['Iterable']] = $ThisURL;
                    $URLScanner['URLs'][$URLScanner['Iterable']] = 'URL:' . $URLHash;
                    $URLScanner['Iterable']++;
                    if (preg_match('/[^\da-z.-]$/i', $ThisURL)) {
                        $URLScanner['x'] = preg_replace('/[^\da-z.-]+$/i', '', $ThisURL);
                        $URLHash = hash('md5', $URLScanner['x']) . ':' . strlen($URLScanner['x']) . ':';
                        $URLScanner['URLsNoLookup'][$URLScanner['Iterable']] = 'URL-NOLOOKUP:' . $URLHash;
                        $URLScanner['URLParts'][$URLScanner['Iterable']] = $URLScanner['x'];
                        $URLScanner['URLs'][$URLScanner['Iterable']] = 'URL:' . $URLHash;
                        $URLScanner['Iterable']++;
                    }
                    if (strpos($ThisURL, '?') !== false) {
                        $URLScanner['x'] = $this->Loader->substrBeforeFirst($ThisURL, '?');
                        $URLHash = hash('md5', $URLScanner['x']) . ':' . strlen($URLScanner['x']) . ':';
                        $URLScanner['URLsNoLookup'][$URLScanner['Iterable']] = 'URL-NOLOOKUP:' . $URLHash;
                        $URLScanner['URLParts'][$URLScanner['Iterable']] = $URLScanner['x'];
                        $URLScanner['URLs'][$URLScanner['Iterable']] = 'URL:' . $URLHash;
                        $URLScanner['x'] = $this->Loader->substrAfterFirst($ThisURL, '?');
                        $URLScanner['Queries'][$URLScanner['Iterable']] = 'QUERY:' . hash('md5', $URLScanner['x']) . ':' . strlen($URLScanner['x']) . ':';
                        $URLScanner['Iterable']++;
                    }
                }
                unset($URLScanner['x'], $URLHash);
            }
            unset($ThisURL, $URLScanner['Matches']);
            $URLScanner['URLsNoLookup'] = array_unique($URLScanner['URLsNoLookup']);
            $URLScanner['URLs'] = array_unique($URLScanner['URLs']);
            $URLScanner['URLParts'] = array_unique($URLScanner['URLParts']);
            $URLScanner['Queries'] = array_unique($URLScanner['Queries']);
            sort($URLScanner['URLsNoLookup']);
            sort($URLScanner['URLs']);
            sort($URLScanner['URLParts']);
            sort($URLScanner['Queries']);
        }

        /** Process non-mappable signatures. */
        foreach ([
                     ['General_Command_Detections', 0],
                     ['Hash', 1],
                     ['PE_Sectional', 2],
                     ['PE_Extended', 3],
                     ['URL_Scanner', 4],
                     ['Complex_Extended', 5]
                 ] as $ThisConf) {

            /** Fire event: "beforeSigFiles". */
            $this->Loader->Events->fireEvent('beforeSigFiles');

            $SigFiles = isset($this->Loader->InstanceCache[$ThisConf[0]]) ? explode(',', $this->Loader->InstanceCache[$ThisConf[0]]) : [];
            foreach ($SigFiles as $SigFile) {
                if (!$SigFile) {
                    continue;
                }
                if (!isset($this->Loader->InstanceCache[$SigFile])) {
                    $this->Loader->InstanceCache[$SigFile] = $this->Loader->readFileBlocks($this->Loader->SignaturesPath . $SigFile);
                }

                /** Fire event: "beforeSigFile". */
                $this->Loader->Events->fireEvent('beforeSigFile', '', $SigFile);

                if (empty($this->Loader->InstanceCache[$SigFile])) {
                    $this->Loader->InstanceCache['scan_errors']++;
                    if (!$this->Loader->Configuration['signatures']['fail_silently']) {
                        if (!$Flagged) {
                            $this->Loader->HashReference .= $sha256 . ':' . $StringLength . ":\n";
                        }
                        $this->Loader->WhyFlagged .= sprintf(
                            $this->Loader->L10N->getString('_exclamation'),
                            $this->Loader->L10N->getString('scan_signature_file_missing') . ' (' . $SigFile . ')'
                        );
                        return [-3, $lnap . sprintf(
                                $this->Loader->L10N->getString('_exclamation_final'),
                                $this->Loader->L10N->getString('scan_signature_file_missing') . ' (' . $SigFile . ')'
                            ) . "\n"];
                    }
                } elseif ($ThisConf[1] === 0) {
                    if (substr($this->Loader->InstanceCache[$SigFile], 0, 9) === 'phpMussel') {
                        $this->Loader->InstanceCache[$SigFile] = substr($this->Loader->InstanceCache[$SigFile], 11, -1);
                    }
                    $ArrayCSV = explode(',', $this->Loader->InstanceCache[$SigFile]);
                    foreach ($ArrayCSV as $ItemCSV) {
                        if (strpos($str_hex_norm, $ItemCSV) !== false) {
                            if (!$Flagged) {
                                $this->Loader->HashReference .= $sha256 . ':' . $StringLength . ':' . $OriginalFilename . "\n";
                                $Flagged = true;
                            }
                            $heur['detections']++;
                            $this->Loader->InstanceCache['detections_count']++;
                            $Out .= $lnap . sprintf(
                                    $this->Loader->L10N->getString('_exclamation'),
                                    $this->Loader->L10N->getString('scan_command_injection')
                                ) . "\n";
                            $this->Loader->WhyFlagged .= sprintf(
                                $this->Loader->L10N->getString('_exclamation'),
                                $this->Loader->L10N->getString('scan_command_injection') . ', \'' . $this->Loader->hexSafe($ItemCSV) . '\' (' . $OriginalFilenameSafe . ')'
                            );
                        }
                    }
                    unset($ItemCSV, $ArrayCSV);
                } elseif ($ThisConf[1] === 1) {
                    foreach ([$md5, $sha1, $sha256] as $CheckThisHash) {
                        if (strpos($this->Loader->InstanceCache[$SigFile], "\n" . $CheckThisHash . ':' . $StringLength . ':') !== false) {
                            $xSig = $this->Loader->substrAfterFirst($this->Loader->InstanceCache[$SigFile], "\n" . $CheckThisHash . ':' . $StringLength . ':');
                            if (strpos($xSig, "\n") !== false) {
                                $xSig = $this->Loader->substrBeforeFirst($xSig, "\n");
                            }
                            $xSig = $this->getShorthand($xSig);
                            if (
                                strpos($this->Loader->InstanceCache['Greylist'], ',' . $xSig . ',') === false &&
                                empty($this->Loader->InstanceCache['ignoreme'])
                            ) {
                                $this->detected($heur, $lnap, $xSig, $OriginalFilename, $OriginalFilenameSafe, $Out, $Flagged, $md5, $StringLength);
                            }
                        }
                    }
                } elseif ($ThisConf[1] === 2) {
                    for ($PEArr['k'] = 0; $PEArr['k'] < $NumOfSections; $PEArr['k']++) {
                        if (!isset($PEArr['SectionArr'][$PEArr['k']]) || !is_array($PEArr['SectionArr'][$PEArr['k']])) {
                            continue;
                        }
                        foreach ($PEArr['SectionArr'][$PEArr['k']] as $TryThis) {
                            if (strpos($this->Loader->InstanceCache[$SigFile], $TryThis) !== false) {
                                $xSig = $this->Loader->substrAfterFirst($this->Loader->InstanceCache[$SigFile], $TryThis);
                                if (strpos($xSig, "\n") !== false) {
                                    $xSig = $this->Loader->substrBeforeFirst($xSig, "\n");
                                }
                                $xSig = $this->getShorthand($xSig);
                                if (
                                    strpos($this->Loader->InstanceCache['Greylist'], ',' . $xSig . ',') === false &&
                                    empty($this->Loader->InstanceCache['ignoreme'])
                                ) {
                                    $this->detected($heur, $lnap, $xSig, $OriginalFilename, $OriginalFilenameSafe, $Out, $Flagged, $md5, $StringLength);
                                }
                            }
                        }
                    }
                } elseif ($ThisConf[1] === 3) {
                    if (!empty($PEArr['FINFO'])) {
                        foreach ($PEArr['FINFO'] as $PEArr['ThisPart']) {
                            if (substr_count($this->Loader->InstanceCache[$SigFile], $PEArr['ThisPart'])) {
                                $xSig = $this->Loader->substrAfterFirst($this->Loader->InstanceCache[$SigFile], $PEArr['ThisPart']);
                                if (strpos($xSig, "\n") !== false) {
                                    $xSig = $this->Loader->substrBeforeFirst($xSig, "\n");
                                }
                                $xSig = $this->getShorthand($xSig);
                                if (
                                    !substr_count($this->Loader->InstanceCache['Greylist'], ',' . $xSig . ',') &&
                                    empty($this->Loader->InstanceCache['ignoreme'])
                                ) {
                                    $this->detected($heur, $lnap, $xSig, $OriginalFilename, $OriginalFilenameSafe, $Out, $Flagged, $md5, $StringLength);
                                }
                            }
                        }
                    }
                } elseif ($ThisConf[1] === 4) {
                    foreach ([$URLScanner['DomainsNoLookup'], $URLScanner['URLsNoLookup']] as $URLScanner['ThisArr']) {
                        foreach ($URLScanner['ThisArr'] as $URLHash) {
                            if (strpos($this->Loader->InstanceCache[$SigFile], $URLHash) !== false) {
                                $xSig = $this->Loader->substrAfterFirst($this->Loader->InstanceCache[$SigFile], $URLHash);
                                if (strpos($xSig, "\n") !== false) {
                                    $xSig = $this->Loader->substrBeforeFirst($xSig, "\n");
                                }
                                if (substr($URLHash, 0, 15) === 'DOMAIN-NOLOOKUP') {
                                    $URLScanner['DomainPartsNoLookup'][$xSig] = true;
                                    continue;
                                }
                                $URLScanner['URLPartsNoLookup'][$xSig] = true;
                            }
                        }
                    }
                    foreach ([
                                 $URLScanner['TLDs'],
                                 $URLScanner['Domains'],
                                 $URLScanner['URLs'],
                                 $URLScanner['Queries']
                             ] as $URLScanner['ThisArr']) {
                        foreach ($URLScanner['ThisArr'] as $URLHash) {
                            if (substr_count($this->Loader->InstanceCache[$SigFile], $URLHash)) {
                                $xSig = $this->Loader->substrAfterFirst($this->Loader->InstanceCache[$SigFile], $URLHash);
                                if (strpos($xSig, "\n") !== false) {
                                    $xSig = $this->Loader->substrBeforeFirst($xSig, "\n");
                                }
                                if (
                                    ($xSig = $this->getShorthand($xSig)) &&
                                    !substr_count($this->Loader->InstanceCache['Greylist'], ',' . $xSig . ',') &&
                                    empty($this->Loader->InstanceCache['ignoreme'])
                                ) {
                                    $this->detected($heur, $lnap, $xSig, $OriginalFilename, $OriginalFilenameSafe, $Out, $Flagged, $md5, $StringLength);
                                }
                            }
                        }
                    }
                } elseif ($ThisConf[1] === 5) {
                    $SigName = '';
                    foreach ([
                                 'NumOfSections',
                                 'PECompanyName',
                                 'PECopyright',
                                 'PEFileDescription',
                                 'PEFileVersion',
                                 'PEOriginalFilename',
                                 'PEProductName',
                                 'PEProductVersion',
                                 'container',
                                 'crc32b',
                                 'fileswitch',
                                 'fourcc',
                                 'is_elf',
                                 'is_email',
                                 'is_graphics',
                                 'is_html',
                                 'is_macho',
                                 'is_not_html',
                                 'is_not_php',
                                 'is_ole',
                                 'is_pdf',
                                 'is_pe',
                                 'is_swf',
                                 'md5',
                                 'phase',
                                 'sha1',
                                 'sha256',
                                 'StringLength',
                                 'twocc',
                                 'xt',
                                 'xts'
                             ] as $ThisCheckFor) {
                        if (!isset($$ThisCheckFor)) {
                            continue;
                        }
                        $ThisCheckValue = "\n$" . $ThisCheckFor . ':' . (substr($ThisCheckFor, 0, 3) !== 'is_' ? $$ThisCheckFor : ($$ThisCheckFor ? '1' : '0')) . ';';
                        if (strpos($this->Loader->InstanceCache[$SigFile], $ThisCheckValue) === false) {
                            continue;
                        }
                        $xSig = explode($ThisCheckValue, $this->Loader->InstanceCache[$SigFile]);
                        $xSigCount = count($xSig);
                        if (isset($xSig[0])) {
                            $xSig[0] = '';
                        }
                        if ($xSigCount > 0) {
                            for ($xIter = 1; $xIter < $xSigCount; $xIter++) {
                                if (strpos($xSig[$xIter], "\n") !== false) {
                                    $xSig[$xIter] = $this->Loader->substrBeforeFirst($xSig[$xIter], "\n");
                                }
                                if (strpos($xSig[$xIter], ';') !== false) {
                                    if (strpos($xSig[$xIter], ':') === false) {
                                        continue;
                                    }
                                    $SigName = $this->getShorthand($this->Loader->substrAfterLast($xSig[$xIter], ';'));
                                    $xSig[$xIter] = explode(';', $this->Loader->substrBeforeLast($xSig[$xIter], ';'));
                                } else {
                                    $SigName = $this->getShorthand($xSig[$xIter]);
                                    $xSig[$xIter] = [];
                                }
                                foreach ($xSig[$xIter] as $ThisSigPart) {
                                    if (empty($ThisSigPart)) {
                                        continue 2;
                                    }
                                    $ThisSigPart = $this->splitSigParts($ThisSigPart, 7);
                                    if ($ThisSigPart[0] === 'LV') {
                                        if (!isset($ThisSigPart[1]) || substr($ThisSigPart[1], 0, 1) !== '$') {
                                            continue 2;
                                        }
                                        $lv_haystack = substr($ThisSigPart[1], 1);
                                        if (!isset($$lv_haystack) || is_array($$lv_haystack)) {
                                            continue 2;
                                        }
                                        $lv_haystack = $$lv_haystack;
                                        if ($climode) {
                                            $lv_haystack = $this->Loader->substrAfterLast($this->Loader->substrAfterLast($lv_haystack, '/'), "\\");
                                        }
                                        $lv_needle = $ThisSigPart[2] ?? '';
                                        $pos_A = $ThisSigPart[3] ?? 0;
                                        $pos_Z = $ThisSigPart[4] ?? 0;
                                        $lv_min = $ThisSigPart[5] ?? 0;
                                        $lv_max = $ThisSigPart[6] ?? -1;
                                        if (!$this->lvMatch($lv_needle, $lv_haystack, $pos_A, $pos_Z, $lv_min, $lv_max)) {
                                            continue 2;
                                        }
                                        continue;
                                    }
                                    if (isset($ThisSigPart[2])) {
                                        if (isset($ThisSigPart[3])) {
                                            if ($ThisSigPart[2] === 'A') {
                                                if (strpos(',FD,FD-RX,FD-NORM,FD-NORM-RX,META,', ',' . $ThisSigPart[0] . ',') === false || ($ThisSigPart[0] === 'FD' &&
                                                        strpos("\x01" . substr($str_hex, 0, $ThisSigPart[3] * 2), "\x01" . $ThisSigPart[1]) === false) || ($ThisSigPart[0] === 'FD-RX' &&
                                                        !preg_match('/\A(?:' . $ThisSigPart[1] . ')/i', substr($str_hex, 0, $ThisSigPart[3] * 2))) || ($ThisSigPart[0] === 'FD-NORM' &&
                                                        strpos("\x01" . substr($str_hex_norm, 0, $ThisSigPart[3] * 2), "\x01" . $ThisSigPart[1]) === false) || ($ThisSigPart[0] === 'FD-NORM-RX' &&
                                                        !preg_match('/\A(?:' . $ThisSigPart[1] . ')/i', substr($str_hex_norm, 0, $ThisSigPart[3] * 2))) || ($ThisSigPart[0] === 'META' &&
                                                        !preg_match('/\A(?:' . $ThisSigPart[1] . ')/i', substr($CoExMeta, 0, $ThisSigPart[3] * 2)))) {
                                                    continue 2;
                                                }
                                                continue;
                                            }
                                            if (strpos(',FD,FD-RX,FD-NORM,FD-NORM-RX,META,', ',' . $ThisSigPart[0] . ',') === false || ($ThisSigPart[0] === 'FD' &&
                                                    strpos(substr($str_hex, $ThisSigPart[2] * 2, $ThisSigPart[3] * 2), $ThisSigPart[1]) === false) || ($ThisSigPart[0] === 'FD-RX' &&
                                                    !preg_match('/(?:' . $ThisSigPart[1] . ')/i', substr($str_hex, $ThisSigPart[2] * 2, $ThisSigPart[3] * 2))) || ($ThisSigPart[0] === 'FD-NORM' &&
                                                    strpos(substr($str_hex_norm, $ThisSigPart[2] * 2, $ThisSigPart[3] * 2), $ThisSigPart[1]) === false) || ($ThisSigPart[0] === 'FD-NORM-RX' &&
                                                    !preg_match('/(?:' . $ThisSigPart[1] . ')/i', substr($str_hex_norm, $ThisSigPart[2] * 2, $ThisSigPart[3] * 2))) || ($ThisSigPart[0] === 'META' &&
                                                    !preg_match('/(?:' . $ThisSigPart[1] . ')/i', substr($CoExMeta, $ThisSigPart[2] * 2, $ThisSigPart[3] * 2)))) {
                                                continue 2;
                                            }
                                            continue;
                                        }
                                        if ($ThisSigPart[2] === 'A') {
                                            if (strpos(',FN,FD,FD-RX,FD-NORM,FD-NORM-RX,META,', ',' . $ThisSigPart[0] . ',') === false || ($ThisSigPart[0] === 'FN' &&
                                                    !preg_match('/\A(?:' . $ThisSigPart[1] . ')/i', $OriginalFilename)) || ($ThisSigPart[0] === 'FD' &&
                                                    strpos("\x01" . $str_hex, "\x01" . $ThisSigPart[1]) === false) || ($ThisSigPart[0] === 'FD-RX' &&
                                                    !preg_match('/\A(?:' . $ThisSigPart[1] . ')/i', $str_hex)) || ($ThisSigPart[0] === 'FD-NORM' &&
                                                    strpos("\x01" . $str_hex_norm, "\x01" . $ThisSigPart[1]) === false) || ($ThisSigPart[0] === 'FD-NORM-RX' &&
                                                    !preg_match('/\A(?:' . $ThisSigPart[1] . ')/i', $str_hex_norm)) || ($ThisSigPart[0] === 'META' &&
                                                    !preg_match('/\A(?:' . $ThisSigPart[1] . ')/i', $CoExMeta))) {
                                                continue 2;
                                            }
                                            continue;
                                        }
                                        if (strpos(',FD,FD-RX,FD-NORM,FD-NORM-RX,META,', ',' . $ThisSigPart[0] . ',') === false || ($ThisSigPart[0] === 'FD' &&
                                                strpos(substr($str_hex, $ThisSigPart[2] * 2), $ThisSigPart[1]) === false) || ($ThisSigPart[0] === 'FD-RX' &&
                                                !preg_match('/(?:' . $ThisSigPart[1] . ')/i', substr($str_hex, $ThisSigPart[2] * 2))) || ($ThisSigPart[0] === 'FD-NORM' &&
                                                strpos(substr($str_hex_norm, $ThisSigPart[2] * 2), $ThisSigPart[1]) === false) || ($ThisSigPart[0] === 'FD-NORM-RX' &&
                                                !preg_match('/(?:' . $ThisSigPart[1] . ')/i', substr($str_hex_norm, $ThisSigPart[2] * 2))) || ($ThisSigPart[0] === 'META' &&
                                                !preg_match('/(?:' . $ThisSigPart[1] . ')/i', substr($CoExMeta, $ThisSigPart[2] * 2)))) {
                                            continue 2;
                                        }
                                        continue;
                                    }
                                    if (($ThisSigPart[0] === 'FN' &&
                                            !preg_match('/(?:' . $ThisSigPart[1] . ')/i', $OriginalFilename)) || ($ThisSigPart[0] === 'FS-MIN' &&
                                            $StringLength < $ThisSigPart[1]) || ($ThisSigPart[0] === 'FS-MAX' &&
                                            $StringLength > $ThisSigPart[1]) || ($ThisSigPart[0] === 'FD' &&
                                            strpos($str_hex, $ThisSigPart[1]) === false) || ($ThisSigPart[0] === 'FD-RX' &&
                                            !preg_match('/(?:' . $ThisSigPart[1] . ')/i', $str_hex)) || ($ThisSigPart[0] === 'FD-NORM' &&
                                            strpos($str_hex_norm, $ThisSigPart[1]) === false) || ($ThisSigPart[0] === 'FD-NORM-RX' &&
                                            !preg_match('/(?:' . $ThisSigPart[1] . ')/i', $str_hex_norm)) || ($ThisSigPart[0] === 'META' &&
                                            !preg_match('/(?:' . $ThisSigPart[1] . ')/i', $CoExMeta))) {
                                        continue 2;
                                    }
                                    if (substr($ThisSigPart[0], 0, 1) === '$') {
                                        $VarInSigFile = substr($ThisSigPart[0], 1);
                                        if (!isset($$VarInSigFile) || is_array($$VarInSigFile) || $$VarInSigFile != $ThisSigPart[1]) {
                                            continue 2;
                                        }
                                        continue;
                                    }
                                    if (substr($ThisSigPart[0], 0, 2) === '!$') {
                                        $VarInSigFile = substr($ThisSigPart[0], 2);
                                        if (!isset($$VarInSigFile) || is_array($$VarInSigFile) || $$VarInSigFile == $ThisSigPart[1]) {
                                            continue 2;
                                        }
                                        continue;
                                    }
                                    if (strpos(',FN,FS-MIN,FS-MAX,FD,FD-RX,FD-NORM,FD-NORM-RX,META,', ',' . $ThisSigPart[0] . ',') === false) {
                                        continue 2;
                                    }
                                }
                                if (
                                    $SigName &&
                                    strpos($this->Loader->InstanceCache['Greylist'], ',' . $SigName . ',') === false &&
                                    empty($this->Loader->InstanceCache['ignoreme'])
                                ) {
                                    $this->detected($heur, $lnap, $SigName, $OriginalFilename, $OriginalFilenameSafe, $Out, $Flagged, $md5, $StringLength);
                                }
                            }
                        }
                    }

                    /** Cleanup. */
                    unset($SigName, $xIter, $xSigCount, $xSig, $ThisSigPart, $ThisCheckValue, $ThisCheckFor);
                }
            }
        }

        /** Process mappable signatures. */
        foreach ([
                     ['Filename', 'str_hex', 'str_hex_len', 2],
                     ['Standard', 'str_hex', 'str_hex_len', 0],
                     ['Normalised', 'str_hex_norm', 'str_hex_norm_len', 0],
                     ['HTML', 'str_hex_html', 'str_hex_html_len', 0],
                     ['Standard_RegEx', 'str_hex', 'str_hex_len', 1],
                     ['Normalised_RegEx', 'str_hex_norm', 'str_hex_norm_len', 1],
                     ['HTML_RegEx', 'str_hex_html', 'str_hex_html_len', 1]
                 ] as $ThisConf) {
            $DataSource = $ThisConf[1];
            $DataSourceLen = $ThisConf[2];

            /** Fire event: "beforeSigFiles". */
            $this->Loader->Events->fireEvent('beforeSigFiles');

            $SigFiles = isset($this->Loader->InstanceCache[$ThisConf[0]]) ? explode(',', $this->Loader->InstanceCache[$ThisConf[0]]) : [];
            foreach ($SigFiles as $SigFile) {
                if (!$SigFile) {
                    continue;
                }
                if (!isset($this->Loader->InstanceCache[$SigFile])) {
                    $this->Loader->InstanceCache[$SigFile] = $this->Loader->readFileAsArray($this->Loader->SignaturesPath . $SigFile, FILE_IGNORE_NEW_LINES);
                }

                /** Fire event: "beforeSigFile". */
                $this->Loader->Events->fireEvent('beforeSigFile', '', $SigFile);

                if (empty($this->Loader->InstanceCache[$SigFile])) {
                    $this->Loader->InstanceCache['scan_errors']++;
                    if (!$this->Loader->Configuration['signatures']['fail_silently']) {
                        if (!$Flagged) {
                            $this->Loader->HashReference .= $sha256 . ':' . $StringLength . ":\n";
                        }
                        $this->Loader->WhyFlagged .= sprintf(
                            $this->Loader->L10N->getString('_exclamation'),
                            $this->Loader->L10N->getString('scan_signature_file_missing') . ' (' . $SigFile . ')'
                        );
                        return [-3, $lnap . sprintf(
                                $this->Loader->L10N->getString('_exclamation_final'),
                                $this->Loader->L10N->getString('scan_signature_file_missing') . ' (' . $SigFile . ')'
                            ) . "\n"];
                    }
                    continue;
                }
                $NumSigs = count($this->Loader->InstanceCache[$SigFile]);
                for ($SigNum = 0; $SigNum < $NumSigs; $SigNum++) {
                    if (!$ThisSig = $this->Loader->InstanceCache[$SigFile][$SigNum]) {
                        continue;
                    }
                    if (substr($ThisSig, 0, 1) === '>') {
                        $ThisSig = explode('>', $ThisSig, 4);
                        if (!isset($ThisSig[1], $ThisSig[2], $ThisSig[3])) {
                            break;
                        }
                        $ThisSig[3] = (int)$ThisSig[3];
                        if ($ThisSig[1] === 'FN') {
                            if (!preg_match('/(?:' . $ThisSig[2] . ')/i', $OriginalFilename)) {
                                if ($ThisSig[3] <= $SigNum) {
                                    break;
                                }
                                $SigNum = $ThisSig[3] - 1;
                            }
                        } elseif ($ThisSig[1] === 'FS-MIN') {
                            if ($StringLength < $ThisSig[2]) {
                                if ($ThisSig[3] <= $SigNum) {
                                    break;
                                }
                                $SigNum = $ThisSig[3] - 1;
                            }
                        } elseif ($ThisSig[1] === 'FS-MAX') {
                            if ($StringLength > $ThisSig[2]) {
                                if ($ThisSig[3] <= $SigNum) {
                                    break;
                                }
                                $SigNum = $ThisSig[3] - 1;
                            }
                        } elseif ($ThisSig[1] === 'FD') {
                            if (strpos($$DataSource, $ThisSig[2]) === false) {
                                if ($ThisSig[3] <= $SigNum) {
                                    break;
                                }
                                $SigNum = $ThisSig[3] - 1;
                            }
                        } elseif ($ThisSig[1] === 'FD-RX') {
                            if (!preg_match('/(?:' . $ThisSig[2] . ')/i', $$DataSource)) {
                                if ($ThisSig[3] <= $SigNum) {
                                    break;
                                }
                                $SigNum = $ThisSig[3] - 1;
                            }
                        } elseif (substr($ThisSig[1], 0, 1) === '$') {
                            $VarInSigFile = substr($ThisSig[1], 1);
                            if (isset($$VarInSigFile) && is_scalar($$VarInSigFile)) {
                                if (!$this->matchVarInSigFile($ThisSig[2], $$VarInSigFile)) {
                                    if ($ThisSig[3] <= $SigNum) {
                                        break;
                                    }
                                    $SigNum = $ThisSig[3] - 1;
                                }
                                continue;
                            }
                            if ($ThisSig[3] <= $SigNum) {
                                break;
                            }
                            $SigNum = $ThisSig[3] - 1;
                        } elseif (substr($ThisSig[1], 0, 2) === '!$') {
                            $VarInSigFile = substr($ThisSig[1], 2);
                            if (isset($$VarInSigFile) && is_scalar($$VarInSigFile)) {
                                if ($this->matchVarInSigFile($ThisSig[2], $$VarInSigFile)) {
                                    if ($ThisSig[3] <= $SigNum) {
                                        break;
                                    }
                                    $SigNum = $ThisSig[3] - 1;
                                }
                                continue;
                            }
                            if ($ThisSig[3] <= $SigNum) {
                                break;
                            }
                            $SigNum = $ThisSig[3] - 1;
                        } else {
                            break;
                        }
                        continue;
                    }
                    if (strpos($ThisSig, ':') !== false) {
                        $VN = $this->splitSigParts($ThisSig);
                        if (!isset($VN[1]) || !strlen($VN[1])) {
                            continue;
                        }
                        if ($ThisConf[3] === 2) {
                            $ThisSig = preg_split('/[\x00-\x1f]+/', $VN[1], -1, PREG_SPLIT_NO_EMPTY);
                            $ThisSig = ($ThisSig === false) ? '' : implode('', $ThisSig);
                            $VN = $this->getShorthand($VN[0]);
                            if (
                                $ThisSig &&
                                strpos($this->Loader->InstanceCache['Greylist'], ',' . $VN . ',') === false &&
                                empty($this->Loader->InstanceCache['ignoreme'])
                            ) {
                                if (preg_match('/(?:' . $ThisSig . ')/i', $OriginalFilename)) {
                                    $this->detected($heur, $lnap, $VN, $OriginalFilename, $OriginalFilenameSafe, $Out, $Flagged, $md5, $StringLength);
                                }
                            }
                        } elseif ($ThisConf[3] === 0 || $ThisConf[3] === 1) {
                            $ThisSig = preg_split(($ThisConf[3] === 0 ? '/[^\da-f>]+/i' : '/[\x00-\x1f]+/'), $VN[1], -1, PREG_SPLIT_NO_EMPTY);
                            $ThisSig = ($ThisSig === false ? '' : implode('', $ThisSig));
                            $ThisSigLen = strlen($ThisSig);
                            if ($this->confineLength($ThisSigLen)) {
                                continue;
                            }
                            $xstrf = $VN[2] ?? '*';
                            $xstrt = $VN[3] ?? '*';
                            $VN = $this->getShorthand($VN[0]);
                            $VNLC = strtolower($VN);
                            if (($is_not_php && (strpos($VNLC, '-php') !== false || strpos($VNLC, '.php') !== false)) || ($is_not_html && (strpos($VNLC, '-htm') !== false || strpos($VNLC, '.htm') !== false)) || $$DataSourceLen < $ThisSigLen) {
                                continue;
                            }
                            if (
                                strpos($this->Loader->InstanceCache['Greylist'], ',' . $VN . ',') === false &&
                                empty($this->Loader->InstanceCache['ignoreme'])
                            ) {
                                if ($ThisConf[3] === 0) {
                                    $ThisSig = strpos($ThisSig, '>') !== false ? explode('>', $ThisSig) : [$ThisSig];
                                    $ThisSigCount = count($ThisSig);
                                    $ThisString = $$DataSource;
                                    $this->dataConfineByOffsets($ThisString, $xstrf, $xstrt, $SectionOffsets);
                                    if ($xstrf === 'A') {
                                        $ThisString = "\x01" . $ThisString;
                                        $ThisSig[0] = "\x01" . $ThisSig[0];
                                    }
                                    if ($xstrt === 'Z') {
                                        $ThisString .= "\x01";
                                        $ThisSig[$ThisSigCount - 1] .= "\x01";
                                    }
                                    for ($ThisSigi = 0; $ThisSigi < $ThisSigCount; $ThisSigi++) {
                                        if (strpos($ThisString, $ThisSig[$ThisSigi]) === false) {
                                            continue 2;
                                        }
                                        if ($ThisSigCount > 1 && strpos($ThisString, $ThisSig[$ThisSigi]) !== false) {
                                            $ThisString = $this->Loader->substrAfterFirst($ThisString, $ThisSig[$ThisSigi]);
                                        }
                                    }
                                } else {
                                    $ThisString = $$DataSource;
                                    $this->dataConfineByOffsets($ThisString, $xstrf, $xstrt, $SectionOffsets);
                                    if ($xstrf === 'A') {
                                        if ($xstrt === 'Z') {
                                            if (!preg_match('/\A(?:' . $ThisSig . ')$/i', $ThisString)) {
                                                continue;
                                            }
                                        } elseif (!preg_match('/\A(?:' . $ThisSig . ')/i', $ThisString)) {
                                            continue;
                                        }
                                    } else {
                                        if ($xstrt === 'Z') {
                                            if (!preg_match('/(?:' . $ThisSig . ')$/i', $ThisString)) {
                                                continue;
                                            }
                                        } elseif (!preg_match('/(?:' . $ThisSig . ')/i', $ThisString)) {
                                            continue;
                                        }
                                    }
                                }
                                $this->detected($heur, $lnap, $VN, $OriginalFilename, $OriginalFilenameSafe, $Out, $Flagged, $md5, $StringLength);
                            }
                        }
                    }
                }
            }
        }

        /** Perform API lookups for domains. */
        if (isset($URLScanner) && !$Out) {

            $URLScanner['DomainsCount'] = count($URLScanner['DomainParts']);

            /** Codeblock for performing hpHosts API lookups. */
            if ($this->Loader->Configuration['urlscanner']['lookup_hphosts'] && $URLScanner['DomainsCount']) {

                /** Fetch the cache entry for hpHosts, if it doesn't already exist. */
                if (!isset($this->Loader->InstanceCache['urlscanner_domains'])) {
                    $this->Loader->InstanceCache['urlscanner_domains'] = $this->Loader->Cache->getEntry('urlscanner_domains');
                }

                $URLExpiry = $this->Loader->Time + $this->Loader->Configuration['urlscanner']['cache_time'];
                $URLScanner['ScriptIdentEncoded'] = urlencode($this->Loader->ScriptIdent);
                $URLScanner['classes'] = [
                    'EMD' => "\x1a\x82\x10\x1bXXX",
                    'EXP' => "\x1a\x82\x10\x16XXX",
                    'GRM' => "\x1a\x82\x10\x32XXX",
                    'HFS' => "\x1a\x82\x10\x32XXX",
                    'PHA' => "\x1a\x82\x10\x32XXX",
                    'PSH' => "\x1a\x82\x10\x31XXX"
                ];
                for ($i = 0; $i < $URLScanner['DomainsCount']; $i++) {
                    if (!empty($URLScanner['DomainPartsNoLookup'][$URLScanner['DomainParts'][$i]])) {
                        continue;
                    }
                    if (
                        $this->Loader->Configuration['urlscanner']['maximum_api_lookups'] > 0 &&
                        $this->Loader->InstanceCache['LookupCount'] > $this->Loader->Configuration['urlscanner']['maximum_api_lookups']
                    ) {
                        if ($this->Loader->Configuration['urlscanner']['maximum_api_lookups_response']) {
                            if (!$Flagged) {
                                $this->Loader->HashReference .= $sha256 . ':' . $StringLength . ':' . $OriginalFilename . "\n";
                                $Flagged = true;
                            }
                            $Out .= $lnap . sprintf(
                                    $this->Loader->L10N->getString('_exclamation_final'),
                                    $this->Loader->L10N->getString('too_many_urls')
                                ) . "\n";
                            $this->Loader->WhyFlagged .= sprintf(
                                $this->Loader->L10N->getString('_exclamation'),
                                $this->Loader->L10N->getString('too_many_urls') . ' (' . $OriginalFilenameSafe . ')'
                            );
                        }
                        break;
                    }
                    $URLHash = hash('md5', $URLScanner['DomainParts'][$i]) . ':' . strlen($URLScanner['DomainParts'][$i]) . ':';
                    while (substr_count($this->Loader->InstanceCache['urlscanner_domains'], $URLHash)) {
                        $URLScanner['Class'] =
                            $this->Loader->substrBeforeFirst($this->Loader->substrAfterLast($this->Loader->InstanceCache['urlscanner_domains'], $URLHash), ';');
                        if (!substr_count($this->Loader->InstanceCache['urlscanner_domains'], $URLHash . ':' . $URLScanner['Class'] . ';')) {
                            break;
                        }
                        $URLScanner['Expiry'] = (int)$this->Loader->substrBeforeFirst($URLScanner['Class'], ':');
                        if ($URLScanner['Expiry'] > $this->Loader->Time) {
                            $URLScanner['Class'] = $this->Loader->substrAfterFirst($URLScanner['Class'], ':');
                            if (!$URLScanner['Class']) {
                                continue 2;
                            }
                            $URLScanner['Class'] = $this->getShorthand($URLScanner['Class']);
                            $this->detected($heur, $lnap, $URLScanner['Class'], $OriginalFilename, $OriginalFilenameSafe, $Out, $Flagged, $md5, $StringLength);
                        }
                        $this->Loader->InstanceCache['urlscanner_domains'] =
                            str_ireplace($URLHash . $URLScanner['Class'] . ';', '', $this->Loader->InstanceCache['urlscanner_domains']);
                    }
                    $URLScanner['req'] =
                        'v=' . $URLScanner['ScriptIdentEncoded'] .
                        '&s=' . $URLScanner['DomainParts'][$i] .
                        '&class=true';
                    $URLScanner['req_result'] = $this->Loader->request(
                        'https://verify.hosts-file.net/?' . $URLScanner['req'],
                        ['v' => $URLScanner['ScriptIdentEncoded'], 's' => $URLScanner['DomainParts'][$i], 'Class' => true],
                        12
                    );
                    $this->Loader->InstanceCache['LookupCount']++;
                    if (substr($URLScanner['req_result'], 0, 6) === 'Listed') {
                        $URLScanner['Class'] = substr($URLScanner['req_result'], 7, 3);
                        $URLScanner['Class'] = $URLScanner['classes'][$URLScanner['Class']] ?? "\x1a\x82\x10\x3fXXX";
                        $this->Loader->InstanceCache['urlscanner_domains'] .=
                            $URLHash .
                            $URLExpiry . ':' .
                            $URLScanner['Class'] . ';';
                        $URLScanner['Class'] = $this->getShorthand($URLScanner['Class']);
                        $this->detected($heur, $lnap, $URLScanner['Class'], $OriginalFilename, $OriginalFilenameSafe, $Out, $Flagged, $md5, $StringLength);
                    }
                    $this->Loader->InstanceCache['urlscanner_domains'] .= $URLScanner['Domains'][$i] . $URLExpiry . ':;';
                }
                $this->Loader->Cache->setEntry('urlscanner_domains', $this->Loader->InstanceCache['urlscanner_domains'], $URLExpiry);
            }

            $URLScanner['URLsCount'] = count($URLScanner['URLParts']);

            /** Codeblock for performing Google Safe Browsing API lookups. */
            if ($this->Loader->Configuration['urlscanner']['google_api_key'] && $URLScanner['URLsCount']) {
                $URLScanner['URLsChunked'] = ($URLScanner['URLsCount'] > 500) ? array_chunk($URLScanner['URLParts'], 500) : [$URLScanner['URLParts']];
                $URLScanner['URLChunks'] = count($URLScanner['URLsChunked']);
                for ($i = 0; $i < $URLScanner['URLChunks']; $i++) {

                    /** Maximum API lookups reached; abort accordingly. */
                    if (
                        $this->Loader->Configuration['urlscanner']['maximum_api_lookups'] > 0 &&
                        $this->Loader->InstanceCache['LookupCount'] > $this->Loader->Configuration['urlscanner']['maximum_api_lookups']
                    ) {
                        if ($this->Loader->Configuration['urlscanner']['maximum_api_lookups_response']) {
                            if (!$Flagged) {
                                $this->Loader->HashReference .= $sha256 . ':' . $StringLength . ':' . $OriginalFilename . "\n";
                                $Flagged = true;
                            }
                            $Out .= $lnap . sprintf(
                                    $this->Loader->L10N->getString('_exclamation_final'),
                                    $this->Loader->L10N->getString('too_many_urls')
                                ) . "\n";
                            $this->Loader->WhyFlagged .= sprintf(
                                $this->Loader->L10N->getString('_exclamation'),
                                $this->Loader->L10N->getString('too_many_urls') . ' (' . $OriginalFilenameSafe . ')'
                            );
                        }
                        break;
                    }

                    /** Perform safe browsing API lookup (v4). */
                    $URLScanner['SafeBrowseLookup'] = $this->safeBrowseLookup(
                        $URLScanner['URLsChunked'][$i],
                        $URLScanner['URLPartsNoLookup'],
                        $URLScanner['DomainPartsNoLookup']
                    );

                    /** Bad URLs found; Flag accordingly. */
                    if ($URLScanner['SafeBrowseLookup'] !== 204) {
                        if (!$Flagged) {
                            $this->Loader->HashReference .= $sha256 . ':' . $StringLength . ':' . $OriginalFilename . "\n";
                            $Flagged = true;
                        }
                        $URLScanner['L10N'] = $this->Loader->L10N->getString(
                            'SafeBrowseLookup_' . $URLScanner['SafeBrowseLookup']
                        ) ?: $this->Loader->L10N->getString('SafeBrowseLookup_999');
                        $Out .= $lnap . sprintf(
                                $this->Loader->L10N->getString('_exclamation_final'),
                                $URLScanner['L10N']
                            ) . "\n";
                        $this->Loader->WhyFlagged .= sprintf(
                            $this->Loader->L10N->getString('_exclamation'),
                            $URLScanner['L10N'] . ' (' . $OriginalFilenameSafe . ')'
                        );

                        /** Prevent further lookups in case of wrong API key used, malformed query, etc. */
                        if ($URLScanner['SafeBrowseLookup'] !== 200) {
                            break;
                        }
                    }
                }
            }
        }

        /** URL scanner data cleanup. */
        unset($URLScanner);

        /** Fire event: "afterURLScanner". */
        $this->Loader->Events->fireEvent('afterURLScanner');

        /** Fire event: "beforeChameleonDetections". */
        $this->Loader->Events->fireEvent('beforeChameleonDetections');

        /** PHP chameleon attack detection. */
        if ($this->Loader->Configuration['files']['chameleon_from_php']) {
            if ($this->containsMustAssert([
                    $this->Loader->Configuration['files']['can_contain_php_file_extensions'],
                    $this->Loader->Configuration['files']['archive_file_extensions']
                ], [$xts, $gzxts, $xt, $gzxt]) && strpos($str_hex_norm, '3c3f706870') !== false) {
                if (!$Flagged) {
                    $this->Loader->HashReference .= $sha256 . ':' . $StringLength . ':' . $OriginalFilename . "\n";
                    $Flagged = true;
                }
                $heur['detections']++;
                $this->Loader->InstanceCache['detections_count']++;
                $Out .= $lnap . sprintf(
                        $this->Loader->L10N->getString('_exclamation_final'),
                        sprintf($this->Loader->L10N->getString('scan_chameleon'), 'PHP')
                    ) . "\n";
                $this->Loader->WhyFlagged .= sprintf(
                    $this->Loader->L10N->getString('_exclamation'),
                    sprintf($this->Loader->L10N->getString('scan_chameleon'), 'PHP') . ' (' . $OriginalFilenameSafe . ')'
                );
            }
        }

        /** Executable chameleon attack detection. */
        if ($this->Loader->Configuration['files']['chameleon_from_exe']) {
            $Chameleon = '';
            if (strpos(',acm,ax,com,cpl,dll,drv,exe,ocx,rs,scr,sys,', ',' . $xt . ',') !== false) {
                if ($twocc !== '4d5a') {
                    $Chameleon = 'EXE';
                }
            } elseif ($twocc === '4d5a') {
                $Chameleon = 'EXE';
            }
            if ($xt === 'elf') {
                if ($fourcc !== '7f454c46') {
                    $Chameleon = 'ELF';
                }
            } elseif ($fourcc === '7f454c46') {
                $Chameleon = 'ELF';
            }
            if ($xt === 'lnk') {
                if (substr($str_hex, 0, 16) !== '4c00000001140200') {
                    $Chameleon = 'LNK';
                }
            } elseif (substr($str_hex, 0, 16) === '4c00000001140200') {
                $Chameleon = 'LNK';
            }
            if ($xt === 'msi' && substr($str_hex, 0, 16) !== 'd0cf11e0a1b11ae1') {
                $Chameleon = 'MSI';
            }
            if ($Chameleon) {
                if (!$Flagged) {
                    $this->Loader->HashReference .= $sha256 . ':' . $StringLength . ':' . $OriginalFilename . "\n";
                    $Flagged = true;
                }
                $heur['detections']++;
                $this->Loader->InstanceCache['detections_count']++;
                $Out .= $lnap . sprintf(
                        $this->Loader->L10N->getString('_exclamation_final'),
                        sprintf($this->Loader->L10N->getString('scan_chameleon'), $Chameleon)
                    ) . "\n";
                $this->Loader->WhyFlagged .= sprintf(
                    $this->Loader->L10N->getString('_exclamation'),
                    sprintf($this->Loader->L10N->getString('scan_chameleon'), $Chameleon) . ' (' . $OriginalFilenameSafe . ')'
                );
            }
        }

        /** Archive chameleon attack detection. */
        if ($this->Loader->Configuration['files']['chameleon_to_archive']) {
            $Chameleon = '';
            if ($xts === 'zip*' && $twocc !== '504b') {
                $Chameleon = 'Zip';
            } elseif ($xt === 'rar' && ($fourcc !== '52617221' && $fourcc !== '52457e5e')) {
                $Chameleon = 'Rar';
            } elseif ($xt === 'gz' && $twocc !== '1f8b') {
                $Chameleon = 'Gzip';
            } elseif ($xt === 'bz2' && substr($str_hex, 0, 6) !== '425a68') {
                $Chameleon = 'Bzip2';
            }
            if ($Chameleon) {
                if (!$Flagged) {
                    $this->Loader->HashReference .= $sha256 . ':' . $StringLength . ':' . $OriginalFilename . "\n";
                    $Flagged = true;
                }
                $heur['detections']++;
                $this->Loader->InstanceCache['detections_count']++;
                $Out .= $lnap . sprintf(
                        $this->Loader->L10N->getString('_exclamation_final'),
                        sprintf($this->Loader->L10N->getString('scan_chameleon'), $Chameleon)
                    ) . "\n";
                $this->Loader->WhyFlagged .= sprintf(
                    $this->Loader->L10N->getString('_exclamation'),
                    sprintf($this->Loader->L10N->getString('scan_chameleon'), $Chameleon) . ' (' . $OriginalFilenameSafe . ')'
                );
            }
        }

        /** Office document chameleon attack detection. */
        if ($this->Loader->Configuration['files']['chameleon_to_doc']) {
            if (strpos(',doc,dot,pps,ppt,xla,xls,wiz,', ',' . $xt . ',') !== false) {
                if ($fourcc !== 'd0cf11e0') {
                    if (!$Flagged) {
                        $this->Loader->HashReference .= $sha256 . ':' . $StringLength . ':' . $OriginalFilename . "\n";
                        $Flagged = true;
                    }
                    $heur['detections']++;
                    $this->Loader->InstanceCache['detections_count']++;
                    $Out .= $lnap . sprintf(
                            $this->Loader->L10N->getString('_exclamation_final'),
                            sprintf($this->Loader->L10N->getString('scan_chameleon'), 'Office')
                        ) . "\n";
                    $this->Loader->WhyFlagged .= sprintf(
                        $this->Loader->L10N->getString('_exclamation'),
                        sprintf($this->Loader->L10N->getString('scan_chameleon'), 'Office') . ' (' . $OriginalFilenameSafe . ')'
                    );
                }
            }
        }

        /** Image chameleon attack detection. */
        if ($this->Loader->Configuration['files']['chameleon_to_img']) {
            $Chameleon = '';
            if (
                (($xt === 'bmp' || $xt === 'dib') && $twocc !== '424d') ||
                ($xt === 'gif' && (substr($str_hex, 0, 12) !== '474946383761' && substr($str_hex, 0, 12) !== '474946383961')) ||
                (preg_match('~j(?:fif?|if|peg?|pg)~', $xt) && substr($str_hex, 0, 6) !== 'ffd8ff') ||
                ($xt === 'jp2' && substr($str_hex, 0, 16) !== '0000000c6a502020') ||
                (($xt === 'pdd' || $xt === 'psd') && $fourcc !== '38425053') ||
                ($xt === 'png' && $fourcc !== '89504e47') ||
                ($xt === 'webp' && ($fourcc !== '52494646' || substr($str, 8, 4) !== 'WEBP')) ||
                ($xt === 'xcf' && substr($str, 0, 8) !== 'gimp xcf')
            ) {
                if (!$Flagged) {
                    $this->Loader->HashReference .= $sha256 . ':' . $StringLength . ':' . $OriginalFilename . "\n";
                    $Flagged = true;
                }
                $heur['detections']++;
                $this->Loader->InstanceCache['detections_count']++;
                $Out .= $lnap . sprintf(
                        $this->Loader->L10N->getString('_exclamation_final'),
                        sprintf($this->Loader->L10N->getString('scan_chameleon'), $this->Loader->L10N->getString('image'))
                    ) . "\n";
                $this->Loader->WhyFlagged .= sprintf(
                    $this->Loader->L10N->getString('_exclamation'),
                    sprintf($this->Loader->L10N->getString('scan_chameleon'), $this->Loader->L10N->getString('image')) . ' (' . $OriginalFilenameSafe . ')'
                );
            }
        }

        /** PDF chameleon attack detection. */
        if ($this->Loader->Configuration['files']['chameleon_to_pdf']) {
            if ($xt === 'pdf' && !$pdf_magic) {
                if (!$Flagged) {
                    $this->Loader->HashReference .= $sha256 . ':' . $StringLength . ':' . $OriginalFilename . "\n";
                    $Flagged = true;
                }
                $heur['detections']++;
                $this->Loader->InstanceCache['detections_count']++;
                $Out .= $lnap . sprintf(
                        $this->Loader->L10N->getString('_exclamation_final'),
                        sprintf($this->Loader->L10N->getString('scan_chameleon'), 'PDF')
                    ) . "\n";
                $this->Loader->WhyFlagged .= sprintf(
                    $this->Loader->L10N->getString('_exclamation'),
                    sprintf($this->Loader->L10N->getString('scan_chameleon'), 'PDF') . ' (' . $OriginalFilenameSafe . ')'
                );
            }
        }

        /** Fire event: "afterChameleonDetections". */
        $this->Loader->Events->fireEvent('afterChameleonDetections');

        /** Control character detection. */
        if ($this->Loader->Configuration['files']['block_control_characters']) {
            if (preg_match('/[\x00-\x08\x0b\x0c\x0e\x1f\x7f]/i', $str)) {
                $Out .= $lnap . sprintf(
                        $this->Loader->L10N->getString('_exclamation'),
                        $this->Loader->L10N->getString('detected_control_characters')
                    ) . "\n";
                $heur['detections']++;
                $this->Loader->InstanceCache['detections_count']++;
                if (!$Flagged) {
                    $this->Loader->HashReference .= $sha256 . ':' . $StringLength . ':' . $OriginalFilename . "\n";
                    $Flagged = true;
                }
                $this->Loader->WhyFlagged .= sprintf(
                    $this->Loader->L10N->getString('_exclamation'),
                    $this->Loader->L10N->getString('detected_control_characters') . ' (' . $OriginalFilenameSafe . ')'
                );
            }
        }

        /**
         * If the heuristic weight of the current scan iteration exceeds the
         * heuristic threshold defined by the configuration, or if outs has already
         * been filled, dump all heuristic detections and non-heuristic detections
         * together into outs and regard the iteration as flagged.
         */
        if (
            $heur['weight'] >= $this->Loader->Configuration['signatures']['heuristic_threshold'] ||
            $Out
        ) {
            $Out .= $heur['cli'];
            $this->Loader->WhyFlagged .= $heur['web'];
        }

        /** Fire event: "beforeVirusTotal". */
        $this->Loader->Events->fireEvent('beforeVirusTotal');

        /** Virus Total API integration. */
        if (
            !$Out &&
            !empty($this->Loader->Configuration['virustotal']['vt_public_api_key'])
        ) {
            $DoScan = false;
            $this->Loader->Configuration['virustotal']['vt_suspicion_level'] =
                (int)$this->Loader->Configuration['virustotal']['vt_suspicion_level'];
            if ($this->Loader->Configuration['virustotal']['vt_suspicion_level'] === 0) {
                $DoScan = ($heur['weight'] > 0);
            } elseif ($this->Loader->Configuration['virustotal']['vt_suspicion_level'] === 1) {
                $DoScan = ($heur['weight'] > 0 ||
                    $is_pe ||
                    $fileswitch === 'chrome' ||
                    $fileswitch === 'java' ||
                    $fileswitch === 'docfile' ||
                    $fileswitch === 'vt_interest');
            } elseif ($this->Loader->Configuration['virustotal']['vt_suspicion_level'] === 2) {
                $DoScan = true;
            }
            if ($DoScan) {
                $VTWeight = ['weight' => 0, 'cli' => '', 'web' => ''];
                if (!isset($this->Loader->InstanceCache['vt_quota'])) {
                    $this->Loader->InstanceCache['vt_quota'] = $this->Loader->Cache->getEntry('vt_quota');
                }
                $x = 0;
                if (!empty($this->Loader->InstanceCache['vt_quota'])) {
                    $this->Loader->InstanceCache['vt_quota'] = explode(';', $this->Loader->InstanceCache['vt_quota']);
                    foreach ($this->Loader->InstanceCache['vt_quota'] as &$Quota) {
                        if ($Quota > $this->Loader->Time) {
                            $x++;
                        } else {
                            $Quota = '';
                        }
                    }
                    unset($Quota);
                    $this->Loader->InstanceCache['vt_quota'] =
                        implode(';', $this->Loader->InstanceCache['vt_quota']);
                }
                if ($x < $this->Loader->Configuration['virustotal']['vt_quota_rate']) {
                    $VTParams = [
                        'apikey' => $this->Loader->Configuration['virustotal']['vt_public_api_key'],
                        'resource' => $md5
                    ];
                    $VTRequest = $this->Loader->request(
                        'https://www.virustotal.com/vtapi/v2/file/report?apikey=' .
                        urlencode($this->Loader->Configuration['virustotal']['vt_public_api_key']) .
                        '&resource=' . $md5,
                        $VTParams,
                        12
                    );
                    $VTJSON = json_decode($VTRequest, true);
                    $y = $this->Loader->Time + ($this->Loader->Configuration['virustotal']['vt_quota_time'] * 60);
                    $this->Loader->InstanceCache['vt_quota'] .= $y . ';';
                    while (substr_count($this->Loader->InstanceCache['vt_quota'], ';;')) {
                        $this->Loader->InstanceCache['vt_quota'] = str_ireplace(';;', ';', $this->Loader->InstanceCache['vt_quota']);
                    }
                    $this->Loader->Cache->setEntry('vt_quota', $this->Loader->InstanceCache['vt_quota'], $y + 60);
                    if (isset($VTJSON['response_code'])) {
                        $VTJSON['response_code'] = (int)$VTJSON['response_code'];
                        if (
                            isset($VTJSON['scans']) &&
                            $VTJSON['response_code'] === 1 &&
                            is_array($VTJSON['scans'])
                        ) {
                            foreach ($VTJSON['scans'] as $VTKey => $VTValue) {
                                if ($VTValue['detected'] && $VTValue['result']) {
                                    $VN = $VTKey . '(VirusTotal)-' . $VTValue['result'];
                                    if (
                                        strpos($this->Loader->InstanceCache['Greylist'], ',' . $VN . ',') === false &&
                                        empty($this->Loader->InstanceCache['ignoreme'])
                                    ) {
                                        if (!$Flagged) {
                                            $this->Loader->HashReference .= $sha256 . ':' . $StringLength . ':' . $OriginalFilename . "\n";
                                            $Flagged = true;
                                        }
                                        $heur['detections']++;
                                        $this->Loader->InstanceCache['detections_count']++;
                                        if ($this->Loader->Configuration['virustotal']['vt_weighting'] > 0) {
                                            $VTWeight['weight']++;
                                            $VTWeight['web'] .= $lnap . sprintf(
                                                    $this->Loader->L10N->getString('_exclamation'),
                                                    sprintf($this->Loader->L10N->getString('detected'), $VN)
                                                ) . "\n";
                                            $VTWeight['cli'] .= sprintf(
                                                $this->Loader->L10N->getString('_exclamation'),
                                                sprintf($this->Loader->L10N->getString('detected'), $VN) . ' (' . $OriginalFilenameSafe . ')'
                                            );
                                        } else {
                                            $Out .= $lnap . sprintf(
                                                    $this->Loader->L10N->getString('_exclamation_final'),
                                                    sprintf($this->Loader->L10N->getString('detected'), $VN)
                                                ) . "\n";
                                            $this->Loader->WhyFlagged .= sprintf(
                                                $this->Loader->L10N->getString('_exclamation'),
                                                sprintf($this->Loader->L10N->getString('detected'), $VN) . ' (' . $OriginalFilenameSafe . ')'
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                    if (
                        $VTWeight['weight'] > 0 &&
                        $VTWeight['weight'] >= $this->Loader->Configuration['virustotal']['vt_weighting']
                    ) {
                        $Out .= $VTWeight['web'];
                        $this->Loader->WhyFlagged .= $VTWeight['cli'];
                    }
                }
            }
        }

        /** Fire event: "afterVirusTotal". */
        $this->Loader->Events->fireEvent('afterVirusTotal');

        /** Add hash cache entry. */
        if (!empty($HashCacheID)) {
            /** 0: (int) {-4...2}; 1: For CLI+API; 2: For Web. */
            $HashCacheEntry = json_encode([!$Out ? 1 : 2, $Out, $this->Loader->WhyFlagged]);
            $this->Loader->Cache->setEntry($HashCacheID, $HashCacheEntry, $this->Loader->Configuration['core']['scan_cache_expiry']);
        }

        /** Set final debug values, if this has been enabled. */
        if (isset($this->debugArr, $this->Loader->InstanceCache['DebugArrKey'])) {
            $this->debugArr[$this->Loader->InstanceCache['DebugArrKey']]['Results'] = !$Out ? 1 : 2;
            $this->debugArr[$this->Loader->InstanceCache['DebugArrKey']]['Output'] = $Out;
        }

        /** Register object flagged. */
        if ($Out) {
            $this->statsIncrement($this->CalledFrom === 'Web' ? 'Web-Blocked' : ($this->CalledFrom === 'CLI' ? 'CLI-Flagged' : 'API-Flagged'), 1);
        }

        /** Exit data handler. */
        return !$Out ? [1, ''] : [2, $Out];
    }

    /**
     * Archive recursor.
     *
     * This is where we recurse through archives during the scan.
     *
     * @param string $x Scan results inherited from parent in the form of a string.
     * @param int $Results Scan results inherited from parent in the form of an integer.
     * @param string $Data The data to be scanned (preferably an archive).
     * @param string $File A path to the file, to be able to access it directly if
     *      needed (because the zip and rar classes require a file pointer).
     * @param int $ScanDepth The current scan depth (supplied during recursion).
     * @param string $ItemRef A reference to the parent container (for logging).
     * @throws Exception if the metadata scanner throws an exception (forwarded on).
     */
    public function archiveRecursor(string &$x, int &$Results, string $Data, string $File = '', int $ScanDepth = 0, string $ItemRef = '')
    {
        /** Fire event: "atStartOf_archiveRecursor". */
        $this->Loader->Events->fireEvent('atStartOf_archiveRecursor');

        /** Create quine detection array. */
        if (!$ScanDepth || !isset($this->Loader->InstanceCache['Quine'])) {
            $this->Loader->InstanceCache['Quine'] = [];
        }

        /** Count recursion depth. */
        $ScanDepth++;

        /** Used for CLI and logging. */
        $Indent = str_pad('> ', $ScanDepth + 1, '-', STR_PAD_LEFT);

        /** Reset container definition. */
        $this->Loader->InstanceCache['container'] = 'none';

        /** The class to use to handle the data to be scanned. */
        $Handler = '';

        /** The type of container to be scanned (mostly just for logging). */
        $ConType = '';

        /** Check whether Crx, and convert if necessary. */
        if ($this->convertCrx($Data)) {

            /** Reset the file pointer (because the content has been modified anyway). */
            $File = '';
        }

        /** Get file extensions. */
        [$xt, $xts, $gzxt, $gzxts] = $this->fetchExtension($ItemRef);

        /** Set appropriate container definitions and specify handler class. */
        if (substr($Data, 0, 2) === 'PK') {
            $Handler = 'ZipHandler';
            if ($xt === 'ole') {
                $ConType = 'OLE';
            } elseif ($xt === 'crx') {
                $ConType = 'Crx';
            } elseif ($xt === 'smpk') {
                $ConType = 'SMPTE';
            } elseif ($xt === 'xpi') {
                $ConType = 'XPInstall';
            } elseif ($xts === 'app*') {
                $ConType = 'App';
            } elseif (strpos(
                    ',docm,docx,dotm,dotx,potm,potx,ppam,ppsm,ppsx,pptm,pptx,xlam,xlsb,xlsm,xlsx,xltm,xltx,',
                    ',' . $xt . ','
                ) !== false) {
                $ConType = 'OpenXML';
            } elseif (strpos(
                    ',odc,odf,odg,odm,odp,ods,odt,otg,oth,otp,ots,ott,',
                    ',' . $xt . ','
                ) !== false || $xts === 'fod*') {
                $ConType = 'OpenDocument';
            } elseif (strpos(',opf,epub,', ',' . $xt . ',') !== false) {
                $ConType = 'EPUB';
            } else {
                $ConType = 'ZIP';
                $this->Loader->InstanceCache['container'] = 'zipfile';
            }
            if ($ConType !== 'ZIP') {
                $this->Loader->InstanceCache['file_is_ole'] = true;
                $this->Loader->InstanceCache['container'] = 'pkfile';
            }
        } elseif (
            substr($Data, 257, 6) === "ustar\x00" ||
            strpos(',tar,tgz,tbz,tlz,tz,', ',' . $xt . ',') !== false
        ) {
            $Handler = 'TarHandler';
            $ConType = 'TarFile';
            $this->Loader->InstanceCache['container'] = 'tarfile';
        } elseif (substr($Data, 0, 4) === 'Rar!' || substr($Data, 0, 4) === "\x52\x45\x7e\x5e") {
            $Handler = 'RarHandler';
            $ConType = 'RarFile';
            $this->Loader->InstanceCache['container'] = 'rarfile';
        }

        /** Not an archive. Exit early. */
        if (!$Handler) {
            return;
        }

        /** Hash the current input data. */
        $DataHash = hash('sha256', $Data);

        /** Fetch length of current input data. */
        $DataLen = strlen($Data);

        /** Handle zip files. */
        if ($Handler === 'ZipHandler') {

            /**
             * Encryption guard.
             * @link https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT
             */
            if ($this->Loader->Configuration['files']['block_encrypted_archives']) {
                $Bits = $this->explodeBits(substr($Data, 6, 2));
                if ($Bits && $Bits[7]) {
                    $Results = -4;
                    $this->Loader->HashReference .= $DataHash . ':' . $DataLen . ':' . $ItemRef . "\n";
                    $this->Loader->WhyFlagged .= sprintf(
                        $this->Loader->L10N->getString('_exclamation'),
                        $this->Loader->L10N->getString('encrypted_archive') . ' (' . $ItemRef . ')'
                    );
                    $x .= sprintf(
                        '-%1$s%2$s \'%3$s\' (FN: %4$s; FD: %5$s):%6$s--%1$s%7$s%8$s%6$s',
                        $Indent,
                        $this->Loader->L10N->getString('scan_checking'),
                        $ItemRef,
                        hash('crc32b', $File),
                        hash('crc32b', $Data),
                        "\n",
                        $this->Loader->L10N->getString('encrypted_archive'),
                        $this->Loader->L10N->getString('_fullstop_final')
                    );
                    return;
                }
            }

            /** Guard. */
            if (!class_exists('ZipArchive')) {
                if (!$this->Loader->Configuration['signatures']['fail_extensions_silently']) {
                    $Results = -1;
                    $this->Loader->HashReference .= $DataHash . ':' . $DataLen . ':' . $ItemRef . "\n";
                    $this->Loader->WhyFlagged .= $this->Loader->L10N->getString('scan_extensions_missing') . ' (Zip)';
                    $x .= sprintf(
                        '-%1$s%2$s \'%3$s\' (FN: %4$s; FD: %5$s):%6$s--%1$s%7$s%6$s',
                        $Indent,
                        $this->Loader->L10N->getString('scan_checking'),
                        $ItemRef,
                        hash('crc32b', $File),
                        hash('crc32b', $Data),
                        "\n",
                        $this->Loader->L10N->getString('scan_extensions_missing') . ' (Zip)'
                    );
                    return;
                }
            }

            /** ZipHandler needs a file pointer. */
            if (!$File || !is_readable($File)) {

                /**
                 * File pointer not available. Probably already inside an
                 * archive. Let's create a temporary file for this.
                 */
                $PointerObject = new TemporaryFileHandler($Data, $this->Loader->CachePath);
                $Pointer = &$PointerObject->Filename;
                $this->Loader->InstanceCache['tempfilesToDelete'][] = $Pointer;
            } else {

                /** File pointer available. Let's reference it. */
                $Pointer = &$File;
            }

            /** We have a valid a pointer. Let's instantiate the object. */
            if ($Pointer) {
                $ArchiveObject = new ZipHandler($Pointer);
            }
        }

        /** Handle tar files. */
        if ($Handler === 'TarHandler') {

            /** TarHandler can work with data directly. */
            $ArchiveObject = new TarHandler($Data);
        }

        /** Handle rar files. */
        if ($Handler === 'RarHandler') {

            /** Guard. */
            if (!class_exists('RarArchive') || !class_exists('RarEntry')) {
                if (!$this->Loader->Configuration['signatures']['fail_extensions_silently']) {
                    $Results = -1;
                    $this->Loader->HashReference .= $DataHash . ':' . $DataLen . ':' . $ItemRef . "\n";
                    $this->Loader->WhyFlagged .= $this->Loader->L10N->getString('scan_extensions_missing') . ' (Rar)';
                    $x .= sprintf(
                        '-%1$s%2$s \'%3$s\' (FN: %4$s; FD: %5$s):%6$s--%1$s%7$s%6$s',
                        $Indent,
                        $this->Loader->L10N->getString('scan_checking'),
                        $ItemRef,
                        hash('crc32b', $File),
                        hash('crc32b', $Data),
                        "\n",
                        $this->Loader->L10N->getString('scan_extensions_missing') . ' (Rar)'
                    );
                    return;
                }
            }

            /** RarHandler needs a file pointer. */
            if (!$File || !is_readable($File)) {

                /**
                 * File pointer not available. Probably already inside an
                 * archive. Let's create a temporary file for this.
                 */
                $PointerObject = new TemporaryFileHandler($Data, $this->Loader->CachePath);
                $Pointer = &$PointerObject->Filename;
                $this->Loader->InstanceCache['tempfilesToDelete'][] = $Pointer;
            } else {

                /** File pointer available. Let's reference it. */
                $Pointer = &$File;
            }

            /** We have a valid a pointer. Let's instantiate the object. */
            if ($Pointer) {
                $ArchiveObject = new RarHandler($Pointer);
            }
        }

        /** Archive object has been instantiated. Let's proceed. */
        if (isset($ArchiveObject) && is_object($ArchiveObject)) {

            /** No errors reported. Let's try checking its contents. */
            if ($ArchiveObject->ErrorState === 0) {

                /** Used to count the number of entries processed. */
                $Processed = 0;

                /** Iterate through the archive's contents. */
                while ($ArchiveObject->EntryNext()) {

                    /** Flag the archive if it exceeds the "max_files_in_archives" limit and return. */
                    if (
                        $this->Loader->Configuration['files']['max_files_in_archives'] > 0 &&
                        $Processed > $this->Loader->Configuration['files']['max_files_in_archives']
                    ) {
                        $Results = 2;
                        $this->Loader->HashReference .= $DataHash . ':' . $DataLen . ':' . $ItemRef . "\n";
                        $this->Loader->WhyFlagged .= sprintf(
                            $this->Loader->L10N->getString('_exclamation'),
                            $this->Loader->L10N->getString('too_many_files_in_archive') . ' (' . $ItemRef . ')'
                        );
                        $x .= sprintf(
                            '-%1$s%2$s \'%3$s\' (FN: %4$s; FD: %5$s):%6$s--%1$s%7$s%8$s%6$s',
                            $Indent,
                            $this->Loader->L10N->getString('scan_checking'),
                            $ItemRef,
                            hash('crc32b', $File),
                            hash('crc32b', $Data),
                            "\n",
                            $this->Loader->L10N->getString('too_many_files_in_archive'),
                            $this->Loader->L10N->getString('_fullstop_final')
                        );
                        unset($ArchiveObject, $Pointer, $PointerObject);
                        return;
                    }

                    $Processed++;

                    /** Encryption guard. */
                    if ($this->Loader->Configuration['files']['block_encrypted_archives'] && $ArchiveObject->EntryIsEncrypted()) {
                        $Results = -4;
                        $this->Loader->HashReference .= $DataHash . ':' . $DataLen . ':' . $ItemRef . "\n";
                        $this->Loader->WhyFlagged .= sprintf(
                            $this->Loader->L10N->getString('_exclamation'),
                            $this->Loader->L10N->getString('encrypted_archive') . ' (' . $ItemRef . ')'
                        );
                        $x .= sprintf(
                            '-%1$s%2$s \'%3$s\' (FN: %4$s; FD: %5$s):%6$s--%1$s%7$s%8$s%6$s',
                            $Indent,
                            $this->Loader->L10N->getString('scan_checking'),
                            $ItemRef,
                            hash('crc32b', $File),
                            hash('crc32b', $Data),
                            "\n",
                            $this->Loader->L10N->getString('encrypted_archive'),
                            $this->Loader->L10N->getString('_fullstop_final')
                        );
                        unset($ArchiveObject, $Pointer, $PointerObject);
                        return;
                    }

                    /** Fetch and prepare filename. */
                    if ($Filename = $ArchiveObject->EntryName()) {
                        if (strpos($Filename, "\\") !== false) {
                            $Filename = $this->Loader->substrAfterLast($Filename, "\\");
                        }
                        if (strpos($Filename, '/') !== false) {
                            $Filename = $this->Loader->substrAfterLast($Filename, '/');
                        }
                    }

                    /** Fetch filesize. */
                    $Filesize = $ArchiveObject->EntryActualSize();

                    /** Fetch content and build hashes. */
                    $Content = $ArchiveObject->EntryRead($Filesize);
                    $Hash = hash('sha256', $Content);
                    $NameCRC32 = hash('crc32b', $Filename);
                    $DataCRC32 = hash('crc32b', $Content);
                    $InternalCRC = $ArchiveObject->EntryCRC();
                    $ThisItemRef = $ItemRef . '>' . urlencode($Filename);

                    /** Verify filesize, integrity, etc. Exit early in case of problems. */
                    if ($Filesize !== strlen($Content) || ($InternalCRC &&
                            preg_replace('~^0+~', '', $DataCRC32) !== preg_replace('~^0+~', '', $InternalCRC))) {
                        $Results = 2;
                        $this->Loader->HashReference .= $Hash . ':' . $Filesize . ':' . $ThisItemRef . "\n";
                        $this->Loader->WhyFlagged .= sprintf(
                            $this->Loader->L10N->getString('_exclamation'),
                            $this->Loader->L10N->getString('scan_tampering') . ' (' . $ThisItemRef . ')'
                        );
                        $x .= sprintf(
                            '-%1$s%2$s \'%3$s\' (FN: %4$s; FD: %5$s):%6$s--%1$s%7$s%8$s%6$s',
                            $Indent,
                            $this->Loader->L10N->getString('scan_checking'),
                            $ThisItemRef,
                            $NameCRC32,
                            $DataCRC32,
                            "\n",
                            $this->Loader->L10N->getString('recursive'),
                            $this->Loader->L10N->getString('_fullstop_final')
                        );
                        unset($ArchiveObject, $Pointer, $PointerObject);
                        return;
                    }

                    /** Executed if the recursion depth limit has been exceeded. */
                    if ($ScanDepth > $this->Loader->Configuration['files']['max_recursion']) {
                        $Results = 2;
                        $this->Loader->HashReference .= $Hash . ':' . $Filesize . ':' . $ThisItemRef . "\n";
                        $this->Loader->WhyFlagged .= sprintf(
                            $this->Loader->L10N->getString('_exclamation'),
                            $this->Loader->L10N->getString('recursive') . ' (' . $ThisItemRef . ')'
                        );
                        $x .= sprintf(
                            '-%1$s%2$s \'%3$s\' (FN: %4$s; FD: %5$s):%6$s--%1$s%7$s%8$s%6$s',
                            $Indent,
                            $this->Loader->L10N->getString('scan_checking'),
                            $ThisItemRef,
                            $NameCRC32,
                            $DataCRC32,
                            "\n",
                            $this->Loader->L10N->getString('recursive'),
                            $this->Loader->L10N->getString('_fullstop_final')
                        );
                        unset($ArchiveObject, $Pointer, $PointerObject);
                        return;
                    }

                    /** Quine detection. */
                    if ($this->quineDetector($ScanDepth, $DataHash, $DataLen, $Hash, $Filesize)) {
                        $Results = 2;
                        $this->Loader->HashReference .= $Hash . ':' . $Filesize . ':' . $ThisItemRef . "\n";
                        $this->Loader->WhyFlagged .= sprintf(
                            $this->Loader->L10N->getString('_exclamation'),
                            sprintf($this->Loader->L10N->getString('detected'), 'Quine') . ' (' . $ThisItemRef . ')'
                        );
                        $x .= sprintf(
                            '-%1$s%2$s \'%3$s\' (FN: %4$s; FD: %5$s):%6$s--%1$s%7$s%8$s%6$s',
                            $Indent,
                            $this->Loader->L10N->getString('scan_checking'),
                            $ThisItemRef,
                            $NameCRC32,
                            $DataCRC32,
                            "\n",
                            sprintf($this->Loader->L10N->getString('detected'), 'Quine'),
                            $this->Loader->L10N->getString('_fullstop_final')
                        );
                        unset($ArchiveObject, $Pointer, $PointerObject);
                        return;
                    }

                    /** Ready to check the entry. */
                    $x .= sprintf(
                        '-%1$s%2$s \'%3$s\' (FN: %4$s; FD: %5$s):%6$s',
                        $Indent,
                        $this->Loader->L10N->getString('scan_checking'),
                        $ThisItemRef,
                        $NameCRC32,
                        $DataCRC32,
                        "\n"
                    );

                    /** Scan the entry. */
                    try {
                        $this->metaDataScan(
                            $x,
                            $Results,
                            '--' . $Indent,
                            $ThisItemRef,
                            $Filename,
                            $Content,
                            $ScanDepth,
                            $Hash
                        );
                    } catch (\Exception $e) {
                        unset($ArchiveObject, $Pointer, $PointerObject);
                        throw new \Exception($e->getMessage());
                    }

                    /** If we've already found something bad, we can exit early to save time. */
                    if ($Results !== 1) {
                        unset($ArchiveObject, $Pointer, $PointerObject);
                        return;
                    }

                    /** Finally, check whether the archive entry is an archive. */
                    $this->archiveRecursor($x, $Results, $Content, '', $ScanDepth, $ThisItemRef);
                }
            }
        }

        /** Unset order is important for temporary files to be able to be deleted properly. */
        unset($ArchiveObject, $Pointer, $PointerObject);
    }

    /**
     * Initialise statistics if they've been enabled.
     */
    public function statsInitialise()
    {
        /** Guard. */
        if (!$this->Loader->Configuration['core']['statistics']) {
            return;
        }

        $this->Loader->InstanceCache['StatisticsModified'] = false;
        if ($this->Loader->InstanceCache['Statistics'] = ($this->Loader->Cache->getEntry('Statistics') ?: [])) {
            if (is_string($this->Loader->InstanceCache['Statistics'])) {
                unserialize($this->Loader->InstanceCache['Statistics']) ?: [];
            }
        }
        if (empty($this->Loader->InstanceCache['Statistics']['Other-Since'])) {
            $this->Loader->InstanceCache['Statistics'] = [
                'Other-Since' => $this->Loader->Time,
                'Web-Events' => 0,
                'Web-Scanned' => 0,
                'Web-Blocked' => 0,
                'Web-Quarantined' => 0,
                'CLI-Events' => 0,
                'CLI-Scanned' => 0,
                'CLI-Flagged' => 0,
                'API-Events' => 0,
                'API-Scanned' => 0,
                'API-Flagged' => 0
            ];
            $this->Loader->InstanceCache['StatisticsModified'] = true;
        }
    }

    /**
     * Increments statistics if they've been enabled.
     *
     * @param string $Statistic The statistic to increment.
     * @param int $Amount The amount to increment it by.
     */
    public function statsIncrement(string $Statistic, int $Amount)
    {
        /** Guard. */
        if (!$this->Loader->Configuration['core']['statistics'] || !isset($this->Loader->InstanceCache['Statistics'][$Statistic])) {
            return;
        }

        $this->Loader->InstanceCache['Statistics'][$Statistic] += $Amount;
        $this->Loader->InstanceCache['StatisticsModified'] = true;
    }

    /**
     * Fetch information about signature files for the scan process.
     */
    private function organiseSigFiles()
    {
        /** Guard. */
        if (empty($this->Loader->Configuration['signatures']['active']) || !$this->Loader->SignaturesPath) {
            return;
        }

        /** Supported signature file classes. */
        $Classes = [
            'General_Command_Detections',
            'Filename',
            'Hash',
            'Standard',
            'Standard_RegEx',
            'Normalised',
            'Normalised_RegEx',
            'HTML',
            'HTML_RegEx',
            'PE_Extended',
            'PE_Sectional',
            'Complex_Extended',
            'URL_Scanner'
        ];

        foreach (explode(',', $this->Loader->Configuration['signatures']['active']) as $File) {
            $File = (strpos($File, ':') === false) ? $File : substr($File, strpos($File, ':') + 1);
            $Handle = fopen($this->Loader->SignaturesPath . $File, 'rb');
            if (fread($Handle, 9) !== 'phpMussel') {
                fclose($Handle);
                continue;
            }
            $Class = fread($Handle, 1);
            fclose($Handle);
            $Nibbles = $this->splitNibble($Class);
            if (!empty($Classes[$Nibbles[0]])) {
                if (!isset($this->Loader->InstanceCache[$Classes[$Nibbles[0]]])) {
                    $this->Loader->InstanceCache[$Classes[$Nibbles[0]]] = ',';
                }
                $this->Loader->InstanceCache[$Classes[$Nibbles[0]]] .= $File . ',';
            }
        }
    }

    /**
     * Implodes multidimensional arrays.
     *
     * @param array $Arr An array to implode.
     * @return string The imploded array.
     */
    public function implodeMd(array $Arr): string
    {
        foreach ($Arr as &$Key) {
            if (is_array($Key)) {
                $Key = $this->implodeMd($Key);
            }
        }
        return implode($Arr);
    }

    /**
     * Does some simple decoding work on strings.
     *
     * @param string $str The string to be decoded.
     * @return string The decoded string.
     */
    public function prescanDecode(string $str): string
    {
        $nstr = html_entity_decode(urldecode(str_ireplace('&amp;#', '&#', str_ireplace('&amp;amp;', '&amp;', $str))));
        if ($nstr !== $str) {
            $nstr = $this->prescanDecode($nstr);
        }
        return $nstr;
    }

    /**
     * Uses iterators to generate an array of the contents of a specified directory.
     *
     * @param string $Base Directory root.
     * @return array Directory tree.
     */
    public function directoryRecursiveList(string $Base): array
    {
        $Arr = [];
        $Offset = strlen($Base);
        $List = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($Base), \RecursiveIteratorIterator::SELF_FIRST);
        foreach ($List as $Item => $List) {
            if (preg_match('~^(?:/\.\.|./\.|\.{3})$~', str_replace("\\", '/', substr($Item, -3))) || !is_readable($Item)) {
                continue;
            }
            $Arr[] = substr($Item, $Offset);
        }
        return $Arr;
    }

    /**
     * Fetches extensions data from filenames.
     *
     * @param string $OriginalFilename The original filename.
     * @return array The extensions data.
     */
    public function fetchExtension(string $OriginalFilename): array
    {
        $decPos = strrpos($OriginalFilename, '.');
        $OriginalFilenameLen = strlen($OriginalFilename);
        if ($decPos === false || $decPos === ($OriginalFilenameLen - 1)) {
            return ['-', '-', '-', '-'];
        }
        $xt = strtolower(substr($OriginalFilename, ($decPos + 1)));
        $xts = substr($xt, 0, 3) . '*';
        if (strtolower(substr($OriginalFilename, -3)) === '.gz') {
            $OriginalFilenameNoGZ = substr($OriginalFilename, 0, ($OriginalFilenameLen - 3));
            $decPosNoGZ = strrpos($OriginalFilenameNoGZ, '.');
            if ($decPosNoGZ !== false && $decPosNoGZ !== (strlen($OriginalFilenameNoGZ) - 1)) {
                $gzxt = strtolower(substr($OriginalFilenameNoGZ, ($decPosNoGZ + 1)));
                $gzxts = substr($gzxt, 0, 3) . '*';
            }
        } else {
            $gzxts = $gzxt = '-';
        }
        return [$xt, $xts, $gzxt, $gzxts];
    }

    /**
     * All needles must assert as the assert state being instances of haystacks.
     *
     * @param array $Haystacks The haystacks.
     * @param array $Needles The needles.
     * @param string $Padding An optional string to pad haystacks and needles.
     * @param bool $AssertState MUST (true) or must NOT (false) be an instance of.
     * @param bool $Mode ALL (false) or ANY (true) must assert.
     * @return bool True if requirement conforms; False otherwise.
     */
    public function containsMustAssert(array $Haystacks, array $Needles, string $Padding = ',', bool $AssertState = false, bool $Mode = false): bool
    {
        foreach ($Haystacks as $Haystack) {
            $Haystack = $Padding . $Haystack . $Padding;
            foreach ($Needles as $Needle) {
                $Needle = $Padding . $Needle . $Padding;
                if (!$Mode) {
                    if (!is_bool(strpos($Haystack, $Needle)) !== $AssertState) {
                        return false;
                    }
                    continue;
                }
                if (!is_bool(strpos($Haystack, $Needle)) === $AssertState) {
                    return true;
                }
            }
        }
        return !$Mode;
    }

    /**
     * Looks for image file indicators (i.e., checks whether a file is an image file).
     *
     * @param string $Ext The file extension.
     * @param string $Head The file header.
     * @return bool True: Indicators found. False: Indicators not found.
     */
    public function imageIndicators(string $Ext, string $Head): bool
    {
        return (preg_match(
                '/^(?:bm[2p]|c(d5|gm)|d(ib|w[fg]|xf)|ecw|fits|gif|img|j(f?if?|p[2s]|pe?g?2?|xr)|p(bm|cx|dd|gm|ic|n[gms]|' .
                'pm|s[dp])|s(id|v[ag])|tga|w(bmp?|ebp|mp)|x(cf|bmp))$/',
                $Ext
            ) ||
            preg_match(
                '/^(?:0000000c6a502020|25504446|38425053|424d|474946383[79]61|57454250|67696d7020786366|89504e47|ffd8ff)/',
                $Head
            ));
    }

    /**
     * Drops trailing extensions from filenames if the extension matches that of a
     * compression format supported by the compression handler.
     *
     * @param string $Filename The filename.
     * @return string The filename sans compression extension.
     */
    public function dropTrailingCompressionExtension(string $Filename): string
    {
        return preg_replace(['~\.t[gbl]?z[\da-z]?$~i', '~\.(?:bz2?|gz|lha|lz[fhowx])$~i'], ['.tar', ''], $Filename);
    }

    /**
     * Quarantines file uploads by bitshifting the input string (the uploaded
     * file's content) on the basis of your quarantine key, appending a header
     * with an explanation of what the bitshifted data is, along with an MD5
     * hash checksum of the original data, and then saves it all to a QFU file,
     * storing these QFU files in your quarantine directory.
     *
     * This isn't hardcore encryption, but it should be sufficient to prevent
     * accidental execution of quarantined files and to allow safe handling of
     * those files, which is the whole point of quarantining them in the first
     * place. Improvements might be made in the future.
     *
     * @param string $In The input string (the file upload / source data).
     * @param string $Key Your quarantine key.
     * @param string $IP Data origin (usually, the IP address of the uploader).
     * @param string $ID The QFU filename to use (calculated beforehand).
     * @return bool True on success; False on failure.
     */
    public function quarantine(string $In, string $Key, string $IP, string $ID): bool
    {
        /** Fire event: "atStartOf_quarantine". */
        $this->Loader->Events->fireEvent('atStartOf_quarantine');

        /** Guard against missing or unwritable quarantine directory. */
        if (!$this->Loader->QuarantinePath) {
            return false;
        }

        if (!$In || !$Key || !$IP || !$ID || !function_exists('gzdeflate') || (strlen($Key) < 128 &&
                !$Key = $this->Loader->hexSafe(hash('sha512', $Key) . hash('whirlpool', $Key)))) {
            return false;
        }
        if ($this->Loader->Configuration['legal']['pseudonymise_ip_addresses']) {
            $IP = $this->Loader->pseudonymiseIP($IP);
        }
        $k = strlen($Key);
        $FileSize = strlen($In);
        $Head = "\xa1phpMussel\x21" . $this->Loader->hexSafe(hash('md5', $In)) . pack('l*', $FileSize) . "\x01";
        $In = gzdeflate($In, 9);
        $Out = '';
        $i = 0;
        while ($i < $FileSize) {
            for ($j = 0; $j < $k; $j++, $i++) {
                if (strlen($Out) >= $FileSize) {
                    break 2;
                }
                $L = substr($In, $i, 1);
                $R = substr($Key, $j, 1);
                $Out .= ($L === false ? "\x00" : $L) ^ ($R === false ? "\x00" : $R);
            }
        }
        $Out =
            "\x2f\x3d\x3d\x20phpMussel\x20Quarantined\x20File\x20Upload\x20\x3d" .
            "\x3d\x5c\n\x7c\x20Time\x2fDate\x20Uploaded\x3a\x20" .
            str_pad($this->Loader->Time, 18, ' ') .
            "\x7c\n\x7c\x20Uploaded\x20From\x3a\x20" . str_pad($IP, 22, ' ') .
            "\x20\x7c\n\x5c" . str_repeat("\x3d", 39) . "\x2f\n\n\n" . $Head . $Out;
        $UsedMemory = $this->memoryUse($this->Loader->QuarantinePath);
        $UsedMemory['Size'] += strlen($Out);
        $UsedMemory['Count']++;
        if ($DeductBytes = $this->Loader->readBytes($this->Loader->Configuration['quarantine']['quarantine_max_usage'])) {
            $DeductBytes = $UsedMemory['Size'] - $DeductBytes;
            $DeductBytes = ($DeductBytes > 0) ? $DeductBytes : 0;
        }
        if ($DeductFiles = $this->Loader->Configuration['quarantine']['quarantine_max_files']) {
            $DeductFiles = $UsedMemory['Count'] - $DeductFiles;
            $DeductFiles = ($DeductFiles > 0) ? $DeductFiles : 0;
        }
        if ($DeductBytes > 0 || $DeductFiles > 0) {
            $UsedMemory = $this->memoryUse($this->Loader->QuarantinePath, $DeductBytes, $DeductFiles);
        }
        $Trail = substr($this->Loader->QuarantinePath, -1);
        if ($Trail !== '/' && $Trail !== '\\') {
            $ID .= DIRECTORY_SEPARATOR;
        }
        $Handle = fopen($this->Loader->QuarantinePath . $ID . '.qfu', 'ab');
        fwrite($Handle, $Out);
        fclose($Handle);
        if ($this->CalledFrom === 'Web') {
            $this->statsIncrement('Web-Quarantined', 1);
        }
        return true;
    }

    /**
     * Calculates the total memory used by a directory, and optionally enforces
     * memory usage and number of files limits on that directory. Should be
     * regarded as part of the phpMussel quarantine functionality.
     *
     * @param string $Path The path of the directory to be checked.
     * @param int $Delete How many bytes to delete from the target directory; Omit
     *      or set to 0 to avoid deleting files on the basis of total bytes.
     * @param int $DeleteFiles How many files to delete from the target directory;
     * Omit or set to 0 to avoid deleting files.
     * @return array Contains two integer elements: `Size`: The actual, total
     *      memory used by the target directory. `Count`: The total number of files
     *      found in the target directory by the time of closure exit.
     */
    private function memoryUse(string $Path, int $Delete = 0, int $DeleteFiles = 0): array
    {
        $Offset = strlen($Path);
        $Files = [];
        $List = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($Path), \RecursiveIteratorIterator::SELF_FIRST);
        foreach ($List as $Item => $List) {
            $File = str_replace("\\", '/', substr($Item, $Offset));
            if ($File && preg_match('~\.qfu$~i', $Item) && is_file($Item) && !is_link($Item) && is_readable($Item)) {
                $Files[$File] = filemtime($Item);
            }
        }
        unset($Item, $List, $Offset);
        $Arr = ['Size' => 0, 'Count' => 0];
        asort($Files, SORT_NUMERIC);
        foreach ($Files as $File => $Modified) {
            $File = $Path . $File;
            $Size = filesize($File);
            if (($Delete > 0 || $DeleteFiles > 0) && unlink($File)) {
                $DeleteFiles--;
                $Delete -= $Size;
                continue;
            }
            $Arr['Size'] += $Size;
            $Arr['Count']++;
        }
        return $Arr;
    }

    /**
     * Does some more complex decoding and normalisation work on strings.
     *
     * @param string $str The string to be decoded/normalised.
     * @param bool $html If true, "style" and "script" tags will be stripped from
     *      the input string (optional; defaults to false).
     * @param bool $decode If false, the input string will be normalised, but not
     *      decoded; If true, the input string will be normalised *and* decoded.
     *      Optional; Defaults to false.
     * @return string The decoded/normalised string.
     */
    public function normalise(string $str, bool $html = false, bool $decode = false): string
    {
        /** Fire event: "atStartOf_normalise". */
        $this->Loader->Events->fireEvent('atStartOf_normalise');

        $ostr = '';
        if ($decode) {
            $ostr .= $str;
            while (true) {
                if (
                    function_exists('gzinflate') &&
                    $c = preg_match_all('/(gzinflate\s*\(\s*["\'])(.{1,4096})(,\d)?(["\']\s*\))/i', $str, $matches)
                ) {
                    for ($i = 0; $c > $i; $i++) {
                        $str = str_ireplace(
                            $matches[0][$i],
                            '"' . gzinflate($this->Loader->substrBeforeLast($this->Loader->substrAfterFirst($matches[0][$i], $matches[1][$i]), $matches[4][$i])) . '"',
                            $str
                        );
                    }
                    continue;
                }
                if ($c = preg_match_all(
                    '/(base64_decode|decode_base64|base64\.b64decode|atob|Base64\.decode64)(\s*' .
                    '\(\s*["\'\`])([\da-z+\/]{4})*([\da-z+\/]{4}|[\da-z+\/]{3}=|[\da-z+\/]{2}==)(["\'\`]' .
                    '\s*\))/i',
                    $str,
                    $matches
                )) {
                    for ($i = 0; $c > $i; $i++) {
                        $str = str_ireplace(
                            $matches[0][$i],
                            '"' . base64_decode($this->Loader->substrBeforeLast($this->Loader->substrAfterFirst($matches[0][$i], $matches[1][$i] . $matches[2][$i]), $matches[5][$i])) . '"',
                            $str
                        );
                    }
                    continue;
                }
                if ($c = preg_match_all(
                    '/(str_rot13\s*\(\s*["\'])([^\'"\(\)]{1,4096})(["\']\s*\))/i',
                    $str,
                    $matches
                )) {
                    for ($i = 0; $c > $i; $i++) {
                        $str = str_ireplace(
                            $matches[0][$i],
                            '"' . str_rot13($this->Loader->substrBeforeLast($this->Loader->substrAfterFirst($matches[0][$i], $matches[1][$i]), $matches[3][$i])) . '"',
                            $str
                        );
                    }
                    continue;
                }
                if ($c = preg_match_all(
                    '/(hex2bin\s*\(\s*["\'])([\da-f]{1,4096})(["\']\s*\))/i',
                    $str,
                    $matches
                )) {
                    for ($i = 0; $c > $i; $i++) {
                        $str = str_ireplace(
                            $matches[0][$i],
                            '"' . $this->Loader->hexSafe($this->Loader->substrBeforeLast($this->Loader->substrAfterFirst($matches[0][$i], $matches[1][$i]), $matches[3][$i])) . '"',
                            $str
                        );
                    }
                    continue;
                }
                if ($c = preg_match_all(
                    '/([Uu][Nn][Pp][Aa][Cc][Kk]\s*\(\s*["\']\s*H\*\s*["\']\s*,\s*["\'])([\da-fA-F]{1,4096})(["\']\s*\))/',
                    $str,
                    $matches
                )) {
                    for ($i = 0; $c > $i; $i++) {
                        $str = str_replace($matches[0][$i], '"' . $this->Loader->hexSafe($this->Loader->substrBeforeLast($this->Loader->substrAfterFirst($matches[0][$i], $matches[1][$i]), $matches[3][$i])) . '"', $str);
                    }
                    continue;
                }
                break;
            }
        }
        $str = preg_replace('/[^\x21-\x7e]/', '', strtolower($this->prescanDecode($str . $ostr)));
        if ($html) {
            $str = preg_replace([
                '@<script[^>]*?>.*?</script>@si',
                '@<[\/\!]*?[^<>]*?>@si',
                '@<style[^>]*?>.*?</style>@siU',
                '@<![\s\S]*?--[ \t\n\r]*>@'
            ], '', $str);
        }
        return trim($str);
    }

    /**
     * Returns the high and low nibbles corresponding to the first byte of the
     * input string.
     *
     * @param string $Input The input string.
     * @return array Contains two elements, both standard decimal integers; The
     *      first is the high nibble of the input string, and the second is the low
     *      nibble of the input string.
     */
    public function splitNibble(string $Input): array
    {
        $Input = bin2hex($Input);
        return [hexdec(substr($Input, 0, 1)), hexdec(substr($Input, 1, 1))];
    }

    /**
     * Expands phpMussel detection shorthand to complete identifiers, makes some
     * determinations based on those identifiers against the package
     * configuration (e.g., whether specific signatures should be weighted or
     * ignored based on those identifiers), and returns a complete signature name
     * containing all relevant identifiers.
     *
     * Originally, this function was created to allow phpMussel to partially
     * compress its signatures without jeopardising speed, performance or
     * efficiency, because by allowing phpMussel to partially compress its
     * signatures, the total signature file footprint could be reduced, thus
     * allowing the inclusion of a greater number of signatures without causing
     * excessive footprint bloat. Its purpose has expanded since then though.
     *
     * @param string $VN The signature name WITH identifiers compressed (i.e.,
     *      the shorthand version of the signature name).
     * @return string The signature name WITHOUT identifiers compressed (i.e., the
     *      identifiers have been decompressed/expanded), or the input verbatim.
     */
    public function getShorthand(string $VN): string
    {
        /** Determine whether the signature is weighted. */
        $this->Loader->InstanceCache['weighted'] = false;

        /** Determine whether the signature should be ignored due to package configuration. */
        $this->Loader->InstanceCache['ignoreme'] = false;

        /** Byte 0 confirms whether the signature name uses shorthand. */
        if ($VN[0] !== "\x1a") {
            return $VN;
        }

        /** Check whether shorthand data has been fetched. If it hasn't, fetch it. */
        if (!$this->Loader->loadShorthandData()) {
            return $VN;
        }

        /** Will be populated by the signature name. */
        $Out = '';

        /** Byte 1 contains vendor name and signature metadata information. */
        $Nibbles = $this->splitNibble($VN[1]);

        /** Populate vendor name. */
        if (
            !empty($this->Loader->InstanceCache['shorthand.yml']['Vendor Shorthand'][$Nibbles[0]]) &&
            is_array($this->Loader->InstanceCache['shorthand.yml']['Vendor Shorthand'][$Nibbles[0]]) &&
            !empty($this->Loader->InstanceCache['shorthand.yml']['Vendor Shorthand'][$Nibbles[0]][$Nibbles[1]]) &&
            is_string($this->Loader->InstanceCache['shorthand.yml']['Vendor Shorthand'][$Nibbles[0]][$Nibbles[1]])
        ) {
            $SkipMeta = true;
            $Out .= $this->Loader->InstanceCache['shorthand.yml']['Vendor Shorthand'][$Nibbles[0]][$Nibbles[1]] . '-';
        } elseif (
            !empty($this->Loader->InstanceCache['shorthand.yml']['Vendor Shorthand'][$Nibbles[0]]) &&
            is_string($this->Loader->InstanceCache['shorthand.yml']['Vendor Shorthand'][$Nibbles[0]])
        ) {
            $Out .= $this->Loader->InstanceCache['shorthand.yml']['Vendor Shorthand'][$Nibbles[0]] . '-';
        }

        /** Populate weight options. */
        if ((!empty($this->Loader->InstanceCache['shorthand.yml']['Vendor Weight Options'][$Nibbles[0]][$Nibbles[1]]) &&
                $this->Loader->InstanceCache['shorthand.yml']['Vendor Weight Options'][$Nibbles[0]][$Nibbles[1]] === 'Weighted') || (!empty($this->Loader->InstanceCache['shorthand.yml']['Vendor Weight Options'][$Nibbles[0]]) &&
                $this->Loader->InstanceCache['shorthand.yml']['Vendor Weight Options'][$Nibbles[0]] === 'Weighted')) {
            $this->Loader->InstanceCache['weighted'] = true;
        }

        /** Populate signature metadata information. */
        if (empty($SkipMeta) && !empty($this->Loader->InstanceCache['shorthand.yml']['Metadata Shorthand'][$Nibbles[1]])) {
            $Out .= $this->Loader->InstanceCache['shorthand.yml']['Metadata Shorthand'][$Nibbles[1]] . '.';
        }

        /** Byte 2 contains vector information. */
        $Nibbles = $this->splitNibble($VN[2]);

        /** Populate vector information. */
        if (!empty($this->Loader->InstanceCache['shorthand.yml']['Vector Shorthand'][$Nibbles[0]][$Nibbles[1]])) {
            $Out .= $this->Loader->InstanceCache['shorthand.yml']['Vector Shorthand'][$Nibbles[0]][$Nibbles[1]] . '.';
        }

        /** Byte 3 contains malware type information. */
        $Nibbles = $this->splitNibble($VN[3]);

        /** Populate malware type information. */
        if (!empty($this->Loader->InstanceCache['shorthand.yml']['Malware Type Shorthand'][$Nibbles[0]][$Nibbles[1]])) {
            $Out .= $this->Loader->InstanceCache['shorthand.yml']['Malware Type Shorthand'][$Nibbles[0]][$Nibbles[1]] . '.';
        }

        /** Populate ignore options. */
        if (!empty($this->Loader->InstanceCache['shorthand.yml']['Malware Type Ignore Options'][$Nibbles[0]][$Nibbles[1]])) {
            $IgnoreOption = $this->Loader->InstanceCache['shorthand.yml']['Malware Type Ignore Options'][$Nibbles[0]][$Nibbles[1]];
            if (isset($this->Loader->Configuration['signatures'][$IgnoreOption]) && !$this->Loader->Configuration['signatures'][$IgnoreOption]) {
                $this->Loader->InstanceCache['ignoreme'] = true;
            }
        }

        /** Return the signature name and exit the closure. */
        return $Out . substr($VN, 4);
    }

    /**
     * Checks if $Needle (string) matches (is equal or identical to) $Haystack
     * (string), or a specific substring of $Haystack, to within a specific
     * threshold of the levenshtein distance between the $Needle and the
     * $Haystack or the $Haystack substring specified.
     *
     * @param string $Needle The needle (will be matched against the $Haystack,
     *      or, if substring positions are specified, against the $Haystack
     *      substring specified).
     * @param string $Haystack The haystack (will be matched against the
     *      $Needle). Note that for the purposes of calculating the levenshtein
     *      distance, it doesn't matter which string is a $Needle and which is
     *      a $Haystack (the value should be the same if the two were
     *      reversed). However, when specifying substring positions, those
     *      substring positions are applied to the $Haystack, and not the
     *      $Needle. Note, too, that if the $Needle length is greater than the
     *      $Haystack length (after having applied the substring positions to
     *      the $Haystack), $Needle and $Haystack will be switched.
     * @param int $pos_A The initial position of the $Haystack to use for the
     *      substring, if using a substring (optional; defaults to `0`; `0` is
     *      the beginning of the $Haystack).
     * @param int $pos_Z The final position of the $Haystack to use for the
     *      substring, if using a substring (optional; defaults to `0`; `0`
     *      will instruct the method to continue to the end of the $Haystack,
     *      and thus, if both $pos_A and $pos_Z are `0`, the entire $Haystack
     *      will be used).
     * @param int $min The threshold minimum (the minimum levenshtein distance
     *      required in order for the two strings to be considered a match).
     *      Optional; Defaults to `0`. If `0` or less is specified, there is no
     *      minimum, and so, any and all strings should always match, as long
     *      as the levenshtein distance doesn't surpass the threshold maximum.
     * @param int $max The threshold maximum (the maximum levenshtein distance
     *      allowed for the two strings to be considered a match). Optional;
     *      Defaults to `-1`. If exactly `-1` is specified, there is no
     *      maximum, and so, any and all strings should always match, as long
     *      as the threshold minimum is met.
     * @return bool True if the values are confined to the threshold; False
     *      otherwise and on error.
     */
    public function lvMatch(string $Needle, string $Haystack, int $pos_A = 0, int $pos_Z = 0, int $min = 0, int $max = -1): bool
    {
        /** Guard. */
        if (!function_exists('levenshtein') || is_array($Needle) || is_array($Haystack)) {
            return false;
        }

        $nlen = strlen($Needle);
        $pos_A = (int)$pos_A;
        $pos_Z = (int)$pos_Z;
        $min = (int)$min;
        $max = (int)$max;
        if ($pos_A !== 0 || $pos_Z !== 0) {
            $Haystack = ($pos_Z === 0) ? substr($Haystack, $pos_A) : substr($Haystack, $pos_A, $pos_Z);
        }
        $hlen = strlen($Haystack);
        if ($nlen < 1 || $hlen < 1) {
            return false;
        }
        if ($nlen > $hlen) {
            $x = [$Needle, $nlen, $Haystack, $hlen];
            $Haystack = $x[0];
            $hlen = $x[1];
            $Needle = $x[2];
            $nlen = $x[3];
        }
        $lv = levenshtein(strtolower($Haystack), strtolower($Needle));
        return (($min === 0 || $lv >= $min) && ($max === -1 || $lv <= $max));
    }

    /**
     * Returns a string representing the binary bits of its input, whereby each
     * byte of the output is either one or zero.
     * Output can be reversed with implodeBits.
     *
     * @param string $Input The input string (see method description above).
     * @return string The output string (see method description above).
     */
    public function explodeBits(string $Input): string
    {
        $Out = '';
        $Len = strlen($Input);
        for ($Byte = 0; $Byte < $Len; $Byte++) {
            $Out .= str_pad(decbin(ord($Input[$Byte])), 8, '0', STR_PAD_LEFT);
        }
        return $Out;
    }

    /**
     * The reverse of explodeBits.
     *
     * @param string $Input The input string (see method description above).
     * @return string The output string (see method description above).
     */
    public function implodeBits(string $Input): string
    {
        $Chunks = str_split($Input, 8);
        $Count = count($Chunks);
        for ($Out = '', $Chunk = 0; $Chunk < $Count; $Chunk++) {
            $Out .= chr(bindec($Chunks[$Chunk]));
        }
        return $Out;
    }

    /**
     * Used for performing lookups to the Google Safe Browsing API (v4).
     * @link https://developers.google.com/safe-browsing/v4/lookup-api
     *
     * @param array $URLs An array of the URLs to lookup.
     * @param array $URLsNoLookup An optional array of URLs to NOT lookup.
     * @param array $DomainsNoLookup An optional array of domains to NOT lookup.
     * @return int The results of the lookup. 200 if AT LEAST ONE of the queried
     *      URLs are listed on any of Google Safe Browsing lists; 204 if NONE of
     *      the queried URLs are listed on any of Google Safe Browsing lists; 400
     *      if the request is malformed or if there aren't any URLs to look up; 401
     *      if the API key is missing or isn't authorised; 503 if the service is
     *      unavailable (e.g., if it's been throttled).
     */
    public function safeBrowseLookup(array $URLs, array $URLsNoLookup = [], array $DomainsNoLookup = []): int
    {
        /** Guard against missing API key. */
        if (empty($this->Loader->Configuration['urlscanner']['google_api_key'])) {
            return 401;
        }

        /** Count URLs and exit early if there aren't any. */
        if (!$Count = count($URLs)) {
            return 400;
        }

        for ($Iterant = 0; $Iterant < $Count; $Iterant++) {
            $Domain = (strpos($URLs[$Iterant], '/') !== false) ? $this->Loader->substrBeforeFirst($URLs[$Iterant], '/') : $URLs[$Iterant];
            if (!empty($URLsNoLookup[$URLs[$Iterant]]) || !empty($DomainsNoLookup[$Domain])) {
                unset($URLs[$Iterant]);
                continue;
            }
            $URLs[$Iterant] = ['url' => $URLs[$Iterant]];
        }
        sort($URLs);

        /** After preparing URLs, prepare JSON array. */
        $Arr = json_encode([
            'client' => [
                'clientId' => 'phpMussel',
                'clientVersion' => $this->Loader->ScriptVersion
            ],
            'threatInfo' => [
                'threatTypes' => [
                    'THREAT_TYPE_UNSPECIFIED',
                    'MALWARE',
                    'SOCIAL_ENGINEERING',
                    'UNWANTED_SOFTWARE',
                    'POTENTIALLY_HARMFUL_APPLICATION'
                ],
                'platformTypes' => ['ANY_PLATFORM'],
                'threatEntryTypes' => ['URL'],
                'threatEntries' => $URLs
            ]
        ], JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);

        /** Fetch the cache entry for Google Safe Browsing, if it doesn't already exist. */
        if (!isset($this->Loader->InstanceCache['urlscanner_google'])) {
            $this->Loader->InstanceCache['urlscanner_google'] = $this->Loader->Cache->getEntry('urlscanner_google') ?: '';
        }

        /** Generate a reference for the cache entry for this lookup. */
        $cacheRef = hash('sha256', $Arr) . ':' . $Count . ':' . strlen($Arr) . ':';

        /** Check if this lookup has already been performed. */
        while (strpos($this->Loader->InstanceCache['urlscanner_google'], $cacheRef) !== false) {
            $Response = $this->Loader->substrBeforeFirst($this->Loader->substrAfterLast($this->Loader->InstanceCache['urlscanner_google'], $cacheRef), ';');

            /** Safety mechanism. */
            if (!$Response || strpos($this->Loader->InstanceCache['urlscanner_google'], $cacheRef . $Response . ';') === false) {
                $Response = '';
                break;
            }

            $Expiry = $this->Loader->substrBeforeFirst($Response, ':');
            if ($Expiry > $this->Loader->Time) {
                $Response = $this->Loader->substrAfterFirst($Response, ':');
                break;
            }
            $this->Loader->InstanceCache['urlscanner_google'] = str_ireplace(
                $cacheRef . $Response . ';',
                '',
                $this->Loader->InstanceCache['urlscanner_google']
            );
            $Response = '';
        }

        /** If this lookup has already been performed, return the results. */
        if (!empty($Response)) {

            /** Potentially harmful URL detected. */
            if ($Response === '200') {
                return 200;
            }

            /** Potentially harmful URL *NOT* detected. */
            if ($Response === '204') {
                return 204;
            }

            /** Malformed request. */
            if ($Response === '400') {
                return 400;
            }

            /** Unauthorised (most likely an invalid API key used). */
            if ($Response === '401') {
                return 401;
            }

            /** Service unavailable. */
            if ($Response === '503') {
                return 503;
            }

            /** Other, unknown problem (in theory, this should never be reached). */
            if ($Response === '999') {
                return 999;
            }
        }

        /** Perform lookup. */
        $Response = $this->Loader->request(
            'https://safebrowsing.googleapis.com/v4/threatMatches:find?key=' . $this->Loader->Configuration['urlscanner']['google_api_key'],
            $Arr,
            $this->Loader->Timeout,
            ['Content-type: application/json']
        );
        $this->Loader->InstanceCache['LookupCount']++;

        /** Generate new cache expiry time. */
        $newExpiry = $this->Loader->Time + $this->Loader->Configuration['urlscanner']['cache_time'];

        /** Potentially harmful URL detected. */
        if (strpos($Response, '"matches":') !== false) {
            $returnVal = 200;
        } else {

            /**
             * Other possible problem detected.
             * @link https://developers.google.com/safe-browsing/v4/status-codes
             */
            if (isset($this->Loader->MostRecentHttpCode) && $this->Loader->MostRecentHttpCode !== 200) {

                /**
                 * Malformed request detected (e.g., invalid argument, invalid
                 * request payload, etc).
                 */
                if ($this->Loader->MostRecentHttpCode === '400') {
                    $returnVal = 400;
                } /**
                 * Unauthorised (most likely an invalid API key used). Returning
                 * the same message for 401 and 403 because the returned message is
                 * suitable either way.
                 */
                elseif ($this->Loader->MostRecentHttpCode >= '401' && $this->Loader->MostRecentHttpCode <= 403) {
                    $returnVal = 401;
                } /**
                 * Service unavailable or internal server error. Returning the same
                 * message for 429, 500, 503, 504 alike because, for our purpose,
                 * the returned message is suitable in any case.
                 */
                elseif ($this->Loader->MostRecentHttpCode >= '429') {
                    $returnVal = 503;
                } /**
                 * Fallback for other error codes (in theory, this shouldn't ever
                 * be reached, but adding it here just in case).
                 */
                else {
                    $returnVal = 999;
                }

                /**
                 * Enforce an additional 24 hours (the maximum computable back-off
                 * period, so as to play it safe) onto the expiry time for cached
                 * failed lookups.
                 * @link https://developers.google.com/safe-browsing/v4/request-frequency#back-off-mode
                 */
                $newExpiry += 86400;
            } else {

                /** Potentially harmful URL *NOT* detected, and no other problems detected. */
                $returnVal = 204;
            }
        }

        /** Update the cache entry for Google Safe Browsing. */
        $this->Loader->InstanceCache['urlscanner_google'] .= $cacheRef . ':' . $newExpiry . ':' . $returnVal . ';';
        $this->Loader->Cache->setEntry('urlscanner_google', $newExpiry, $this->Loader->InstanceCache['urlscanner_google']);

        return $returnVal;
    }

    /**
     * Checks whether signature length is confined within an acceptable limit.
     *
     * @param int $Length
     * @return bool
     */
    public function confineLength(int $Length): bool
    {
        return ($Length < 4 || $Length > 1024);
    }

    /**
     * Detection trigger method (appends detection information).
     *
     * @param array $Heuristic
     * @param string $Indentation
     * @param string $VN
     * @param string $OriginalFilename
     * @param string $OriginalFilenameSafe
     * @param string $Out
     * @param bool $Flagged
     * @param string $Checksum
     * @param int $StringLength
     */
    private function detected(
        array &$Heuristic,
        string &$Indentation,
        string &$VN,
        string &$OriginalFilename,
        string &$OriginalFilenameSafe,
        string &$Out,
        bool &$Flagged,
        string &$Checksum,
        int &$StringLength
    )
    {
        /** Fire event: "atStartOf_detected". */
        $this->Loader->Events->fireEvent('atStartOf_detected', '', $Heuristic, $Indentation, $VN, $OriginalFilename, $OriginalFilenameSafe, $Out, $Flagged, $Checksum, $StringLength);

        if (!$Flagged) {
            $this->Loader->HashReference .= $Checksum . ':' . $StringLength . ':' . $OriginalFilename . "\n";
            $Flagged = true;
        }
        $Heuristic['detections']++;
        $this->Loader->InstanceCache['detections_count']++;
        if ($this->Loader->InstanceCache['weighted']) {
            $Heuristic['weight']++;
            $Heuristic['cli'] .= $Indentation . sprintf(
                    $this->Loader->L10N->getString('_exclamation_final'),
                    sprintf($this->Loader->L10N->getString('detected'), $VN)
                ) . "\n";
            $Heuristic['web'] .= sprintf(
                $this->Loader->L10N->getString('_exclamation'),
                sprintf($this->Loader->L10N->getString('detected'), $VN) . ' (' . $OriginalFilenameSafe . ')'
            );
            return;
        }
        $Out .= $Indentation . sprintf(
                $this->Loader->L10N->getString('_exclamation_final'),
                sprintf($this->Loader->L10N->getString('detected'), $VN)
            ) . "\n";
        $this->Loader->WhyFlagged .= sprintf(
            $this->Loader->L10N->getString('_exclamation'),
            sprintf($this->Loader->L10N->getString('detected'), $VN) . ' (' . $OriginalFilenameSafe . ')'
        );
    }

    /**
     * Confines a string boundary as per rules specified by parameters.
     *
     * @param string $Data The string.
     * @param string|int $Initial The start of the boundary or string initial offset value.
     * @param string|int $Terminal The end of the boundary or string terminal offset value.
     * @param array $SectionOffsets Section offset values.
     */
    public function dataConfineByOffsets(string &$Data, &$Initial, &$Terminal, array &$SectionOffsets)
    {
        /** Guard. */
        if ($Initial === '*' && $Terminal === '*') {
            return;
        }

        if (substr($Initial, 0, 2) === 'SE') {
            $SectionNum = (int)substr($Initial, 2);
            $Initial = '*';
            $Terminal = '*';
            if (isset($SectionOffsets[$SectionNum][0])) {
                $Data = substr($Data, $SectionOffsets[$SectionNum][0] * 2);
            }
            if (isset($SectionOffsets[$SectionNum][1])) {
                $Data = substr($Data, 0, $SectionOffsets[$SectionNum][1] * 2);
            }
        } elseif (substr($Initial, 0, 2) === 'SL') {
            $Remainder = strlen($Initial) > 3 && substr($Initial, 2, 1) === '+' ? (substr($Initial, 3) ?: 0) : 0;
            $Initial = '*';
            $Final = count($SectionOffsets);
            if ($Final > 0 && isset($SectionOffsets[$Final - 1][0])) {
                $Data = substr($Data, ($SectionOffsets[$Final - 1][0] + $Remainder) * 2);
            }
            if ($Terminal !== '*' && $Terminal !== 'Z') {
                $Data = substr($Data, 0, $Terminal * 2);
                $Terminal = '*';
            }
        } elseif (substr($Initial, 0, 1) === 'S') {
            if (($PlusPos = strpos($Initial, '+')) !== false) {
                $SectionNum = substr($Initial, 1, $PlusPos - 1) ?: 0;
                $Remainder = substr($Initial, $PlusPos + 1) ?: 0;
            } else {
                $SectionNum = substr($Initial, 1) ?: 0;
                $Remainder = 0;
            }
            $Initial = '*';
            if (isset($SectionOffsets[$SectionNum][0])) {
                $Data = substr($Data, ($SectionOffsets[$SectionNum][0] + $Remainder) * 2);
            }
            if ($Terminal !== '*' && $Terminal !== 'Z') {
                $Data = substr($Data, 0, $Terminal * 2);
                $Terminal = '*';
            }
        } else {
            if ($Initial !== '*' && $Initial !== 'A') {
                $Data = substr($Data, $Initial * 2);
                $Initial = '*';
            }
            if ($Terminal !== '*' && $Terminal !== 'Z') {
                $Data = substr($Data, 0, $Terminal * 2);
                $Terminal = '*';
            }
        }
    }

    /**
     * Match a variable referenced by a signature file (guards against some obscure
     * referencing and typecasting problems).
     *
     * @param mixed $Actual The actual data found in the signature file.
     * @param mixed $Expected The expected data to be matched against.
     * @return bool True when they match; False when they don't.
     */
    public function matchVarInSigFile($Actual, $Expected): bool
    {
        $LCActual = strtolower($Actual);
        if ($LCActual === '0' || $LCActual === 'false') {
            if ($Expected === 0 || $Expected === false) {
                return true;
            }
        }
        if ($LCActual === '1' || $LCActual === 'true') {
            if ($Expected === 1 || $Expected === true) {
                return true;
            }
        }
        $Actual = (string)$Actual;
        $Expected = (string)$Expected;
        return $Actual === $Expected;
    }

    /**
     * Splits a signature into its constituent parts (name, pattern, etc).
     *
     * @param string $Sig The signature.
     * @param int $Max The maximum number of parts to return (optional).
     * @return array The parts.
     */
    public function splitSigParts(string $Sig, int $Max = -1): array
    {
        return preg_split('~(?<!\?|\<)\:~', $Sig, $Max, PREG_SPLIT_NO_EMPTY);
    }

    /**
     * Handles scanning for files contained within archives.
     *
     * @param string $x Scan results inherited from parent in the form of a string.
     * @param int $r Scan results inherited from parent in the form of an integer.
     * @param string $Indent Line padding for the scan results.
     * @param string $ItemRef A reference to the path and original filename of the
     *      item being scanned in relation to its container and/or its hierarchy
     *      within the scan process.
     * @param string $Filename The original filename of the item being scanned.
     * @param string $Data The data to be scanned.
     * @param int $Depth The depth of the item being scanned in relation to its
     *      container and/or its hierarchy within the scan process.
     * @param string $Checksum A hash for the content, inherited from the parent.
     */
    public function metaDataScan(string &$x, int &$r, string $Indent, string $ItemRef, string $Filename, string &$Data, int $Depth, string $Checksum)
    {
        /** Fire event: "atStartOf_metaDataScan". */
        $this->Loader->Events->fireEvent('atStartOf_metaDataScan');

        /** Data is empty. Nothing to scan. Exit early. */
        if (!$Filesize = strlen($Data)) {
            return;
        }

        /** Filesize thresholds. */
        if (
            $this->Loader->Configuration['files']['filesize_archives'] &&
            $this->Loader->Configuration['files']['filesize_limit'] > 0 &&
            $Filesize > $this->Loader->readBytes($this->Loader->Configuration['files']['filesize_limit'])
        ) {
            if (!$this->Loader->Configuration['files']['filesize_response']) {
                $x .=
                    $Indent . $this->Loader->L10N->getString('ok') . ' (' .
                    $this->Loader->L10N->getString('filesize_limit_exceeded') . ").\n";
                return;
            }
            $r = 2;
            $this->Loader->HashReference .= $Checksum . ':' . $Filesize . ':' . $ItemRef . "\n";
            $this->Loader->WhyFlagged .= sprintf(
                $this->Loader->L10N->getString('_exclamation'),
                $this->Loader->L10N->getString('filesize_limit_exceeded') . ' (' . $ItemRef . ')'
            );
            $x .=
                $Indent . $this->Loader->L10N->getString('filesize_limit_exceeded') .
                $this->Loader->L10N->getString('_fullstop_final') . "\n";
            return;
        }

        /** Process filetype blacklisting, whitelisting, and greylisting. */
        if ($this->Loader->Configuration['files']['filetype_archives']) {
            [$xt, $xts, $gzxt, $gzxts] = $this->fetchExtension($Filename);
            if ($this->containsMustAssert([
                $this->Loader->Configuration['files']['filetype_whitelist']
            ], [$xt, $xts], ',', true, true)) {
                $x .= $Indent . $this->Loader->L10N->getString('scan_no_problems_found') . "\n";
                return;
            }
            if ($this->containsMustAssert([
                $this->Loader->Configuration['files']['filetype_blacklist']
            ], [$xt, $xts], ',', true, true)) {
                $r = 2;
                $this->Loader->HashReference .= $Checksum . ':' . $Filesize . ':' . $ItemRef . "\n";
                $this->Loader->WhyFlagged .= sprintf(
                    $this->Loader->L10N->getString('_exclamation'),
                    $this->Loader->L10N->getString('filetype_blacklisted') . ' (' . $ItemRef . ')'
                );
                $x .=
                    $Indent . $this->Loader->L10N->getString('filetype_blacklisted') .
                    $this->Loader->L10N->getString('_fullstop_final') . "\n";
                return;
            }
            if (!empty($this->Loader->Configuration['files']['filetype_greylist']) && $this->containsMustAssert([
                    $this->Loader->Configuration['files']['filetype_greylist']
                ], [$xt, $xts])) {
                $r = 2;
                $this->Loader->HashReference .= $Checksum . ':' . $Filesize . ':' . $ItemRef . "\n";
                $this->Loader->WhyFlagged .= sprintf(
                    $this->Loader->L10N->getString('_exclamation'),
                    $this->Loader->L10N->getString('filetype_blacklisted') . ' (' . $ItemRef . ')'
                );
                $x .=
                    $Indent . $this->Loader->L10N->getString('filetype_blacklisted') .
                    $this->Loader->L10N->getString('_fullstop_final') . "\n";
                return;
            }
        }

        /** Determine whether the file being scanned is a macro. */
        $this->Loader->InstanceCache['file_is_macro'] = (preg_match('~vbaProject\.bin$~i', $Filename) ||
            preg_match('~^\xd0\xcf|\x00Attribut|\x01CompObj|\x05Document~', $Data));

        /** Handle macro detection and blocking. */
        if ($this->Loader->Configuration['files']['block_macros'] && $this->Loader->InstanceCache['file_is_macro']) {
            $r = 2;
            $this->Loader->HashReference .= $Checksum . ':' . $Filesize . ':' . $ItemRef . "\n";
            $this->Loader->WhyFlagged .= sprintf(
                $this->Loader->L10N->getString('_exclamation'),
                $this->Loader->L10N->getString('macros_not_permitted') . ' (' . $ItemRef . ')'
            );
            $x .= $Indent . $this->Loader->L10N->getString('macros_not_permitted') . $this->Loader->L10N->getString('_fullstop_final') . "\n";
            return;
        }

        /** Increment objects scanned count. */
        $this->Loader->InstanceCache['objects_scanned']++;

        /** Send the scan target to the data handler. */
        $Scan = $this->dataHandler($Data, $Depth, $Filename);

        /**
         * Check whether the file is compressed. If it's compressed, attempt to
         * decompress it, and then scan the decompressed version of the file. We'll
         * only bother doing this if the file hasn't already been flagged though.
         */
        if ($Scan[0] === 1) {

            /** Create a new compression object. */
            $CompressionObject = new CompressionHandler($Data);

            /** Now we'll try to decompress the file. */
            if (!$CompressionResults = $CompressionObject->TryEverything()) {

                /** Success! Now we'll send it to the data handler. */
                $Scan = $this->dataHandler($CompressionObject->Data, $Depth, $this->dropTrailingCompressionExtension($Filename));

                /**
                 * Replace originally scanned data with decompressed data in case
                 * needed by the archive handler.
                 */
                $Data = $CompressionObject->Data;
            }

            /** Cleanup. */
            unset($CompressionResults, $CompressionObject);
        }

        /** Reset Crx variables. */
        $this->CrxPubKey = '';
        $this->CrxSignature = '';

        /** Update the results if anything bad was found and then exit. */
        if ($Scan[0] !== 1) {
            $r = $Scan[0];
            $x .= '-' . $Scan[1];
            return;
        }

        /** Or, if nothing bad was found for this entry, make a note of it. */
        $x .= $Indent . $this->Loader->L10N->getString('scan_no_problems_found') . "\n";
    }

    /**
     * Quine detection for the archive handler.
     *
     * @param int $ScanDepth The current scan depth.
     * @param string $ParentHash Parent data hash.
     * @param int $ParentLen Parent data length.
     * @param string $ChildHash Child data hash.
     * @param int $ChildLen Child data length.
     * @return bool True when a quine is detected; False otherwise.
     */
    public function quineDetector(int $ScanDepth, string $ParentHash, int $ParentLen, string $ChildHash, int $ChildLen): bool
    {
        $this->Loader->InstanceCache['Quine'][$ScanDepth - 1] = [$ParentHash, $ParentLen];
        for ($Iterate = 0; $Iterate < $ScanDepth; $Iterate++) {
            if ($this->Loader->InstanceCache['Quine'][$Iterate][0] === $ChildHash && $this->Loader->InstanceCache['Quine'][$Iterate][1] === $ChildLen) {
                return true;
            }
        }
        return false;
    }

    /**
     * Convert Chrome Extension data to standard Zip data.
     *
     * @param string $Data Referenced via the archive recursor.
     * @return bool True when conversion succeeds; False otherwise (e.g., not Crx).
     */
    public function convertCrx(string &$Data): bool
    {
        if (substr($Data, 0, 4) !== 'Cr24' || strlen($Data) <= 16) {
            return false;
        }
        $Crx = ['Version' => unpack('i*', substr($Data, 4, 4))];
        if ($Crx['Version'][1] === 2) {
            $Crx['PubKeyLen'] = unpack('i*', substr($Data, 8, 4));
            $Crx['SigLen'] = unpack('i*', substr($Data, 12, 4));
            $ZipBegin = 16 + $Crx['PubKeyLen'][1] + $Crx['SigLen'][1];
            if (substr($Data, $ZipBegin, 2) === 'PK') {
                $this->CrxPubKey = bin2hex(substr($Data, 16, $Crx['PubKeyLen'][1]));
                $this->CrxSignature = bin2hex(substr($Data, 16 + $Crx['PubKeyLen'][1], $Crx['SigLen'][1]));
                $Data = substr($Data, $ZipBegin);
                return true;
            }
        }
        return false;
    }

    /**
     * Assigns an array to use for dumping scan debug information (optional).
     *
     * @param array $Arr
     */
    public function setScanDebugArray(&$Arr)
    {
        unset($this->debugArr);
        if (!is_array($Arr)) {
            $Arr = [];
        }
        $this->debugArr = &$Arr;
    }

    /**
     * Destroys the scan debug array (optional).
     *
     * @param array $Arr
     */
    public function destroyScanDebugArray(&$Arr)
    {
        unset($this->Loader->InstanceCache['DebugArrKey'], $this->debugArr);
        $Arr = null;
    }
}
