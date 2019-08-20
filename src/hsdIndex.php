<?php
namespace ierusalim\hsd;

class hsdIndex
{

    /**
     * Write last hsd-file-number and last wr-seek to streams.list file
     *
     * File format is:
     * xxxxxxxx   xxxx      xxxx
     *   sid     wr_hsd_n  wr_seek
     *
     * @param string $streams_list_name
     * @param string|int $sid_or_num
     * @param int $wr_hsd_n
     * @param int $wr_seek
     * @return int|false
     */
    public static function hsdFolderUpdate(
        $streams_list_name,
        $sid_or_num,
        $wr_hsd_n,
        $wr_seek
    ) {
        $wrpack = pack('N2', $wr_hsd_n, $wr_seek);
        if (is_string($sid_or_num) && strlen($sid_or_num) == 16) {
            $sid_bin = hex2bin($sid_or_num);
            $scan_folder = function($sid_bin) use ($streams_list_name) {
                if (is_file($streams_list_name)) {
                    $data = file_get_contents($streams_list_name);
                    $data_arr = str_split($data, 16);
                    foreach($data_arr as $cell_num => $data) {
                        if (substr($data,0,8) == $sid_bin) {
                            return $cell_num;
                        }
                    }
                }
                return false;
            };
            $cell_num = $scan_folder($sid_bin);
            if ($cell_num === false) {
                $pack_str = $sid_bin . $wrpack;
                if (!is_file($streams_list_name)) {
                    $pack_str = str_repeat('=', 16) . $pack_str;
                }
                file_put_contents($streams_list_name, $pack_str, \FILE_APPEND);
                $cell_num = $scan_folder($sid_bin);
            }
        } elseif (is_numeric($sid_or_num)) {
            $cell_num = $sid_or_num;
        } else {
            return false;
        }
        if (!is_numeric($cell_num) || ($cell_num > 255)) {
            return false;
        }
        $f = fopen($streams_list_name, 'rb+');
        if (!$f) {
            return false;
        }
        fseek($f, 8 + 16 * $cell_num);
        fwrite($f, $wrpack);
        fclose($f);
        return $cell_num;
    }

    /**
     * Update seek.index file when new block started
     *
     * @param \ierusalim\hsd\hsd $hsd
     * @param int $blk_n
     * @param int $hash_seek
     * @return false|int
     */
    public static function hsdSeekIndexUpdate(hsd $hsd, $blk_n, $hash_seek)
    {
        $seek_index_name = $hsd->makeHSDfileName('seek.index');
        if (!$blk_n && !is_file($seek_index_name)) {
            $fmode = 'wb+';
        } else {
            $fmode = 'rb+';
        }
        $fs = fopen($seek_index_name, $fmode);
            if (!$fs) {
                return false;
            }
            if (fseek($fs, $blk_n * 4)) {
                fclose ($fs);
                return false;
            }
            $wb = fwrite($fs, pack('N', $hash_seek));
        fclose($fs);
        if ($wb != 4) {
            return false;
        }
        return $hash_seek;
    }

    public static function whereBlkN($fb, $blk_n)
    {
        $hsd_n = 1;
        fseek($fb, 4);
        $data = fread($fb, 4);
        while (!feof($fb)) {
            if (strlen($data) != 4) {
                return false;
            }
            $curr_start_n = unpack('N', $data)[1];

            $data = fread($fb, 4);
            if (strlen($data) == 4) {
                $next_start_n = unpack('N', $data)[1];
            } else {
                if (feof($fb)) {
                    return -$hsd_n;
                } else {
                    return false;
                }
            }

            if (($blk_n >= $curr_start_n) && ($blk_n < $next_start_n)) {
                return $hsd_n;

            }
            $hsd_n++;
        }
        return false;
    }
    public static function getStartBlkN($fb, $hsd_n)
    {
        if (fseek($fb, $hsd_n * 4)) {
            return false;
        }
        $data = fread($fb, 4);
        if (strlen($data) != 4) {
            return false;
        }
        return unpack('N', $data)[1];
    }

    /**
     * Read blocks-parameter
     *
     * In: opened for reading file resource or 4-bytes string
     * Out: integer value (or empty if error)
     *
     * The blocks-parameter is file-finalize state indicator:
     *  if >0 then it is blosk_cnt (file is finalized)
     *  if <0 then it is last-hash-seek-point
     *  if =0 means error state (last-hash MUST present in hsd-file)
     * format: (4 bytes)
     *    "ff xx xx xx" - blocks cnt,
     * or "xx xx xx xx" - seek-point of end of last finalized block
     *
     * @param resource|string $fr_or_blocks
     * @return integer|false
     */
    public static function getBlocksPar($fr_or_blocks)
    {
        if (is_resource($fr_or_blocks)) {
            fseek($fr_or_blocks, 4);
            $blocks = fread($fr_or_blocks, 4);
        } else {
            $blocks = $fr_or_blocks;
        }
        if (!is_string($blocks) || (strlen($blocks) != 4)) {
            return false;
        }
        if ($blocks[0] == chr(255)) {
            $blocks[0] = chr(0);
            $blocks = unpack('N', $blocks)[1];
        } else {
            $blocks = -unpack('N', $blocks)[1];
        }
        return $blocks;
    }

    /**
     * Update blkn.index file when new hsd-file started
     *
     * @param \ierusalim\hsd\hsd $hsd
     * @param int $hsd_n
     * @param int $st_blk_n
     * @return false|int
     */
    public static function hsdBlknUpdate(hsd $hsd, $hsd_n, $st_blk_n)
    {
        $blkn_index_name = $hsd->makeHSDfileName('blkn.index');
        if (!is_file($blkn_index_name)) {
            if (($hsd_n === 1) && ($st_blk_n === 0)) {
                $create_blkn_data = str_repeat(chr(0), 4);
                if (file_put_contents($blkn_index_name, $create_blkn_data) != 4) {
                    return false;
                }
            }
        }
        $max_hsd_n = filesize($blkn_index_name);
        if (!$max_hsd_n) {
            return false;
        } else {
            $max_hsd_n = $max_hsd_n / 4;
            if ($hsd_n > $max_hsd_n) {
                $max_hsd_n = $hsd_n;
            }
        }

        $fb = fopen($blkn_index_name, 'rb+');
            if (!$fb) {
                return false;
            }
            if (fseek($fb, $hsd_n * 4)) {
                fclose ($fb);
                return false;
            }
            $wb = fwrite($fb, pack('N', $st_blk_n));

            rewind($fb);
            $wb = fwrite($fb, pack('N', $max_hsd_n));

        fclose($fb);
        if ($wb != 4) {
            return false;
        }
        return $st_blk_n;

    }

    public static function buildHSDindex(hsd $hsd)
    {
        $hsd_diap_arr = self::hsdDiapScan($hsd);
        if (empty($hsd_diap_arr)) return false;

        $seek_index_name = $hsd->makeHSDfileName('seek.index');
        $blkn_index_name = $hsd->makeHSDfileName('blkn.index');

        $fs = fopen($seek_index_name, 'wb+');
        $fb = fopen($blkn_index_name, 'wb+');

        foreach($hsd_diap_arr as $one_diap) {
            for($hsd_n = $one_diap[0]; $hsd_n <= $one_diap[1]; $hsd_n++) {
                $hsd_file = $hsd->makeHSDfileName($hsd_n);

                $walk = hsdWalk::FileWalkBlocks($hsd_file);

                $start_blk_n = $walk['from'];
                $blocks_cnt = $walk['blocks_cnt'];
                $data_seek = $walk['data_seek'];

                fseek($fb, $hsd_n * 4);
                fwrite($fb, pack('N', $start_blk_n));

                fseek($fs, $start_blk_n * 4);

                for($i = 0; $i < $blocks_cnt; $i++) {
                    $blk_n = $start_blk_n + $i;
                    $blk_len = $walk[$blk_n];
                    fwrite($fs, pack('N', $data_seek));
                    $data_seek += $blk_len;
                }
            }
        }
        // write max_hsd_n to head of blkn.index
        rewind($fb);
        fwrite($fb, pack('N', ($hsd_n - 1)));

        // finish
        fclose($fb);
        fclose($fs);
        return $walk;
    }

    /**
     * Calculate block ranges in hsd-files
     *
     * @param \ierusalim\hsd\hsd $hsd
     * @return array|false
     */
    public static function calcHSDlist(\ierusalim\hsd\hsd $hsd)
    {
        $diap_arr = self::hsdDiapScan($hsd);
        if (!count($diap_arr)) {
            return false;
        }

        $hsd_list = [];

        foreach($diap_arr as $diap) {
            for($hsd_n = $diap[0]; $hsd_n <= $diap[1]; $hsd_n++)
            {
                $file_name = $hsd->makeHSDfileName($hsd_n);
                $data = file_get_contents($file_name, false, NULL, 4, 8);
                $fc = ord($data[0]);
                if ($fc != 255) {
                    continue;
                }
                $blk_cnt = unpack('N', chr(0) . substr($data, 1, 3))[1];
                $st_blk_n = unpack('N', substr($data, 4, 4))[1];
                $hsd_list[$hsd_n] = [$st_blk_n, $blk_cnt];
            }
        }
        return $hsd_list;
    }

    /**
     * Return array of founded diapasones of hsd-files
     * format: 0=>[1,6], 1=>[8,8] - means 1,2,3,4,5,6,.,8
     *
     * @param \ierusalim\hsd\hsd $hsd
     * @return array
     */
    public static function hsdDiapScan(\ierusalim\hsd\hsd $hsd)
    {
        $hsd_arr = self::scanHSDfiles($hsd->base_path, $hsd->base_name);
        if (!isset($hsd_arr['max'])) {
            return [];
        }
        $min_hsd_n = $hsd_arr['min'];
        $max_hsd_n = $hsd_arr['max'];

        $diaps = [];
        $diap_start = $min_hsd_n;
        for ($n = $min_hsd_n; $n <= $max_hsd_n; $n++) {
            $s = array_search($n, $hsd_arr);
            if (($s === false) && $diap_start) {
                $diaps[] = [$diap_start, $n - 1];
                $diap_start = false;
            }
            if (($s !== false) && !$diap_start) {
                $diap_start = $n;
            }
        }
        if ($diap_start) {
            $diaps[] = [$diap_start, $n - 1];
        }
        return $diaps;
    }

    /**
     * Return max.number of hsd-files
     *
     * Read from locker or scan all hsd-files in sid-folder
     *
     * @param \ierusalim\hsd\hsd $hsd
     * @return false|integer
     */
    public static function lastHSDscan(\ierusalim\hsd\hsd $hsd)
    {
        $locker_file = $hsd->lockerFileName();
        // try get curr_hsd_n from locker
        $curr_hsd_n = false;
        if (is_file($locker_file)) {
            $data = file_get_contents($locker_file, false, NULL, 4, 4);
            if (strlen($data) == 4) {
                $curr_hsd_n = unpack('N', $data)[1];
            }
        }
        // if curr_hsd_n unknown, try enumerate all hsd-files
        if (!$curr_hsd_n) {
            $hsd_arr = self::scanHSDfiles($hsd->base_path, $hsd->base_name);
            if (isset($hsd_arr['max'])) {
                $curr_hsd_n = $hsd_arr['max'];
            }
        }
        return $curr_hsd_n;
    }

    public static function scanHSDfiles($base_path, $base_name, $ret_only_max_min = false)
    {
        $max_num = 0;
        $min_num = 4294967296; // 2^32

        // scan hsd files
        $pattern = $base_path . $base_name . DIRECTORY_SEPARATOR . $base_name . '-';
        $plen = strlen($pattern);
        $files_arr = glob($pattern . '*.hsd');
        $hsd_arr = [];
        foreach($files_arr as $k => $fileN) {
            $file_num = strstr(substr($fileN, $plen), '.', true);
            if (strlen($file_num) != 8) continue;
            $file_num = hexdec($file_num);
            if (!$file_num) continue;
            if ($file_num > $max_num) $max_num = $file_num;
            if ($file_num < $min_num) $min_num = $file_num;
            $hsd_arr[] = $file_num;
        }
        if (count($hsd_arr)) {
            if ($ret_only_max_min) {
                $hsd_arr = [];
            }
            $hsd_arr['min'] = $min_num;
            $hsd_arr['max'] = $max_num;
        }
        return $hsd_arr;
    }

    /**
     * Create or rewrite Locker-file
     *
     * @param boolean $overwrite
     * @param string $locker_str
     * @return boolean|string
     */

    public static function writeLocker(
        $locker_file_name,
        $locker_str, //data-string, packaged by self::packLocker()
        $overwrite = false
    ) {
        // check locker file
        if (!$overwrite && is_file($locker_file_name)) {
            return "HSD locker already exist";
        }

        // write locker
        $wb_cnt = file_put_contents($locker_file_name, $locker_str);
        if ($wb_cnt < strlen($locker_str)) {
            return 'Error HSD-locker write';
        }
        return false;
    }

    /**
     * Repair Locker for write new data (LW-mode)
     *
     */
    public static function repairWriteMode(hsd $hsd, $skip_blocks = true, $trans_in_last_block = true)
    {
        $base_path = $hsd->base_path;
        $base_name = $hsd->base_name;

        // scan last hsd-file
        $hsd_arr = self::scanHSDfiles($base_path, $base_name, true);
        if (isset($hsd_arr['max'])) {
            $last_hsd_n = $hsd_arr['max'];
        } else {
            return "No HSD files";
        }

        // last hsd-file name
        $file_name = $hsd->makeHSDfileName($last_hsd_n);

        $buff = file_get_contents($file_name, false, NULL, 0, 1100);
        $head_arr = hsd::unpackHSDheader($buff);
        if (!is_array($head_arr)) {
            return 'Bad file format: ' . $file_name;
        }

        $iii_str = $head_arr['iii_str'];
        $hash_size = $head_arr['hash_size'];
        $blocks = $head_arr['blocks'];
        $start_blk = $head_arr['start_blk'];

        // is file finalized?
        if ($blocks < 0) { // not finalize
            $hash_seek = -$blocks;
            $wr_hsd_n = $last_hsd_n;
            $p = $head_arr['data_seek'] + $hash_size;

            $wr_seek = 0;
            $wr_trans_n = 0;

            $walk_blocks = hsdWalk::FileWalkBlocks($file_name, false,
                static function($in_arr) use (&$wr_seek, &$wr_trans_n, $skip_blocks, $trans_in_last_block) {
                    $walk_trans = hsdWalk::fileWalkRecords($fd,
                        static function($in_arr) use (&$wr_seek, $trans_in_last_block) {
                            print_r($in_arr);
                            $wr_trans++;
                        }, $head_arr, $buff, $p);
                });

            //$wr_blk_n ?
            //
        } else { // file finalized, need create new hsd-file
            $wr_hsd_n = $last_hsd_n + 1;
            $start_blk += $blocks;

            $iii_arr = hsd::unpackIII($iii_str);

            $final_hash = hsdWalk::getFinalHash($file_name);
            $par_arr = [
                'hash_size' => $hash_size,
                'locker_alg' => 'LW',
                'start_blk' => $start_blk,
                'hsd_n' => $wr_hsd_n,
                'iii_arr' => $iii_arr,
            ];
            $locker_arr = $hsd->createHSD($final_hash, $par_arr, $wr_hsd_n, $start_blk);
            if (!is_array($locker_arr)) {
                return "Continue-HSD ERROR:" . $locker_arr;
            }
            $wr_trans_n = 0;
            $hash_seek = $locker_arr['hash_seek'];
            $wr_seek = $locker_arr['wr_seek'];
            $wr_blk_n = $start_blk;
        }


        $locker_str = packLocker(
            $hash_size,
            'LW',
            $wr_hsd_n,  // number of hsd-file for write
            $wr_trans_n,// transaction number(from 0 per each block)
            $wr_seek,   // seek-point for write
            $hash_seek, // seek-point to begin of block-hash calculate
            $wr_blk_n,  // current block number for write
            $start_blk, // start block number in current file
            $hsd_folder,// pointer of hsd-folder
            $iii_str    // parameters III-package for write after fixed-area
        );
        print_r($head_arr);
    }

}
