<?php
namespace ierusalim\hsd;

class hsd
{
    public $base_path;
    public $base_name;

    public $iii_arr = false;
    public $locker;
    public $fh_lock = false; // resource when lock-file opened and locked

    public $fn_hash = __CLASS__ . '::hashCalcInFile';

    public function __construct($base_path, $base_name)
    {
        $base_path = \realpath($base_path);

        if (is_string($base_path)) {
            $base_path .= DIRECTORY_SEPARATOR;
        }

        if (!is_dir($base_path)) {
            throw new \Exception("Path not found");
        }

        $this->base_path = $base_path;
        $this->base_name = $base_name;
    }

    public function makeHSDfileName($hsd_num = 1)
    {
        return
            $this->base_path .
            $this->base_name . '-' .
            bin2hex(pack('N', $hsd_num)) .
            '.hsd';
    }

    public function lockerFileName()
    {
        return
            $this->base_path .
            $this->base_name .
            '-lock.bin';
    }
/*
 Lock-file format:
 - First4 is First 4 bytes = bp4-header: 1 byte = [hashx], 2 byte = [alg], 1 byte = [ehl]
 - Next 24 bytes - fixed-size array, 7 int-values by 4 bytes:
 Attn: [ehl]-parameter in First4  =7, because 7x4 is extra-header length.
 [hashx]-parameter in First4 contains default-length of hash / 2
   hashx = 01xxxxxx (01 = DYN+INS mode bp4), xxxxxx = hash_lengt/2
 - After fixed-size-area until end of file contains iii_str-package of hsd-parameters

 Locker alg (First4 [alg] parameter) is:
  LW - write new data
  LM - mirror from remote source
  LS - storage part of old-data

 LW alg:
 4 First4 = hashx . 'LW' . 0x06:
 4 [wr_hsd_n] current number of hsd-file for writing (1,2,3...)
 4 [wr_trans_n] number of next transaction in file (= count of transactions writed in file)
 4 [wr_seek] seek point for write
 4 [hash_seek] seek-point to begin of block-hash calculate
 4 [wr_blk_n] current block number for write
 4 [st_blk_n] start block number in current file
 4 [hsd_folder] pointer of hsd-folder
After fixed area to end of file - place for iii-package with hsd-parameters.
 From this iii-package getting parameters to create next hsd-files.
 */

    /**
     * Create or rewrite Locker-file
     *
     * @param boolean $overwrite
     * @param string $locker_str
     * @return boolean|string
     */
    public function writeLocker(
        $locker_str, //data-string, packaged by self::packLocker()
        $overwrite = false
    ) {
        // check locker file
        $locker_file_name = $this->lockerFileName();
        if (!$overwrite && is_file($locker_file_name)) {
            return "HSD locker already exist";
        }

        // write locker
        $wb_cnt = file_put_contents($locker_file_name, $locker_str);
        if ($wb_cnt != strlen($locker_str)) {
            return 'Error HSD-locker write';
        }
        return false;
    }
    /**
     * Make data-string for locker-file
     *
     * @param int $hash_size
     * @param string $alg
     * @param int $wr_hsd_n
     * @param int $wr_trans_n
     * @param int $wr_seek
     * @param int $hash_seek
     * @param int $wr_blk_n
     * @param int $st_blk_n
     * @param string $iii_str
     * @return string
     */
    public static function packLocker(
        $hash_size = 32,
        $alg = 'LW',

        $wr_hsd_n = 0, // number of hsd-file for write
        $wr_trans_n = 0, // transaction number(from 0 per each block)
        $wr_seek = 0, // seek-point for write
        $hash_seek = 0, // seek-point to begin of block-hash calculate
        $wr_blk_n = 0, // current block number for write
        $st_blk_n = 0, // start block number in current file
        $hsd_folder = 0, // pointer of hsd-folder

        $iii_str // parameters III-package for write after fixed-area
    ) {

        $fix_arr = compact(
            'wr_hsd_n',
            'wr_trans_n',
            'wr_seek',
            'hash_seek',
            'wr_blk_n',
            'st_blk_n',
            'hsd_folder'
            );

        // make locker_str, first4
        $locker_str =
            chr(64 + $hash_size / 2) . // hashx = 01+010000 = DYN_INS + 16*2 =32 bytes hash
            $alg .                    //alg = LW (Writer) LM (Mirror) LS (Storage)
            chr(count($fix_arr));    // header additional length x4;

        // add fixed-area
        foreach($fix_arr as $v) {
            $locker_str .= pack('N', $v);
        }

        $locker_str .= $iii_str;

        return $locker_str;
    }

    /**
     * Unpack locker data
     *
     * @param string $str
     * @param boolean $onlyfix
     * @return array|string
     */
    public static function unpackLocker($str, $onlyfix = false)
    {
        if (!is_string($str)) {
            return "Not string";
        }

        $l = strlen($str);

        if ($l >= 32) {
            // check first4 bytes
            $hashx = ord($str[0]);
            if (($hashx & 192) != 64) {
                return "Bad 0-byte";
            }
            $alg = substr($str, 1, 2);
            $p = strpos('LWLMLSLwLmLs', $alg);
            if (($p === false) || ($p % 2)) {
                return "Unknown alg='$alg'";
            }
            $ehl = ord($str[3]) * 4;
        } else {
            return "Header too short";
        }

        if ($ehl != 28) {
            // Only 28 bytes (4 x 7 fixed-size records) supported now
            return "Unsupported fixed-size area $ehl bytes";
        }

        $hash_size = ($hashx & 31) * 2;

        $fix_keys = [
            'wr_hsd_n',
            'wr_trans_n',
            'wr_seek',
            'hash_seek',
            'wr_blk_n',
            'st_blk_n',
            'hsd_folder'
        ];
        $fix_arr = str_split(substr($str, 4, 28), 4);
        foreach($fix_arr as $k => $v) {
            $fix_arr[$k] = unpack('N', $v)[1];
        }
        $fix_arr = array_combine($fix_keys, $fix_arr);

        if ($onlyfix) {
            return compact('alg', 'hash_size', 'fix_arr');
        }

        $iii_str = substr($str, 4 + $ehl);
        $iii_arr = self::unpackIII($iii_str);
        return compact('alg', 'hash_size', 'fix_arr', 'iii_arr', 'iii_str');
    }

    public function checkHSDpar(
        $par_arr = false,
        $wr_hsd_n = 1,
        $wr_blk_n = 0
    ) {
        if ($par_arr === false) {

            $sid = $this->base_name;

            $locker_alg = 'LW';
            $hash_size = 32;
            $hash_mode = 'sha256';

            $iii_arr = [
                'sid' => $sid,
                'fil' => [
                    'fnum' => $wr_hsd_n, // number of file
                    'maxl' => 10 * 1024 * 1024, // 10M file limit
                    'maxb' => 1000, //max blocks in one file
                ],
                'blk' => [
                    'from' => $wr_blk_n,
                    'maxt' => 65535,
                    'maxs' => 8 * 1024 * 1024, // 8M block limit
                    'numb' => false, // write 4-byte block number to block tail ?
                    'time' => false, // auto-add 4-bytes unixtime to block tail ?
                    'hash' => $hash_mode,
                ],
            ];
            $par_arr = compact('hash_size', 'locker_alg', 'iii_arr');
        } elseif (!is_array($par_arr)) {
            return 'Array reqired';
        }

        // Check required keys in $par_arr
        foreach(['hash_size', 'locker_alg', 'iii_arr'] as $k) {
            if (!isset($par_arr[$k])) {
                return "Not found key [$k] in parameters array";
            }
        }
        // check required keys in $par_arr['iii_arr'] parameters array:
        foreach([
            'sid' => [],
            'fil' => ['fnum', 'maxl', 'maxb'],
            'blk' => ['from', 'maxt', 'maxs', 'numb', 'time', 'hash'],
                ] as $k => $sk_arr) {
            if (!isset($par_arr['iii_arr'][$k])) {
                return "Not found key iii_arr[$k] in parameters";
            }
            foreach($sk_arr as $sk) {
                if (!isset($par_arr['iii_arr'][$k][$sk])) {
                    return "Not found key iii_arr[$k][$sk] in parameters";
                }
            }
        }

        return $par_arr;
    }

    public function createHSD(
        $par_arr = false,
        $wr_hsd_n = 1,
        $wr_blk_n = 0,
        $prev_hash = ''
    ) {
        $hsd_folder = 0;
        // check locker
        if (!$this->fh_lock) {
            $locker_file_name = $this->lockerFileName();
            if (is_file($locker_file_name)) {
                return "HSD locker already exist";
            }
        }

        // Check $par_arr or create with default values
        $par_arr = $this->checkHSDpar($par_arr, $wr_hsd_n, $wr_blk_n);
        if (!is_array($par_arr)) {
            return $par_arr;
        }

        // Extract required parameters from $par_arr
        foreach(['hash_size', 'locker_alg', 'iii_arr'] as $k) {
            $$k = $par_arr[$k];
        }

        $iii_str = self::packIII($iii_arr);
        $this->iii_arr = $iii_arr;

        $sid = $this->base_name;

        // calculate hsd-header
        $hsd_header = self::packHSDheader($iii_str, $hash_size);

        // calculate hash_seek
        $hash_seek = strlen($hsd_header);

        // calculate wr_seek
        $pl = strlen($prev_hash);
        $wr_seek = $hash_seek;
        if ($pl) {
            if ($pl === $hash_size) {
                $wr_seek += $pl;
            } else {
                return "Bad prev-hash size = $pl";
            }
        }
        // append prev_hash to hsd file body
        $hsd_header .= $prev_hash;

        // calculate locker
        $locker_str = self::packLocker(
            $hash_size,
            'LW',
            $wr_hsd_n, // number of hsd-file for write
            0, // transaction number(from 0 per each block)
            $wr_seek, // seek point for write
            $hash_seek, // seek-point to begin of block-hash calculate
            $wr_blk_n, // current block number for write
            $wr_blk_n, // start block number in current file
            $hsd_folder, // pointer of hsd-folder
            $iii_str // parameters III-package for write after fixed-area
        );
        // write locker
        if (!$this->fh_lock) {
            $locker_arr = $this->beginWrite($locker_str);
        } else {
            rewind($this->fh_lock);
            $wb_cnt = fwrite($this->fh_lock, $locker_str);
            if ($wb_cnt != strlen($locker_str)) {
                return 'Error HSD-locker write';
            }
            fflush($this->fh_lock);
            // lock agan for re-read array
            $locker_arr = $this->beginWrite();
        }

        // write hsd-file
        $hsd_file_name = $this->makeHSDfileName($wr_hsd_n);
        $wb_cnt = file_put_contents($hsd_file_name, $hsd_header);
        if (!$this->endWrite()) {
            return "Error endWrite()";
        }
        if ($wb_cnt != strlen($hsd_header)) {
            return 'Error HSD-file write';
        }
        return $locker_arr;
    }

    /**
     * Pack HSD-header parameters to string
     *
     * @param string|array $iii_arr_or_str
     * @return string|boolean
     */
    public static function packHSDheader(
        $iii_arr_or_str,
        $hash_size = 32
    ) {
        if (is_array($iii_arr_or_str)) {
            $iii = self::packIII($iii_arr_or_str);
        } else {
            $iii = $iii_arr_or_str;
        }
        if (!is_string($iii)) {
            return false;
        }
        $l = strlen($iii);
        if ($l > 1020) {
            return false;
        }
        if ($l) {
            $lc = substr($iii, -1);
            if ($lc === chr(0)) {
                return false;
            }
            $addz = $l % 4;
            if ($addz) {
                $iii .= str_repeat(chr(0), 4 - $addz);
                $l += $addz;
            }
        }

        return
            chr(64 + $hash_size / 2) .    // hashx = 01+010000 = DYN_INS + 16*2 =32 bytes hash
            'hs' .              //alg = hs
            chr(($l + 4) / 4) . // header additional length
            pack('N', 0) .      // reserved 4 bytes for in-file blocks counter
            $iii;               // iii-package
    }

    public static function unpackHSDheader($str)
    {
        $l = strlen($str);
        if ($l < 8) {
            return false;
        }
        $hashx = ord($str[0]);
        $alg =  substr($str, 1, 2);
        if (($hashx & 0xC0 != 64) || $alg != 'hs') {
            return false;
        }
        $hash_size = ($hashx & 63) * 2;

        $hl = ord($str[3]) * 4;
        if ($l < $hl + 4) {
            return false;
        }

        // file-finalize state: if >0 is blosk_cnt, if <0 is seek-point
        // format:
        //    "ff xx xx xx" - blocks cnt,
        // or "xx xx xx xx" - seek-point of end of last finalized block
        $blocks = substr($str,4,4);
        if ($blocks[0] == chr(255)) {
            $blocks[0] = chr(0);
            $blocks = unpack('N', $blocks)[1];
        } else {
            $blocks = -unpack('N', $blocks)[1];
        }

        $l = $hl + 8;
        for($i = 1; $i<5; $i++) {
            $e = $l - $i;
            if (isset($str[$e]) && ord($str[$e])) break;
        }

        $iii_str = substr($str, 8, $e - 11);
        $iii_arr = self::unpackIII($iii_str);
        $iii_arr['hash_size'] = $hash_size;
        $iii_arr['alg'] = $alg;
        $iii_arr['seek'] = $l - 4;
        $iii_arr['blocks'] = $blocks;
        return $iii_arr;
    }

    /**
     * Pack INS
     *
     * What is INS? It is integer from -16383 to +4194303
     *  packaged into 1..3 bytes by hsd-ins format.
     *
     * 0-127 => 1 byte
     * 128-16383 => 2 byte
     * 16384-4194303 => 3 byte
     * Neg:
     * -127..-1 => 2 byte
     * -16383..-128 => 3 byte
     *
     * 0xxx xxxx - 1 byte (0-127)
     * 10xx xxxx  xxxx xxxx - 2 byte (128-16383)
     * 11xx xxxx  xxxx xxxx  xxxx xxxx - 3 byte (16384-4194303)
     * Neg:
     * 1000 0000  0xxx xxxx - 2 byte (-0 .. -127)
     * 1100 0000  00xx xxxx  xxxx xxxx - 3 byte (-16383 .. - 128)
     * 1100 0000  0000 0000  0xxx xxxx - 3 byte (reserved alt -0 .. -127)
     *
     * @param integer $nmb
     * @return string 1-3 bytes
     */
    public static function packINS($nmb)
    {
        if ($nmb < 0) {
            $nmb = -$nmb;
            if ($nmb < 128) {
                return pack('n', $nmb + 32768);
            } elseif ($nmb < 16384) {
                $s = pack('N', $nmb + 12582912);
                return substr($s, -3);
            }
        } else {
            if ($nmb < 128) {
                return chr($nmb);
            } elseif ($nmb < 16384) {
                return pack('n', $nmb + 32768);
            } elseif ($nmb < 4194304) {
                $s = pack('N', $nmb + 12582912);
                return substr($s, -3);
            }
        }
        return false;
    }
    /**
     * Unpack 1-3 bytes hsd-ins format to integer
     *
     * See packINS function
     *
     * @param integer $first_byte_n 0-255
     * @param string $next_bytes | 0 or 1 or 2 bytes
     * @return integer
     */
    public static function unpackINS($first_byte_n, $next_bytes)
    {
        $fc = $first_byte_n & 63;
        switch ($first_byte_n & 192) {
            case 0:
            case 64:
                return $first_byte_n & 127;
            case 192:
                $n256 = ord($next_bytes[0]);
                $n = $fc * 65536 + ord($next_bytes[1]);
                $fc = $fc ? $fc : ($n256 & 192);
                break;
            case 128:
                $n256 = $fc;
                $n = ord($next_bytes[0]);
                $fc = $fc ? $fc : ($n & 128);
        }
        $n += $n256 * 256;
        return $fc ? $n : -$n;
    }

    /**
     * III-format = array to string serialize, like serialize(), json_encode(), etc.
     *
     * ->packIII($arr)   = Pack array to string
     * ->unpackIII($str) = Unpack array from string
     *
     * Sub-arrays supported.
     *
     * Limits:
     * - array keys must have length between 1-33 bytes
     * - max length of string element is 65535 bytes
     * - numeric array keys 0,1,2.. accepted as string keys '0', '1', '2',...
     *
     * Format each element: 1 header byte, then 0,1,2 or 4 bytes.
     * bbbn nnnn
     * |||\----/-- name length 00000-11111 = 1-33
     * \|/-------- type of data
     * Types of data:
     * 000x xxxx - boolean false
     * 001x xxxx - int 1 byte
     * 010x xxxx - int 2 byte
     * 011x xxxx - int 4 byte
     * 100x xxxx - boolean true
     * 101x xxxx - string 1 byte length
     * 110x xxxx - string 2 byte length
     * 111x xxxx - special int 4 byte ext
     *  \/-------- 00 = +0 bytes, 01 = +1 byte, 10 = +2 byte, 11 = +4 byte
     * si (special int 4 byte) value (from 0 to 2^32=4294967296) means:
     * si = 0 = -1
     * si in [1-255] = numeric value in string length 0-255
     * si in [256-2^32] =  si/256 length of nested array III-package
     *
     * @param array $arr
     * @return string|false
     */
    public static function packIII($arr)
    {
        $res = [];
        foreach($arr as $n => $v) {
            $l = strlen($n);
            if ($l <1 || $l>33) return false;

            $l = $b = $l - 1;

            $t = gettype($v);
            switch ($t) {
            case 'boolean':
                if ($v) {
                    $b += 128;
                }
                $c = '';
                break;
            case 'float':
            case 'double':
            case 'integer':
                $c = pack('N', strlen($v)) . $v;
                $b += 224;
                if ((floor($v) != $v) || ($v < -1)) {
                    break;
                }
                if ($v == -1) {
                    $c = pack('N', 1);
                } elseif ($v < 256) { // 001 0 0000
                    $b = 32 + $l;
                    $c = chr($v);
                } elseif ($v < 65536) { //010 0 0000
                    $b = 64 + $l;
                    $c = pack('n', $v);
                } elseif ($v < 4294967296) { //011 0 0000
                    $b = 96 + $l;
                    $c = pack('N', $v);
                }
                break;
            case 'array':
                $apack = self::packIII($v);
                if (!is_string($apack)) {
                    return false;
                }
                $b += 224;
                $c = pack('N', strlen($apack) * 256) . $apack;
                break;
            case 'object':
                $v = (string)$v;
                if (!is_string($v)) {
                    return false;
                }
            case 'string':
                $l = strlen($v);
                if ($l < 256) {
                    $c = chr($l);
                    $b += 160;     //101 0 0000
                } elseif ($l < 65536) {
                    $c = pack('n', $l);
                    $b += 192;    // 110 0 0000
                } else {
                    return false;
                }
                $c .= $v;
                break;
            default:
                // unsupported type of value
                return false;
            }
            $res[] = chr($b) . $n . $c;
        }
        //$res[] = chr(0);
        return implode($res);
    }

    /**
     * Unpack III string, packaged by packIII function, back to array
     *
     * @param string $str
     * @return array
     */
    public static function unpackIII($str)
    {
        $arr = [];
        $p = 0;
        while($p < strlen($str)) {
            $b = ord($str[$p++]);
            $l = ($b & 31) + 1;
            $name = substr($str, $p, $l);
            $p += $l;
            $addb = ($b & 96) / 32;
            if ($addb) {
                if ($addb == 3) $addb++;
                $c = substr($str, $p, $addb);
                switch($addb) {
                case 1:
                    $c = ord($c);
                    break;
                case 2:
                    $c = unpack('n', $c)[1];
                    break;
                case 4:
                    $c = unpack('N', $c)[1];
                }
                $p += $addb;
            }
            switch(($b & 224) / 32) {
                case 0: // 000 boolean false
                case 4: // 100 boolean true
                    $v = ($b & 128) == 128;
                    break;
                case 7:
                    if ($c != 1) {
                        $b = ($c > 256);
                        if ($b) {
                            $c = $c / 256;
                        }
                        $v = substr($str, $p, $c);
                        $p += $c;
                        if ($b) {
                            $c = self::unpackIII($v);
                        } else {
                            // Don't convert to double, only integer
                            $c = (int) $v;
                            if ((string)$c !== (string)$v) {
                                $c = $v;
                            }
                        }
                    } else {
                        $c = -1;
                    }
                case 1: // 001 integer 1 b
                case 2: // 010 integer 2 b
                case 3: // 011 integer 4 b
                    $v = $c;
                    break;
                case 5: // 101 string 1 b len
                case 6: // 110 string 2 b len
                    $v = substr($str, $p, $c);
                    $p += $c;
            }
            $arr[$name] = $v;
        }
        return $arr;
    }

    public function beginWrite($new_locker_data = false)
    {
        if (false === $this->fh_lock) {
            if (is_string($new_locker_data)) {
                $this->fh_lock = fopen($this->lockerFileName(), "wb+");
            } else {
                $this->fh_lock = fopen($this->lockerFileName(), "rb+");
            }
            if (false === $this->fh_lock) {
                return "Can't open locker-file";
            }
            if (flock($this->fh_lock, \LOCK_EX)) {
                if (is_string($new_locker_data)) {
                    fwrite($this->fh_lock, $new_locker_data);
                    $str = substr($new_locker_data, 0, 32);
                } else {
                    $str = fread($this->fh_lock, 32);
                }
            } else {
                // Can't lock
                fclose($this->fh_lock);
                $this->fh_lock = false;
                return "Can't lock lock-file";
            }
        } else {
            rewind($this->fh_lock);
            $str = fread($this->fh_lock, 32);
        }

        $locker_arr = self::unpackLocker($str, true);
        if (!is_array($locker_arr)) {
            // Can't bad Locker
            flock($this->fh_lock, LOCK_UN); // unlock
            fclose($this->fh_lock);
            $this->fh_lock = false;
            return "Locker-file error: $locker_arr";
        }

        if ($this->iii_arr === false) {
            fseek($this->fh_lock, 32);
            $str = fread($this->fh_lock, 1100);
            $this->iii_arr = self::unpackIII($str);
        }

        $this->locker = $locker_arr;
        return $locker_arr;
    }

    public function endWrite(
        $new_trans_n = false,
        $new_seek = false,

        $new_hash_seek = false,
        $new_blk_n = false
    ) {
        $fp = $this->fh_lock;
        if (false === $fp) {
            return false;
        }
        if (is_numeric($new_trans_n) && is_numeric($new_seek)) {
            $str = pack('N', $new_trans_n) . pack('N', $new_seek);
            if (8 != strlen($str)) {
                $str = false;
            } elseif (is_numeric($new_hash_seek) && is_numeric($new_blk_n)) {
                $str .= pack('N', $new_hash_seek) . pack('N', $new_blk_n);
                if (16 != strlen($str)) {
                    $str = false;
                } else {
                    $this->locker['fix_arr']['hash_seek'] = $new_hash_seek;
                    $this->locker['fix_arr']['wr_blk_n'] = $new_blk_n;
                }
            }
            if (false !== $str) {
                $this->locker['fix_arr']['wr_trans_n'] = $new_trans_n;
                $this->locker['fix_arr']['wr_seek'] = $new_seek;
                fseek($fp, 8);
                $wsize = fwrite($fp, $str);
                fflush($fp);       // write out
                if ($wsize != strlen($str)) {
                    $str = false;
                }
            }
        } else {
            $str = true;
        }
        flock($fp, LOCK_UN); // unlock
        fclose($fp);
        $this->fh_lock = false;

        return ($str !== false);
    }

    public function appendRecord($data, $fn_final_check = true)
    {
        if (!is_string($data)) {
            return false;
        }

        $rec_size = strlen($data); // max data length = 4194303 (=4Mb)
        if ($rec_size > 4194303) {
            return false;
        }

        // 1. Lock for write
        $locker_arr = $this->beginWrite();
        if (!is_array($locker_arr)) {
            return "Can't lock write for append record: $locker_arr";
        }

        $hash_size = $locker_arr['hash_size'];

        // 2. Check finalization (if need)
        if ($fn_final_check !== false) {
            if ($fn_final_check === true) {
                $fn_final_check = __CLASS__ . '::stdFinalCheck';
            }
            // function must return false if no need finalize
            // or integer finalize-length, if need finalize
            $final_size = call_user_func($fn_final_check, [
                'rec_size' => &$rec_size,
                'locker_arr' => &$locker_arr,
                'iii_arr' => &$this->iii_arr,
                ]);
        } else {
            $final_size = false;
        }

        if ($final_size === false) {
            $prefix = $this->packINS($rec_size);
            $file_finalize = false;
        } else {
            $file_finalize = ($final_size < 0);
            $final_size = abs($final_size);
            if (($final_size > 16383) || ($final_size <0) || ($rec_size > $final_size)) {
                return false;
            }
            $prefix = $this->packINS(-$final_size);
            $ost_len = $final_size - $rec_size - 4 - $hash_size;

            if ($ost_len < 0) {
                // Final-record size too small
                return 'Final record too small: ' . (-$ost_len) . ' bytes is missing';
            }

        }

        // 3. Calc current file pointer
        $wr_hsd_n = $locker_arr['fix_arr']['wr_hsd_n'];
        $blk_n = $locker_arr['fix_arr']['wr_blk_n'];
        $file_dat = $this->makeHSDfileName($wr_hsd_n);

        $fd = fopen($file_dat, 'rb+');

        if (!$fd) {
            $this->endWrite();
            return "Can't open data file=$file_dat for append record";
        }

        // Write INS prefix
        $wr_seek = $this->locker['fix_arr']['wr_seek'];

        if (fseek($fd, $wr_seek)) {
            $this->endWrite();
            fclose($fd);
            return "Can't fseek to write-point in file=$file_dat for append record";
        }
        $pl = strlen($prefix);
        $wbcnt = @\fwrite($fd, $prefix);
        if ($wbcnt === $pl) {
            // Write data after prefix
            $wbcnt = @\fwrite($fd, $data, $rec_size);
            fflush($fd); // write out
        } else {
            $rec_size = $pl;
        }
        if ($wbcnt !== $rec_size) {
            fclose($fd);
            $this->endWrite();
            return "Write data error. Size=$wbcnt not equal record_size=$rec_size in block=$blk_n";
        }

        $trans_n = $this->locker['fix_arr']['wr_trans_n'];
        $new_trans_n = $trans_n + 1;
        $new_seek = $wr_seek + $pl + $wbcnt;

        $new_hash_seek = false;
        $new_blk_n = false;

        // 4. if finalize - hash calculate
        if ($final_size) {
            // Previous hash-point
            $hash_seek = $this->locker['fix_arr']['hash_seek'];
            // New hash-point
            $new_hash_seek = $wr_seek + $pl + $final_size - $hash_size;

            $block_len = $new_hash_seek - $hash_seek;
            // Write block-finalize parameters:
            $block_size = pack('N', $block_len);
            $wbcnt = @\fwrite($fd, $block_size);
            fflush($fd); // write out
            if ($wbcnt != 4) {
                $this->endWrite();
                fclose($fd);
                return "Write data error. File=$file_dat";
            }

            if (fseek($fd, $hash_seek)) {
                $this->endWrite();
                fclose($fd);
                return "Can't fseek in file=$file_dat for finalize record";
            }
            // Calculate hash from current seek-point
            $final_hash = call_user_func($this->fn_hash, $fd, $block_len);
            if (!is_string($final_hash)) {
                $this->endWrite();
                fclose($fd);
                return "Can't calculate finalization hash by $file_dat";
            }

            if (strlen($final_hash) == $hash_size) {
                // Write final_hash if size correctly
                $f_cnt = @\fwrite($fd, $final_hash, $hash_size);
                // Change pointers to next block
                $new_trans_n = 0;
                $new_seek = $new_hash_seek + $hash_size;
                $new_blk_n = $blk_n + 1;
            } else {
                $this->endWrite();
                fclose($fd);
                return "Can't finalize block: bad final-hash size ($final_len != $hash_size)";
            }
            // Write new_hash_seek to 4-bytes header-value
            if ($file_finalize) {
                $file_finalizator = "END";
                $file_finalizator .= pack('N', strlen($file_finalizator));
                fseek($fd, $new_seek);
                $wbcnt = fwrite($fd, $file_finalizator);
                $new_seek += $wbcnt;
                ftruncate($fd, $new_seek);

                $blocks_cnt = $new_blk_n - $this->locker['fix_arr']['st_blk_n'];
                $wr4 = pack('N', $blocks_cnt);
                $wr4[0] = chr(255);
            } else {
                $wr4 = pack('N', $new_hash_seek);
            }
            fseek($fd, 4);
            fwrite($fd, $wr4);
        }

        fclose($fd);

        if ($file_finalize) {
            $new_hsd_n = $wr_hsd_n + 1;
            $iii_arr = $this->iii_arr;
            $iii_arr['fil']['num'] =  $new_hsd_n;
            $iii_arr['blk']['from'] = $new_blk_n;
            $this->iii_arr = $iii_arr;
            $par_arr = [
                'hash_size' => $hash_size,
                'locker_alg' => $this->locker['alg'],
                'iii_arr' => $iii_arr,
            ];
            $ok = $this->createHSD($par_arr, $new_hsd_n, $new_blk_n, $final_hash);
            if (!is_array($ok)) {
                return "Continue-HSD ERROR:" . $ok;
            }
        } else {
            $ok = $this->endWrite(
                $new_trans_n,
                $new_seek,

                $new_hash_seek,
                $new_blk_n
                );
        }
        if ($ok) {
            return compact(
                'trans_n',
                'blk_n',
                'wr_hsd_n',
                'file_finalize'
                );
        } else {
            return 'endWrite error';
        }
    }

    public static function stdFinalCheck($in_arr)
    {
        // Extract parameters:
        $rec_size = $in_arr['rec_size']; // current record size
        $hash_size = $in_arr['locker_arr']['hash_size'];

        // Extract locker parameters:
        extract($in_arr['locker_arr']['fix_arr']);
        // $wr_seek, $hash_seek, $wr_trans_n, $wr_blk_n, $st_blk_n

        // check limit of transactions count in block
        $fin_block = ($wr_trans_n >=  $in_arr['iii_arr']['blk']['maxt']);
        // check limit of block size
        $current_block_size = $wr_seek + $rec_size + 3 - $hash_seek;
        if ($current_block_size > $in_arr['iii_arr']['blk']['maxs']) {
            $fin_block = true;
        }

        // check limit of file size
        $current_file_size = $rec_size + $wr_seek + $hash_size + 8;
        $fin_file = ($current_file_size > $in_arr['iii_arr']['fil']['maxl']);

        $blocks_in_this_file = $wr_blk_n - $st_blk_n;
        if ($fin_block) {
            $blocks_in_this_file++;
        }
        if ($blocks_in_this_file >= $in_arr['iii_arr']['fil']['maxb']) {
            $fin_file = true;
        }


/* $in_arr is:
[rec_size] => 8
[locker_arr] => Array
    (
        [alg] => LW
        [hash_size] => 32
        [fix_arr] => Array
            (
                [wr_hsd_n] => 4
                [wr_trans_n] => 3
                [wr_seek] => 41518
                [hash_seek] => 41189
                [wr_blk_n] => 30
                [st_blk_n] => 4
            )

    )

[iii_arr] => Array
    (
        [sid] => 0123456789abcdef
        [fil] => Array
            (
                [fnum] => 4
                [maxl] => 10485760
                [maxb] => 1000
            )

        [blk] => Array
            (
                [from] => 4
                [maxt] => 65535
                [maxs] => 8388608
                [numb] =>
                [time] =>
                [hash] => sha256
            )

    )
         */
        if ($fin_block || $fin_file) {
            $fin_size = $hash_size + 4 + $rec_size;
            if ($fin_file) {
               return -$fin_size;
            }
            return $fin_size;
        }
        return false;
    }

    public static function hashCalcInFile($fd, $bytes_len, $hash_name = 'sha256')
    {
        $hs = hash_init($hash_name);
        $size = hash_update_stream($hs, $fd, $bytes_len);
        if ($bytes_len != $size) return false;
        $hash = hash_final($hs, true);
        return $hash;
    }

    public static function FileWalkBlocks($file_name, $file_size = false, $fn_every_block = false)
    {
        if  (!is_file($file_name)) {
            return 'File not found';
        }
        if (!$file_size) {
            $file_size = filesize($file_name);
        }
        $fd = fopen($file_name, 'rb');
        if (!$fd) {
            return "Can't open source file $file_name";
        }

        // get header
        $head_arr = self::unpackHSDheader(fread($fd, 1100));
        if (!is_array($head_arr)) {
            return 'Bad file format';
        }
        $hash_size = $head_arr['hash_size'];

        $last_hash_point = $head_arr['blocks'];
        if (!$last_hash_point) {
            return "No finalized blocks";
        } elseif($last_hash_point>0) {
            // File finalized
            fseek($fd, $file_size - 4);
            $fin_len = fread($fd, 4);
            $fin_len = unpack('N', $fin_len)[1];
            $last_hash_point = $file_size - $fin_len - 4 - $hash_size;
        } else {
            $last_hash_point = -$last_hash_point;
        }

        $st_blk_n = $head_arr['blk']['from'];
        $data_seek = $head_arr['seek'];

        $len_arr = [];
        // Blocks counting from tail to head
        while($last_hash_point > $data_seek) {
            fseek($fd, $last_hash_point - 4);
            $block_len = fread($fd, 4);
            $block_len = unpack('N', $block_len)[1];
            $len_arr[] = $block_len;
            $last_hash_point -= $block_len;
        }

        $blocks_cnt = count($len_arr);
        $blocks_arr = array_fill($st_blk_n, $blocks_cnt, 0);
        $blocks_arr['from'] = $st_blk_n;
        $blocks_arr['blocks_cnt'] = $blocks_cnt;

        for($p = $blocks_cnt - 1; $p >= 0; $p--) {
            $blocks_arr[$st_blk_n++] = $len_arr[$p];
        }

        $blk = $head_arr['blk'];
        $blk['hash_size'] = $hash_size;
        if ($fn_every_block !== false) {
            $seek = $data_seek;
            $st_blk_n = $blocks_arr['from'];
            for($n = 0; $n < $blocks_cnt; $n++) {
                $blk_n = $st_blk_n + $n;
                $block_len = $blocks_arr[$blk_n];
                $result = call_user_func($fn_every_block,
                    ['fd' => $fd,
                     'seek' => $seek,
                     'block_len' => $block_len,
                     'blk_n' => $blk_n,
                     'blk' => &$blk,
                    ]);
                $seek += $block_len;
                if ($result === false) break;
                $blocks_arr[$blk_n] = $result;
            }
        }
        fclose($fd);
        return $blocks_arr;
    }

    public static function FileVerifyBlockHashes(
        $file_name,
        $ret_err_cnt = true,
        $fn_hash = __CLASS__. '::hashCalcInFile'
    ) {
        $errors = 0;
        $walk = self::FileWalkBlocks($file_name, false,
        function($par_arr) use ($fn_hash, &$errors) {
            extract($par_arr);// $fd, $seek, $block_len, $blk_n, $blk

            $hash_size = $blk['hash_size'];
            $hash_name = $blk['hash'];

            $hash_seek = $seek + $block_len;
            fseek($fd, $hash_seek);
            $hash_bin = fread($fd, $hash_size);
            // calculate real hash
            fseek($fd, $seek);
            $real_hash = call_user_func($fn_hash, $fd, $block_len, $hash_name);

            if ($real_hash == $hash_bin) {
                $ok = "OK";
            } else {
                $ok = "FAIL";
                $errors++;
            }
            return $ok;
        });
        if (!is_array($walk)) {
            return $walk;
        }
        if ($ret_err_cnt) {
            return $errors;
        }
        $walk['errors'] = $errors;
        return $walk;
    }
    public static function FileWalkTrans($file_name, $fn_every_trans)
    {
        if (!is_file($file_name)) {
            return 'File not found';
        }
        $fd = fopen($file_name, 'rb');
        if (!$fd) {
            return "Can't open source file $file_name";
        }

        // get header
        $seek = 1100;
        $buff = fread($fd, $seek);
        $head_arr = self::unpackHSDheader($buff);
        if (!is_array($head_arr)) {
            return 'Bad file format';
        }

        $blk = $head_arr['blk'];

        $p = $head_arr['seek'];

        //function for buffered-reading from file
        $reader = function($len, $max_read = 1100) use ($fd, &$eof, &$seek, &$buff, &$p) {
            // return: string from buff, side effect: set $eof and change pointers
            // if no enought data in buff, read data from file-resource $fd to buff.
            // pointer $seek is the place for reading data to buff

            // result: $data
            // side effects: set $eof value and change pointers
            $eof = false;
            $l = strlen($buff);
            $ost = $l - $p; // how many not-readed bytes have in buffer?
            if ($len <= $ost) {
                //return the result from buffer if possible
                $data = substr($buff, $p, $len);
                $p += $len;
            } else {
                //read new data from file to buffer, if need
                $data = substr($buff, $p); // but, previously, return data remaining in buffer
                $buff = ''; //and clear buffer
                $p = 0;
                if (feof($fd)) {
                    //can't read new data if end of file is reached, but return data remaining in buffer
                    $eof = true;
                } else {
                    // read new data from file (size limited by $max_read)
                    $buff = fread($fd, $max_read);
                    if (false === $buff) {
                        // if no data - set eof flag
                        $eof = true;
                    } else {
                        $seek += strlen($buff);
                        $p = $len - $ost;
                        $data .= substr($buff, 0, $p);

                        if (feof($fd)) { //if file resource set EOF, also set eof if buffer ended
                            $eof = !($p < strlen($buff));
                        }
                    }
                }
            }
            return $data;
        };

        $eof = false;

        while (!$eof) {
            // Read INS

            $data = $reader(1);

            if ($eof) break; //eof reached - no more records

            $first_byte_n = ord($data); // 1 byte expected

            // how many bytes need to read, for receive full INS ?
            $fc = ($first_byte_n & 192) / 64;
            if ($fc > 1) {
                $data = $reader($fc - 1);
            }
            // unpack INS
            $ins = self::unpackINS($first_byte_n, $data);
            $a = abs($ins); // framgent length

            // read INS data
            $data = $reader($a, $a + 3);

            // call user-function on readed data.
            if (call_user_func($fn_every_trans, $ins, [
                'data' => &$data,
                'blk'  => &$blk,
            ])) {
                break;
            }
        }
        fclose ($fd);
        return $head_arr;
    }
}
