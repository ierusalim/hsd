<?php
namespace ierusalim\hsd;

class hsd
{
    public $base_path; //init on construct
    public $base_name; //init on construct
    public $sid_bin;   //init on construct
    public $hsd_folder;//init on construct
    public $hsd_n;     //init on construct

    public $hsd_f = false; // resource of opened hsd-file (openWrite)
    public $block_n;   //init on openWrite
    public $abs_p;     //init on openWrite


    public $hash_size = 32;     //reload in loadMan on construct (if man exists)
    public $hash_alg = 'sha256';//reload in loadMan on construct (if man exists)

    public $sign_alg = 'btc'; // bitcoin sign algorithm
    public $signer_a160 = false; // signer addr (20 bytes)
    private $ec; // elliptic-curve object with private key

    // man parameters
    public $fil_maxl = 10 * 1024 * 1024; // 10M file limit
    public $fil_maxb = 1000; //max blocks in one file
    public $blk_maxs = 8 * 1024 * 1024; // block size limit (8M)
    public $blk_maxt = 65535; //max transactions in block
    public $blk_numb = false; // auto-add 4-byte block number to block-fin ?
    public $blk_time = false; // auto-add 4-bytes unixtime to block-fin ?

    public $man_arr = false;
    public $man_str;

    public function __construct($base_path, $sid_bin)
    {
        $base_path = \realpath($base_path);

        if (is_string($base_path)) {
            $base_path .= DIRECTORY_SEPARATOR;
        }

        if (!is_dir($base_path)) {
            throw new \Exception("Path not found");
        }

        if (strlen($sid_bin) != 8) {
            throw new \Exception("Bad sid length (expect 8)");
        }

        $base_name = bin2hex($sid_bin);

        $sid_path = $base_path . $base_name;
        if (!is_dir($sid_path) && !mkdir($sid_path)) {
            throw new \Exception("Can't create sid_path");
        }

        $this->base_path = $base_path;
        $this->base_name = $base_name;
        $this->sid_bin = $sid_bin;
        $cell_arr = $this->hsdFolderCell($sid_bin);
        if ($cell_arr === false) {
            throw new \Exception("Can't update streams.list");
        }
        $this->hsd_folder = $cell_arr['cell_num'];
        $this->hsd_n = $cell_arr['hsd_n'];

        $this->loadMan();
    }

    /**
     * Read last or first hash from finalized hsd-file or from hash-file
     *
     * Return: string-hash or false if error
     *
     * @param int $hsd_n
     * @param int $read_last 1 = read last hash, 0 = read first (prev) hash
     * @return string
     */
    public function readEdgeHash($hsd_n = false, $read_last = 1)
    {
        $parr = $this->openRead($hsd_n);
        if (!is_array($parr)) {
            return false;
        }
        $f = $parr['f'];
        $hash_size = $parr['hash_size'];
        $in_blk_n = $parr['blocks_cnt'];
        $edge_hash = false;
        if ($parr['ff']) {
            // File Finalized
            if (!fseek($f, $parr['wr_seek'] + $in_blk_n * 4 + 4 + $hash_size * $read_last)) {
                $edge_hash = fread($f, $hash_size);
            }
        } else {
            // File NOT finalized
            $edge_hash = $this->readHashFile($in_blk_n * $read_last, $hash_size, $hsd_n);
        }
        fclose($f);
        if (!is_string($edge_hash) || (strlen($edge_hash) != $hash_size)) {
            $edge_hash = false;
        }
        return $edge_hash;
    }
    public function readPrevHash($hsd_n = false)
    {
        if ($hsd_n === false) {
            $hsd_n = $this->hsd_n;
        }
        if (!is_numeric($hsd_n) || ($hsd_n < 1)) {
            return false;
        }
        $hsd_n--;
        if (!$hsd_n) {
            return $this->calcZeroHash();
        }
        return $this->readEdgeHash($hsd_n, 1);
    }

    /**
     * HSD Header:
     * 0000 INS H hashL WF
     * 0004 FF blocks
     * 0008 start_blk
     * 0012 start_abs_p
     * 0016 start_abs_p
     * 0020 sid_bin
     * 0024 sid_bin
     * 0028 wr_seek -> seek_table
     * 0032 blk_seek ->cover_len [=0 if file sinalized without hashes]
     * 0036
     *
     * @param int $blocks_cnt count of blocks in this file
     * @param int $start_blk start block number in global stream
     * @param int $start_abs absolut point in global stream
     * @return string (36 bytes)
     */
    public function packHSDhead($blocks_cnt, $start_blk, $start_abs)
    {
        $ins = 35;
        $data = pack('CCCCNNJA8NN',
            $ins,
            72, // H
            $this->hash_size,
            0,

            $blocks_cnt,
            $start_blk,
            $start_abs,

            $this->sid_bin,
            $ins + 1,
            $ins + 1
            );

        return $data;
    }

    /**
     * Unpack hsd-file header
     *
     * In: data string
     * Out: array with keys
     *  [ff] => File Finalized flag (1 - file finalized / 0 - not finalized)
     *  [hash_size] => 1-127
     *  [wf] => writing flag. (0 = normal state / else - broken write)
     *  [blocks_cnt] => count blocks in file
     *  [start_blk] => number of start block in file
     *  [start_abs] => absolute position of start block in file
     *  [sid_bin]
     *  [wr_seek] => curr.write point / seek_table point if FF
     *  [blk_seek] => start of last block / cover_len if FF
     *  [hc] = true/false hash need calculate flag (from hash_size byte)
     *
     * @param string $data
     * @return array|string
     */
    public function unpackHSDhead($data)
    {
        if (!is_string($data) || strlen($data) < 36) {
            return "Bad data format";
        }
        $ins_size = ord($data[0]);
        if ((ord($data[1]) != 72) || strlen($data) <= $ins_size) {
            return "Bad data format";
        }
        $arr = unpack('Cff/Chash_size/Cwf/Nblocks_cnt/Nstart_blk/Jstart_abs/A8sid_bin/Nwr_seek/Nblk_seek', substr($data, 1, $ins_size));
        $bcnt = $arr['blocks_cnt'];
        if ($bcnt > 4278190079) {
            $arr['blocks_cnt'] = $bcnt - 4278190080;
            $arr['ff'] = 1;
        } else {
            $arr['ff'] = 0;
        }
        if($arr['hash_size'] & 128) {
            $arr['hash_size'] = $arr['hash_size'] & 127;
            $arr['hc'] = true;
        } else {
            $arr['hc'] = false;
        }
        $arr['bsize'] = $ins_size + 1;
        return $arr;
    }

    public function makeHSDfileName($hsd_name = false)
    {
        if ($hsd_name === false) {
            $hsd_name = $this->hsd_n;
        }
        return
            $this->base_path .
            $this->base_name . DIRECTORY_SEPARATOR .
            $this->base_name . '-' .
            (is_numeric($hsd_name) ?
                bin2hex(pack('N', $hsd_name)) . '.hsd' : $hsd_name
            );
    }

    public function satFileName($char, $hsd_n = false)
    {
        if ($hsd_n === false) {
            $hsd_n = $this->hsd_n;
        }
        $hsd_name = bin2hex(pack('N', $hsd_n)) . $char . '.sat';
        return $this->makeHSDfileName($hsd_name);
    }

    public function writeMan($man_arr = false) {
        if ($man_arr === false) {
            $man_arr = $this->makeManArr();
        }
        if (!is_array($man_arr)) {
            return false;
        }
        $man_str = self::packIII($man_arr);

        $l = strlen($man_str);
        if (($l > 999) || ($l < 20)) {
            return false;
        }
        $this->man_arr = $man_arr;
        $this->man_str = $man_str;
        $man_file = $this->makeHSDfileName('man.bin');
        return file_put_contents($man_file, $man_str);
    }
    public function readMan($re_load = false)
    {
        if (($this->man_arr === false) || $re_load) {
            $man_file = $this->makeHSDfileName('man.bin');
            if (is_file($man_file)) {
                $man_str = file_get_contents($man_file, false, null, 0, 1024);
            }
            if (empty($man_str)) {
                return false;
            }
            $this->man_str = $man_str;
            $this->man_arr = self::unpackIII($man_str);
        }
        return $this->man_arr;
    }
    public function loadMan()
    {
        $arr = $this->readMan();
        if (!is_array($arr)) {
            return $arr;
        }
        if (($arr['sid'] != $this->sid_bin) || !isset($arr['blk']['hash'])) {
            return false;
        }
        $hash_alg = $arr['blk']['hash'];
        $test_hash = hash($this->hash_alg, $this->hash_alg, true);
        if (empty($test_hash)) {
            return false;
        }
        $this->hash_size = strlen($test_hash);
        foreach([
            'maxl' => 'fil_maxl',
            'maxb' => 'fil_maxb',
            'salg' => 'sign_alg',
            'a160' => 'signer_a160'] as $k => $z
        ) {
            if (isset($arr['fil'][$k])) {
                $this->$z = $arr['fil'][$k];
            }
        }
        foreach([
            'maxt' => 'blk_maxt',
            'maxs' => 'blk_maxs',
            'numb' => 'blk_numb',
            'time' => 'blk_time',
            'hash' => 'hash_alg'] as $k => $z
        ) {
            if (isset($arr['blk'][$k])) {
                $this->$z = $arr['blk'][$k];
            }
        }
        return $arr;
    }
    public function makeManArr()
    {
        if (empty($this->signer_a160)) {
            return false;
        }
        return
        [
            'sid' => $this->sid_bin,
            'fil' => [
                'maxl' => $this->fil_maxl, //file size limit
                'maxb' => $this->fil_maxb, //max blocks in one file
                'salg' => $this->sign_alg, //btc
                'a160' => $this->signer_a160, // signer a160
            ],
            'blk' => [
                'maxt' => $this->blk_maxt, // max transactions in block
                'maxs' => $this->blk_maxs, // block size limit
                'numb' => $this->blk_numb, // auto-add 4-byte block number to block-fin ?
                'time' => $this->blk_time, // auto-add 4-bytes unixtime to block-fin ?
                'hash' => $this->hash_alg,
            ],
        ];
    }

    public function setSigner($ec, $sign_alg = 'btc')
    {
        if (!is_string($sign_alg) || strlen($sign_alg) > 15) {
            return "Bad signature algorithm specified";
        }

        $signer_a160 = hex2bin($ec->geta160());

        if (!is_string($signer_a160) || strlen($signer_a160) != 20) {
            return "Bad signer_id";
        }

        $this->signer_a160 = $signer_a160;
        $this->sign_alg = $sign_alg;
        $this->ec = $ec;

        return false;
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
     * 0xxx xxxx - 1 byte (0-127) [0 means EOB with zero size finish-data]
     * 10xx xxxx  xxxx xxxx - 2 byte (128-16383)
     * 11xx xxxx  xxxx xxxx  xxxx xxxx - 3 byte (16384-4194303)
     * Neg:
     * 1000 0000  0xxx xxxx - 2 byte (-0 .. -127) [means EOB with finish-data]
     * 1000 0000  0000 0000 = [means zero-size transaction]
     * 1100 0000  00xx xxxx  xxxx xxxx - 3 byte (-16383 .. - 128) [means EOB]
     * 1100 0000  0000 0000  0xxx xxxx - 3 byte (alt -0 .. -127) [means EOF]
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
 * Format: 1 header byte, then 0,1,2 or 4 bytes
 * bbbn nnnn - data_type + name_length
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
 */

    /**
     * Pack array to string by III-format
     *
     * @param array $arr
     * @return string|false
     */
    public static function packIII($arr)
    {
        if (!is_array($arr)) {
            return false;
        }
        $res = [];
        foreach($arr as $n => $v) {
            $l = strlen($n);
            if ($l <1 || $l>32) return false;

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
                if (!method_exists($v, "__toString")) {
                    return false;
                }
                $v = (string)$v;
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
                // unsupported type
                return false;
            }
            $res[] = chr($b) . $n . $c;
        }
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

    /**
     * Update file streams.list
     *
     * In: $sid_or_num ( 8-bytes string or integer cell-number)
     *     $wr_hsd_n, $wr_seek - parameter to write new data (or 0 for skip)
     * Out: integer cell number, or false if error
     * Limits: max.256 hsd-streams supported
     *
     * @param integer|string $sid_or_num
     * @param integer $hsd_n
     * @param integer $wr_seek
     * @return integer|false
     */
    public function hsdFolderCell(
        $sid_or_num,
        $hsd_n = 0,
        $wr_seek = 0
    ) {
        $streams_list_name = $this->base_path . 'streams.list';
        $wrpack = pack('N2', $hsd_n, $wr_seek);
        if (is_string($sid_or_num) && strlen($sid_or_num) == 8) {
            $sid_bin = $sid_or_num;
            $scan_cell = function() use ($streams_list_name, $sid_bin) {
                if (is_file($streams_list_name)) {
                    $data = file_get_contents($streams_list_name, false, NULL, 0, 4096);
                    $data_arr = str_split($data, 16);
                    foreach($data_arr as $cell_num => $data) {
                        if (substr($data,0,8) == $sid_bin) {
                            $arr = unpack('Nhsd_n/Nwr_seek', substr($data, 8));
                            return array_merge(compact('cell_num'), $arr);
                        }
                    }
                }
                return false;
            };
            $ret_arr = $scan_cell();
            if ($ret_arr === false) {
                $pack_str = $sid_bin . $wrpack;
                file_put_contents($streams_list_name, $pack_str, \FILE_APPEND);
                $cell_num = $scan_cell();
            } else {
                $cell_num = $ret_arr['cell_num'];
            }
        } else {
            $cell_num = $sid_or_num;
            if (!$hsd_n) {
                $data = file_get_contents($streams_list_name, false, NULL, 8 + $cell_num * 16, 8);
                $ret_arr = unpack('Nhsd_n/Nwr_seek', $data);
                $ret_arr['cell_num'] = $cell_num;
                return $ret_arr;
            }
            $ret_arr = compact('cell_num', 'hsd_n', 'wr_seek');
        }
        if (!is_numeric($cell_num) || ($cell_num > 255) || ($cell_num < 0)) {
            return false;
        }
        if ($hsd_n) {
            $f = fopen($streams_list_name, 'rb+');
            if (!$f) {
                return false;
            }
            fseek($f, 8 + 16 * $cell_num);
            fwrite($f, $wrpack);
            fclose($f);
        }
        return $ret_arr;
    }

    /**
     * Scan all hsd-files in folder by current sid
     *
     * @param boolean $ret_only_max_min
     * @return array
     */
    public function scanHSDfiles($ret_only_max_min = false)
    {
        $max_num = 0;
        $min_num = 4294967296; // 2^32

        // scan hsd files
        $pattern = $this->base_path . $this->base_name . DIRECTORY_SEPARATOR . $this->base_name . '-';
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
        if ($c = count($hsd_arr)) {
            $unb = (($max_num - $min_num + 1) == $c) || ($min_num == $max_num);
            if ($ret_only_max_min) {
                $hsd_arr = [];
            }
            $hsd_arr['min'] = $min_num;
            $hsd_arr['max'] = $max_num;
            $hsd_arr['unb'] = $unb ? 1 : 0;
        }
        return $hsd_arr;
    }

    public function calcZeroHash()
    {
        if (empty($this->signer_a160)) {
            $man_arr = $this->readMan();
            if (empty($man_arr['fil']['a160'])) {
                return false;
            } else {
                $this->signer_a160 = $man_arr['fil']['a160'];
            }
        }
        $zero_hash = hash($this->hash_alg, $this->signer_a160, true);
        return $zero_hash;
    }
    public function initStream()
    {
        if (empty($this->signer_a160)) {
            return "Signer must be set before initStream";
        }
        $max_min = $this->scanHSDfiles(true);
        if (!empty($max_min['max'])) {
            return "HSD-file already exists";
        }
        $prev_hash = $this->calcZeroHash();
        $hash_size = strlen($prev_hash);
        if (!$hash_size) {
            return "Bad hash alg";
        }
        $this->hash_size = $hash_size;

        $wrb = $this->writeMan();
        if (empty($wrb)) {
            return "Can't write man-file";
        }
        $this->hsd_n = 1;
        return $this->initWriteNext(1, $prev_hash, 0, 0, true);
    }

    /**
     * Out:
     *  false = init successful
     *  true = already exists hsd-file, but no re_write flag
     *  string = other error
     *
     * @param int $hsd_n
     * @param string $prev_hash
     * @param int $start_blk
     * @param int $start_abs
     * @param boolean $re_write
     * @return boolean|string
     */
    public function initWriteNext($hsd_n, $prev_hash, $start_blk, $start_abs, $re_write = false)
    {
        $file_name = $this->makeHSDfileName($hsd_n);
        if (!$re_write && is_file($file_name)) {
            return true;
        }
        $hsd_head = $this->packHSDhead(0, $start_blk, $start_abs); // $blocks_cnt, $start_blk, $start_abs
        $wr_seek = strlen($hsd_head);
        $wrb = file_put_contents($file_name, $hsd_head);
        if ($wrb !== $wr_seek) {
            return "Can't create hsd-file";
        }
        $cell_arr = $this->hsdFolderCell($this->hsd_folder, $hsd_n, $wr_seek);

        if (!$this->writeHashFile(0, $prev_hash, $hsd_n)) {
            return "Can't write hash-file";
        }
        if (!$this->writeSeekFile(0, $wr_seek, $hsd_n)) {
            return "Can't write seek-file";
        }
        return false;
    }

    /**
     * Close and unlock file, opened by openWrite()
     *
     * In:
     *  false or 0 = unlock and close only, dont change WF
     *  true = unlock, close, clear WF (set =0)
     *  1,2,3... 255 = unlock, close, and set WF = specified value
     *
     * Out:
     *  false = only unlock and close, no write changes
     *  1 = WF-flag updated
     *
     * @param boolean|int $wf_update
     * @return boolean|int
     */
    public function closeWrite($wf_update = true) {
        $wb = false;
        if ($this->hsd_f) {
            if ($wf_update) {
                if (!fseek($this->hsd_f, 3)) {
                    $wb = \fwrite($this->hsd_f, chr(($wf_update === true) ? 0 : $wf_update));
                }
            }
            \flock($this->hsd_f, \LOCK_UN); // unlock
            \fclose($this->hsd_f);
            $this->hsd_f = false;
        }
        return $wb;
    }
    public function openRead($hsd_n = false)
    {
        if (!$hsd_n) {
            $hsd_n = $this->hsd_n;
        }
        if (($hsd_n < 1) || ($hsd_n > 4294967295)) {
            return false;
        }
        $file_name = $this->makeHSDfileName($hsd_n);
        if (!is_file($file_name)) {
            return false;
        }
        $f = fopen($file_name, 'rb');
        if (!$f) {
            return false;
        }
        $data = fread($f, 36);
        $arr = $this->unpackHSDhead($data);
        if (!is_array($arr)) {
            fclose($f);
            return false;
        }
        $arr['file_name'] = $file_name;
        $arr['hsd_n'] = $hsd_n;
        $arr['f'] = $f;
        return $arr;
    }

    /**
     * In: $wf = 0-255 (write to WF) or =false (no change wf)
     *  $wf_ignore = true - open if WF not clear
     * Out: array = ok, else = error [ true - file locked by another process ]
     *
     * @param int $hsd_n
     * @param int|false $wf
     * @param boolean $wf_ignore
     * @return boolean
     */
    public function openWrite($hsd_n = false, $wf = 1, $wf_ignore = false)
    {
        if (!$hsd_n) {
            $hsd_n = $this->hsd_n;
        }
        $ret = !$hsd_n;
        if ($ret || !empty($this->hsd_f)) {
            return false;
        }
        $file_name = $this->makeHSDfileName($hsd_n);
        $f = fopen($file_name, 'rb+');
        if (!$f) {
            return "Can't open hsd-file #$hsd_n for write";
        }

        $wblk = 0;
        if (!\flock($f, \LOCK_EX | \LOCK_NB,  $wblk)) {
            fclose ($f);
            return $wblk;
        }
        $this->hsd_f = $f;

        $parr = $this->unpackHSDhead(fread($f, 36));
        if (is_array($parr)) {
            if ($parr['wf'] && !$wf_ignore) {
                $this->closeWrite(false);
                return "Error WF=" . $parr['wf'];
            } else {
                $this->writeWF($wf);
            }
        } else {
            $this->closeWrite(false);
            return $parr;
        }
        $parr['file_name'] = $file_name;
        $parr['hsd_n'] = $hsd_n;
        $this->block_n = $parr['start_blk'] + $parr['blocks_cnt'];
        $this->abs_p = $parr['start_abs'] + $parr['wr_seek'] - 36;
        return $parr;
    }
    /**
     * Write WF (Write Flag) to current write-opened hsd-file
     *
     * In: $state is numeric (0-255)
     *     false - do nothing, return false
     * Out: false = ok, string = error
     *
     * WF=
     *  0 - normal state (before write)
     *  1 - appendRecord: last record write may be broken
     *  2 - appendRecord: after record writed and wr_seek updated, but not update FolderCell
     *  3 - blockFinalize: finalize-record write may be broken
     *  4 - blockFinalize: finalize-record added successful, blocks_cnt updated, before seek-file update
     *  5 - fileFinalize: before finalization record add
     *  6 - fileFinalize: after new-hsd-file created, after finalization record add and seek(28) update, before seek-updates
     *  7 - fileFinalize: after seek-table writed, but no hashes and cover
     *  8 - fileFinalize: after write hashes, but no cover
     *
     * @param integer|false $state
     * @return false|string
     */
    private function writeWF($state)
    {
        if (is_numeric($state)) {
            if (fseek($this->hsd_f, 3)) {
                return "Can't fseek hsd-file";
            }
            $wb = fwrite($this->hsd_f, chr($state));
            if ($wb != 1) {
                return "Can't write state to hsd-file";
            }
        }
        return false;
    }

    private function writeN4($seek, $n)
    {
        if (!is_numeric($n) || $n < 0 || $n > 4294967296) {
            return "Bad value";
        }
        if (fseek($this->hsd_f, $seek)) {
            return "Can't fseek in hsd-file to #$seek";
        }
        $wb = fwrite($this->hsd_f, pack('N', $n));
        if ($wb != 4) {
            return "Can't write n=$n to hsd-file (seek #$seek )";
        }
        return false;
    }

    public function appendRecord($data)
    {
        if (!is_string($data)) {
            return 'Bad data';
        }

        $rec_size = strlen($data); // max data length = 4194303 (=4Mb)
        if ($rec_size > 4194303) {
            return 'Data size too large';
        }

        // 1. Lock for write
        $parr = $this->openWrite(false, 1, true);
        if (!is_array($parr)) {
            if ($parr == 1) { // file locked by another process
                return true;
            }
            $parr = $this->openWrite(false, 1, true);

            return "Can't open write for append record: $parr";
        }
        $wf = $parr['wf'];
        if ($wf > 2) { // wf = 1 and 2 can ignore
            $this->closeWrite(false);
            return "hsd-file need to repare because wf=$wf";
        }
        if ($parr['ff']) {
            $this->closeWrite();
            // "Can't write because hsd-file finalized";
            $cell_arr = $this->hsdFolderCell($this->hsd_folder);
            if ($this->hsd_n != $cell_arr['hsd_n']) {
                $this->hsd_n = $cell_arr['hsd_n'];
                return $this->appendRecord($data);
            }
            return "Can't write because current hsd-file finalized and new not created";
        }

        // make INS
        if ($rec_size) {
            $ins = $this->packINS($rec_size);
        } else {
            $ins = chr(128) . chr(0); // sub-0 exception
        }
        $rec_size += strlen($ins);

        // 2. fseek to wr_seek
        $wr_seek = $parr['wr_seek'];
        if (fseek($this->hsd_f, $wr_seek)) {
            $this->closeWrite();
            return "Can't fseek for append data";
        }

        // calculate new wr_seek
        $rec_seek = $wr_seek;
        $wr_seek += $rec_size;

        // 3. check new wr_seek
        if ($wr_seek > 4294900000) {
            $this->closeWrite();
            return 'hsd-file size out of range';
        }

        // 4. write ins and data
        $wb = fwrite($this->hsd_f, $ins . $data);

        if ($wb !== $rec_size) {
            $this->closeWrite(false);
            return 'Error writing hsd-file';
        }

        // 5. write new wr_seek
        if ($ret = $this->writeN4(28, $wr_seek)) {
            $this->closeWrite(false);
            return 'Error update wr_seek in hsd_file:' . $ret;
        }

        $rec_abs_p = $this->abs_p;
        $this->abs_p += $rec_size;

        // 6. update wf to 2 (mode 2 means: hsd-file updated, start update indexes)
        if ($ret = $this->writeWF(2)) {
            $this->closeWrite(false);
            return $ret;
        }

        // 7. update hsd-folder cell
        $ret = $this->hsdFolderCell($this->hsd_folder, $this->hsd_n, $wr_seek);
        if (!is_array($ret)) {
            $this->closeWrite(false);
            return "Can't update hsd-folder cell index";
        }

        // 8. finish succesfull
        $wb = $this->closeWrite();
        if ($wb != 1) {
            return "can't update wf-flag";
        }

        return [
        'rec_abs_p' => $rec_abs_p,
        'sid_bin' => $this->sid_bin,
        'rec_blk_n' => $this->block_n,
        'rec_seek' => $rec_seek,
        'rec_size' => $rec_size,
        'rec_file' => $parr['file_name'],
        'rec_hsd_n' => $parr['hsd_n'],
        ];
    }
    public function fileAfterFinalize($hsd_n, &$blocks_arr = false)
    {
        // openRead and quick check
        $rarr = $this->openRead($hsd_n);
        if (!is_array($rarr)) {
            return "Can't open hsd-file #$hsd_n";
        }
        \extract($rarr);
        // $wf
        // 6 - fileFinalize: after new-hsd-file created, after finalization record add and seek(28) update, before seek-updates
        // 7 - fileFinalize: after seek-table writed, but no hashes and cover
        // 8 - fileFinalize: after write hashes, but no cover
        if (!$wf) {
            if ($ff) {
                return "hsd-file #$hsd_n already finalized";
            } else {
                return "need to call fileFinalize() before";
            }
        }

        if ($blocks_arr === false) {
            $blocks_arr = $this->readSeekTable($hsd_n);
        }
        if (is_string($blocks_arr)) {
            return "can't read seek-table from hsd #$hsd_n: $blocks_arr";
        }
        $blk_in_seek = count($blocks_arr);

        // calculate last-point by seek-table
        $lr = $blk_in_seek - 1;
        $seek_last_point = $blocks_arr[$lr][0] + $blocks_arr[$lr][1];

        if ($wf == 6) {
            $parr = $this->openWrite($hsd_n, false, true);
            if (!is_array($parr)) {
                return "Can't open hsd-file #$hsd_n for after-finalize ($wf)";
            }
            // 7. Write seek-table
            if (fseek($this->hsd_f, $wr_seek)) {
                $this->closeWrite();
                return "Can't fseek to end of hsd-file #$hsd_n";
            }

            foreach($blocks_arr as $seek_len) {
                $seek = pack('N', $seek_len[0]);
                $wb = fwrite($this->hsd_f, $seek);
                if ($wb != 4) {
                    $this->closeWrite(false);
                    return "Can't write record seek-table to hsd-file";
                }
            }

            // write final-record of seek-table
            $seek = pack('N', $seek_last_point);
            $wb = fwrite($this->hsd_f, $seek);
            if ($wb != 4) {
                $this->closeWrite(false);
                return "Can't write last-record of seek-table to hsd-file";
            }
            $wr_seek += $blocks_cnt * 4 + 4;
            $wf = 7;
            $this->closeWrite($wf);
        }
        if ($wf == 7) {
            //First and last hashes
            $first_hash = $this->readHashFile(0, $hash_size, $hsd_n);

            if (empty($first_hash)) {
                $first_hash = $this->repairHashFile($hsd_n, $blocks_arr);
                if (!is_array($first_hash)) {
                    return $first_hash;
                }
                $last_hash = $first_hash[count($first_hash) - 1];
                $first_hash = $first_hash[0];
            }
            if (empty($last_hash) || empty($first_hash)) {
                return "Missing hashes for file-after-finalization";
            }

            $parr = $this->openWrite($hsd_n, false, true);
            if (!is_array($parr)) {
                return "Can't open hsd-file #$hsd_n for after-finalize ($wf)";
            }
            // Write first & last hashes
            if (fseek($this->hsd_f, $wr_seek)) {
                $this->closeWrite();
                return "Can't fseek to write final-hash";
            }

            $wb = fwrite($this->hsd_f, $first_hash . $last_hash);
            if ($hash_size * 2 != $wb) {
                $this->closeWrite(false);
                return "Error writing final-hashes";
            }
            $wr_seek += $wb;

            // 11. Close write and Update WF to 8
            $wf = 8;
            $wb = $this->closeWrite($wf);
            if ($wb != 1) {
                return "Error close-write on after-finalize hsd #$hsd_n";
            }
        }
        if ($wf == 8) {

            $parr = $this->openWrite($hsd_n, false, true);
            if (!is_array($parr)) {
                return "Can't open hsd-file #$hsd_n for after-finalize ($wf)";
            }

            // 12. Write FF flag (FF = File-Finalized flag)
            $wb = fwrite($this->hsd_f, chr(255));

            if ($wb != 1) {
                $this->closeWrite(false);
                return "Can't write FF flag on after-finalize hsd #$hsd_n";
            }

            // remove seek-file
            $seek_file = $this->satFileName('s', $hsd_n);
            if (is_file($seek_file)) {
                unlink($seek_file);
            }
            $sc_file = $this->satFileName('z', $hsd_n);
            if (is_file($sc_file)) {
                unlink($sc_file);
            }
            $wf = 9;
            $this->closeWrite($wf);
        }
        if (($wf == 9) || ($wf == 10)) {
            // Hashes Verification
            $hashes_arr = $this->verifyHashFile($hsd_n, $blocks_arr, true);
            if (!is_array($hashes_arr)) {
                return "Hashes verification error: $hashes_arr";
            }

            // Make signature
            $last_hash = end($hashes_arr);

            $sign_hex = $this->ec->signMsgHex($last_hash);
            if (!is_string($sign_hex) || strlen($sign_hex) < 128) {
                return "Digital signature is incorrect";
            }
            $sign_bin = hex2bin($sign_hex);
            if (!is_string($sign_bin) || strlen($sign_bin) < 64) {
                return "Digital signature is incorrect";
            }

            $hc_red_arr = $this->reduceHashes($blocks_arr, $hashes_arr, 65535);

            if (!is_array($hc_red_arr)) {
                return $hc_red_arr;
            }
            $hc_cnt = count($hc_red_arr);

            $sign_seek = $wr_seek + $blocks_cnt * 4 + 4 + $hash_size * 2;

            $parr = $this->openWrite($hsd_n, false, true);
            if (!is_array($parr)) {
                return "Can't open hsd-file #$hsd_n for after-finalize ($wf)";
            }

            $new_sign_seek = $parr['wr_seek'] + $parr['blocks_cnt'] * 4 + 4 + $hash_size * 2;
            if ($new_sign_seek != $sign_seek) {
                $this->closeWrite(false);
                return "Finalized file changed outside";
            }

            $sign_data = pack('n', strlen($sign_bin)) . $sign_bin . pack('N', $hc_cnt);

            if (fseek($this->hsd_f, $sign_seek)) {
                $this->closeWrite(false);
                return "Can't fseek to write digital signature";
            }

            $wb = fwrite($this->hsd_f, $sign_data);
            if (strlen($sign_data) != $wb) {
                $this->closeWrite(false);
                return "Error writing digital signature";
            }

            $red_hash_seek = $sign_seek + strlen($sign_data);
            $sz = $hash_size + 4;

            if ($hc_cnt) {
                $wf = 10;
                $wb = $this->writeWF($wf);
                if ($wb) {
                    return "Can't set wf=$wf";
                }

                if (fseek($this->hsd_f, $red_hash_seek)) {
                    $this->closeWrite(false);
                    return "Can't fseek to write digital signature";
                }
                foreach($hc_red_arr as $in_hash_n => $hash_bin) {
                    $hc_hash_data = pack("N", $in_hash_n) . $hash_bin;
                    $wb = fwrite($this->hsd_f, $hc_hash_data);
                    if ($sz != $wb) {
                        $this->closeWrite(false);
                        return "Error writing digital signature";
                    }
                }
            }
            $cover_seek = $red_hash_seek + $sz * $hc_cnt;
            $cover_data = "THE END OF HSD#$hsd_n FILE";

            if (fseek($this->hsd_f, $cover_seek)) {
                $this->closeWrite(false);
                return "Can't fseek to write file-cover";
            }
            $wb = fwrite($this->hsd_f, $cover_data);
            if (strlen($cover_data) != $wb) {
                $this->closeWrite(false);
                return "Error writing file-finalize cover";
            }
            // Write cover_seek
            if ($ret = $this->writeN4(32, $cover_seek)) {
                $this->closeWrite(false);
                return "Error writing file-finalize cover-seek:" . $ret;
            }

            $this->closeWrite();

            // remove hash & hc files
            $hash_file = $this->satFileName('h', $hsd_n);
            if (is_file($hash_file)) {
                unlink($hash_file);
            }
            $hash_file = $this->satFileName('x', $hsd_n);
            if (is_file($hash_file)) {
                unlink($hash_file);
            }
            return false;
        }
    }
    public function fileFinalize($hsd_n = false)
    {
        // PART I. Check file before finalize

        // openRead and quick check
        $rarr = $this->openRead($hsd_n);
        if (!is_array($rarr)) {
            return "Can't open hsd-file #$hsd_n";
        }
        \extract($rarr);
        \fclose($f);
        if ($wf && ($wf != 5)) {
            if ($wf > 5 && $wf < 10) {
                return $this->fileAfterFinalize($hsd_n);
            } else {
                return "hsd-file #$hsd_n need to repare because wf=$wf";
            }
        }
        if ($ff) {
            return "hsd-file #$hsd_n already finalized";
        }

        // Check last-block-finalize
        if (!$blocks_cnt || ($wr_seek > $blk_seek)) {
            if (!$blk_seek && $wf == 5) {
                $wr_seek -= 3;
                $blk_seek = $wr_seek;
            } else {
                return "Last block not finalized";
            }
        }

        // Check Seek-file
        $blocks_arr = $this->readSeekTable($hsd_n);
        if (!is_array($blocks_arr) || empty($blocks_arr)) {
            return "Can't read seek-table #$hsd_n $blocks_arr";
        }
        $blk_in_seek = count($blocks_arr);

        // calculate last-point by seek-table
        $lr = $blk_in_seek - 1;
        $seek_last_point = $blocks_arr[$lr][0] + $blocks_arr[$lr][1];

        if (($blocks_cnt != $blk_in_seek) || $seek_last_point != $wr_seek) {
            $new_blocks_arr = $this->repairSeekFile($hsd_n);
            if (is_array($new_blocks_arr) && !empty($new_blocks_arr) && ($new_blocks_arr != $blocks_arr)) {
                $this->fileFinalize($hsd_n);
            }
            return "Seek-file #$hsd_n corrupted";
        }

        // read prev_hash
        $last_hash = $this->readHashFile($blocks_cnt, $hash_size, $hsd_n);
        if (empty($last_hash)) {
            $last_hash = '';
        }

        // calculate new start_blk and new start_abs
        $curr_blk_n = $start_blk + $blocks_cnt;
        $curr_abs = $start_abs + $wr_seek - 36;

        // PART II. Open and lock, create continue, write file-finalization record

        // Set WF = 5

        // 3. Lock hsd-file for write
        $parr = $this->openWrite($hsd_n, 5, true);
        if (!is_array($parr)) {
            return "Can't open hsd-file #$hsd_n for finalize";
        }
        foreach(['ff', 'hash_size', 'wf', 'blocks_cnt', 'start_blk', 'start_abs', 'sid_bin', 'wr_seek', 'blk_seek', 'hc'] as $k) {
            if ($rarr[$k] != $parr[$k]) {
                $this->closeWrite();
                return $this->fileFinalize($hsd_n);
            }
        }

        // 4. Create new hsd-file for writing new data
        $cre = $this->initWriteNext($hsd_n + 1, $last_hash, $curr_blk_n, $curr_abs, false);
        // after this operation new data can be parallel written to new hsd-file
        if ($cre !== false) {
            if (($cre === true) && ($wf == 5)) {

            } else {
                $this->closeWrite(false);
                return "File-Finalization error. Can't create hsd-continue-file: $cre";
            }
        }

        // 5. Finalization record write
        if (fseek($this->hsd_f, $wr_seek)) {
            $this->closeWrite(false);
            return "Can't fseek for File Finalization";
        }
        $fin_rec = chr(192) . chr(0) . chr(0);
        $wb = fwrite($this->hsd_f, $fin_rec);
        $l = strlen($fin_rec);
        if ($wb != $l) {
            $this->closeWrite(false);
            return "Can't write file-finalization record to hsd #$hsd_n";
        }
        $wr_seek += $l;

        // 6. Write seek-table start point and 0 to cover-length
        if (fseek($this->hsd_f, 28)) {
            $this->closeWrite();
            return "Can't fseek in hsd-file";
        }
        $wb = fwrite($this->hsd_f, pack('N2', $wr_seek, 0));
        if ($wb != 8) {
            $this->closeWrite(false);
            return "Can't write seek-table point to hsd #$hsd_n";
        }

        if ($ret = $this->writeWF(6)) {
            $this->closeWrite(false);
            return $ret;
        }

        // WF = 6

        // 7. Write seek-table
        if (fseek($this->hsd_f, $wr_seek)) {
            $this->closeWrite();
            return "Can't fseek to end of hsd-file #$hsd_n";
        }

        foreach($blocks_arr as $seek_len) {
            $seek = pack('N', $seek_len[0]);
            $wb = fwrite($this->hsd_f, $seek);
            if ($wb != 4) {
                $this->closeWrite(false);
                return "Can't write record seek-table to hsd-file";
            }
        }

        // write final-record of seek-table
        $seek = pack('N', $seek_last_point);
        $wb = fwrite($this->hsd_f, $seek);
        if ($wb != 4) {
            $this->closeWrite(false);
            return "Can't write last-record of seek-table to hsd-file";
        }
        $wr_seek += $blocks_cnt * 4 + 4;


        // 9. Update WF to 7
        if ($ret = $this->writeWF(7)) {
            $this->closeWrite(false);
            return $ret;
        }

        //First and last hashes
        $first_hash = $this->readHashFile(0, $hash_size, $hsd_n);
        if (empty($last_hash) || empty($first_hash)) {
            $this->closeWrite(false);
            return "Missing hashes for file-finalization";
        }

        // 10. write first & last hashes
        if (fseek($this->hsd_f, $wr_seek)) {
            $this->closeWrite(false);
            return "Can't fseek to write final-hash";
        }

        $wb = fwrite($this->hsd_f, $first_hash . $last_hash);
        if ($hash_size * 2 != $wb) {
            $this->closeWrite(false);
            return "Error writing final-hashes";
        }
        $wr_seek += $wb;

        // 11. Update WF to 8
        if ($ret = $this->writeWF(8)) {
            return $ret;
        }
        // 12. Write FF flag
        $wb = fwrite($this->hsd_f, chr(255));

        // 13. Close write and set WF=9
        $this->closeWrite(9);

        if ($wb != 1) {
            return "Can't write FF flag";
        }

        // remove seek-file
        $seek_file = $this->satFileName('s', $hsd_n);
        if (is_file($seek_file)) {
            unlink($seek_file);
        }
        $sc_file = $this->satFileName('z', $hsd_n);
        if (is_file($sc_file)) {
            unlink($sc_file);
        }

        return $this->fileAfterFinalize($hsd_n, $blocks_arr);
    }
    public function blockFinalize($hash_update = true)
    {
        // 1. read man
        $man_arr = $this->readMan();
        if (!$man_arr) {
            return "Can't read hsd-man";
        }

        // 2. Lock hsd-file for write
        $parr = $this->openWrite(false, 3);
        if (!is_array($parr)) {
            if ($parr == 1) { // file locked by another process
                return true;
            }
            return "Can't open write for append record: $parr";
        }
        $wf = $parr['wf'];
        if ($wf > 0) {
            $this->closeWrite(false);
            return "hsd-file need to repare because wf=$wf";
        }
        if ($parr['ff']) {
            $this->closeWrite();
            return "Can't write because hsd-file finalized";
        }
        $f = $this->hsd_f;

        // 3. calculate block-finalizator data
        $blocks_cnt = $parr['blocks_cnt'];
        $curr_blk_n = $parr['start_blk'] + $blocks_cnt;
        if ($curr_blk_n > 4294967295) {
            $curr_blk_n -= 4294967296;
        }

        if ($man_arr['blk']['time']) { // auto-add 4-byte block number to block-fin
            $data = pack('N', time());
        } else {
            $data = '';
        }
        if ($man_arr['blk']['numb']) { // auto-add 4-byte block number to block-fin
            $data .= pack('N', $curr_blk_n);
        }
        $rec_size = strlen($data);
        if ($rec_size) {
            $ins = self::packINS(-$rec_size);
        } else {
            $ins = chr(0);
        }
        $rec_size += strlen($ins);

        // 4. fseek to wr_seek
        $wr_seek = $parr['wr_seek'];
        if (fseek($f, $wr_seek)) {
            $this->closeWrite();
            return "Can't fseek for finalize block";
        }

        // 6. check new wr_seek
        $rec_seek = $wr_seek;
        $wr_seek += $rec_size;
        if ($wr_seek > 4294967295) {
            $this->closeWrite();
            return 'hsd-file size out of range';
        }

        // 7. write ins and data
        $wb = fwrite($f, $ins . $data);

        if ($wb !== $rec_size) {
            $this->closeWrite(false);
            return 'Error writing block-finalization data';
        }

        $rec_abs_p = $this->abs_p;
        $this->abs_p += $rec_size;

        $rec_blk_n = $this->block_n;
        $this->block_n++;

        // 8. update hsd-header
        $blk_seek = $wr_seek;
        if (fseek($f, 28)) {
            $this->closeWrite(false);
            return "Can't update header of hsd_file";
        }
        if (fwrite($f, pack('N2', $wr_seek, $blk_seek)) != 8) {
            $this->closeWrite(false);
            return "Can't update header of hsd_file";
        }

        // 9. update WF=4 and blocks_cnt
        if (fseek($f, 3)) {
            $this->closeWrite(false);
            return "Can't update wf in hsd_file";
        }
        $new_blk_cnt = $blocks_cnt + 1;
        if (fwrite($f, chr(4) . pack('N', $new_blk_cnt)) != 5) {
            $this->closeWrite(false);
            return "Can't update wf+blocks_cnt in hsd_file";
        }

        // set hc (Hash need Calculate) flag
        if (!fseek($f, 2)) {
            fwrite($f, chr($parr['hash_size'] | 128));
        }

        // 10. update seek
        $wb = $this->writeSeekFile($new_blk_cnt, $wr_seek);
        if (!$wb) {
            $this->closeWrite(false);
            return "Error seek-file update";
        }

        // unlock file
        $wb = $this->closeWrite();
        if ($wb != 1) {
            return "Error on close hsd-file after block finalized";
        }

        // 11. update hash
        if ($hash_update) {
            $this->calcNewHashes($this->hsd_n);
        }

        return [
        'rec_abs_p' => $rec_abs_p,
        'sid_bin' => $this->sid_bin,
        'rec_blk_n' => $rec_blk_n,
        'rec_seek' => $rec_seek,
        'rec_size' => $rec_size,
        'rec_file' => $parr['file_name'],
        'rec_hsd_n' => $parr['hsd_n'],
        ];
    }


    public function reduceHashes(&$blocks_arr, &$hashes_arr, $bytes_size = 65535)
    {
        $cnt = count($blocks_arr);
        if (count($hashes_arr) != $cnt + 1) {
            return "Array size are different";
        }
        $red_arr = [];
        $area_size = 0;
        reset($blocks_arr);
        for($in_hash_n = 1; $in_hash_n < $cnt; $in_hash_n++) {
            $area_size += current($blocks_arr)[1];
            if ($area_size > $bytes_size) {
                $red_arr[$in_hash_n] = $hashes_arr[$in_hash_n];
                $area_size = 0;
            }
            next($blocks_arr);
        }
        return $red_arr;
    }

    public function readSeekFile($in_blk_n, $hsd_n = false)
    {
        $file_name = $this->satFileName('s', $hsd_n);
        $data = self::readSatFile($file_name, $in_blk_n);
        if ($data) {
            $data = unpack('N', $data)[1];
        }
        return $data;
    }
    public function readHashFile($in_blk_n, $hash_size, $hsd_n = false)
    {
        $file_name = $this->satFileName('h', $hsd_n);
        return self::readSatFile($file_name, $in_blk_n, $hash_size);
    }

    /**
     * Return:
     *  string data if ok
     *  false = error
     *
     * @param string $file_name
     * @param int $in_blk_n
     * @param int $rec_size
     * @return boolean|string
     */
    public static function readSatFile($file_name, $in_blk_n, $rec_size = 4)
    {
        if (!is_numeric($in_blk_n) || ($in_blk_n < 0) || ($in_blk_n > 16777215) || ($rec_size < 1) || ($rec_size > 256)) {
            return false;
        }
        $f = fopen($file_name, 'rb');
            if (!$f) {
                return false;
            }
            if (fseek($f, $in_blk_n * $rec_size)) {
                fclose($f);
                return false;
            }
            $data = fread($f, $rec_size);
        fclose($f);
        if (strlen($data) != $rec_size) {
            return false;
        }
        return $data;
    }
    /**
     * Return:
     *  false = error
     *  true = ok
     *
     * @param string $file_name
     * @param int $in_blk_n
     * @param int $rec_size
     * @param string $data
     * @return boolean
     */
    public static function writeSatFile($file_name, $in_blk_n, $rec_size, $data)
    {
        $l = strlen($data);
        if (!is_numeric($in_blk_n)
          || !is_numeric($rec_size)
          || !is_string($file_name)
          || !is_string($data)
          || ($in_blk_n <0)
          || ($in_blk_n > 16777215)
          || ($rec_size < 1)
          || ($rec_size > 256)
        ) {
            return false;
        }
        if ($in_blk_n) {
            if ($l != $rec_size) {
                return false;
            }
            $f = fopen($file_name, 'rb+');
            if (!$f) {
                return false;
            }
                fseek($f, $in_blk_n * $rec_size);
                $wb = fwrite($f, $data);
            fclose($f);
        } else {
            if (($l != $rec_size) && ($l != 0)) {
                return false;
            }
            $wb = file_put_contents($file_name, $data);
        }
        return $wb === $rec_size;
    }
    public function writeSeekFile($in_blk_n, $wr_seek, $hsd_n = false)
    {
        if (!is_numeric($wr_seek) || ($wr_seek < 1) || ($wr_seek > 4294967295)) {
            return false;
        }
        $seek_bin = pack('N', $wr_seek);
        $sc_file = $this->satFileName('z', $hsd_n);
        $sc_bin = pack('N', $in_blk_n) . $seek_bin;
        $wb = file_put_contents($sc_file, $sc_bin, \FILE_APPEND);

        $seek_file = $this->satFileName('s', $hsd_n);
        return self::writeSatFile($seek_file, $in_blk_n, 4, $seek_bin);
    }

    public function tryGetSC($hsd_n, $in_blk_n)
    {
        $sc_file = $this->satFileName('z', $hsd_n);
        if (!is_file($sc_file)) {
            return false;
        }
        $f = fopen($sc_file, 'rb');
        if (!$f) {
            return false;
        }
        $result_seek = false;
        while (!feof($f)) {
            $sc_bin = fread($f, 8);
            if ($sc_bin === false || strlen($sc_bin) != 8) {
                break;
            }
            $sc_arr = unpack('Nin_n/Nseek', $sc_bin);
            if ($sc_arr['in_n'] == $in_blk_n) {
                $result_seek = $sc_arr['seek'];
                break;
            }
        }
        fclose($f);
        return $result_seek;
    }
    public function writeHashFile($in_blk_n, $blk_hash, $hsd_n = false)
    {
        $hash_file = $this->satFileName('h', $hsd_n);
        return self::writeSatFile($hash_file, $in_blk_n, $this->hash_size, $blk_hash);
    }

    /**
     * Verify hash-file and compare with re-calculated hashes
     *
     * Return:
     *  "Ok" or hash_array = calculated hashes is equal with presented in hash-file
     *  Other string means error
     *
     * @param int $hsd_n
     * @param array $blocks_arr
     * @return string
     */
    public function verifyHashFile($hsd_n = false, $blocks_arr = false, $ret_array = false)
    {
        if (false === $hsd_n) {
            $hsd_n = $this->hsd_n;
        }
        $hash_size = $this->hash_size;

        $hash_file = $this->satFileName('h', $hsd_n);
        if (!\is_file($hash_file)) {
            return "No hash-file for hsd #$hsd_n";
        }
        $file_size = \filesize($hash_file);
        if (!empty($file_size) && !($file_size % $hash_size)) {
            $have_hashes_cnt = $file_size / $hash_size;
        } else {
            return "Bad hash-file-size for hsd #$hsd_n";
        }

        if ($blocks_arr === false) {
            $blocks_arr = $this->readSeekTable($hsd_n);
        }
        if (count($blocks_arr) != $have_hashes_cnt - 1) {
            return "Different blocks and hashes count";
        }
        // Ok, Calculate hashes
        $hash_arr = $this->calcHashes($hsd_n, true, $blocks_arr);
        if (!is_array($hash_arr)) {
            return $hash_arr;
        }

        $f = fopen($hash_file, 'rb');
        if (!$f) {
            return "Can't open hash-file for read";
        }

        for($in_hash_n = 0; $in_hash_n < $have_hashes_cnt; $in_hash_n++) {
            $have_hash = fread($f, $hash_size);
            if ($in_hash_n) {
                $exp_hash = $hash_arr[$in_hash_n];
            } else {
                $exp_hash = $this->readPrevHash($hsd_n);
                if (empty($exp_hash)) {
                    return "Can't retreive prev_hash for hsd #$hsd_n";
                }
            }
            if ($have_hash !== $exp_hash) {
                return "Different hash #$in_hash_n in hsd #$hsd_n \n" .
                    "Expected: " . bin2hex($exp_hash) . "\n" .
                    "Present : " . bin2hex($have_hash);
            }
        }
        if ($ret_array) {
            return $hash_arr;
        }
        return "Ok";
    }

    /**
     * Return:
     *  array if ok
     *  string if error
     *
     * @param int $hsd_n
     * @param array $blocks_arr
     * @return string|array
     */
    public function repairHashFile($hsd_n, $blocks_arr = false)
    {
        $hash_arr = $this->calcHashes($hsd_n, true, $blocks_arr);
        if (!is_array($hash_arr)) {
            return $hash_arr;
        }

        $hash_file = $this->satFileName('h', $hsd_n);
        $f = fopen($hash_file, 'wb');
        if (!$f) {
            return "Can't open hash-file for write";
        }
        $hash_size = $this->hash_size;
        foreach($hash_arr as $hash_bin) {
            $wb = fwrite($f, $hash_bin);
            if ($wb != $hash_size) {
                break;
            }
        }
        fclose($f);
        if ($wb != $hash_size) {
            return "Error hash-file reapir #$hsd_n";
        }
        return $hash_arr;
    }
    public function repairSeekFile($hsd_n, $blocks_arr = false)
    {
        if ($blocks_arr === false) {
            $blocks_arr = $this->fileScanBlocks($hsd_n, true);
        }
        if (!is_array($blocks_arr)) {
            return $blocks_arr;
        }
        $seek_file = $this->satFileName('s', $hsd_n);
        $f = fopen($seek_file, 'wb');
        if (!$f) {
            return "Can't open seek-file #$hsd_n for write";
        }
            foreach ($blocks_arr as $blk_n => $seek_len) {
                $seek = pack('N', $seek_len[0]);
                $wb = fwrite($f, $seek);
                if ($wb != 4) {
                    break;
                }
            }
            // add last record:
            $seek = pack('N', $seek_len[0] + $seek_len[1]);
            $wb = fwrite($f, $seek);
        fclose ($f);
        if ($wb != 4) {
            return "Error write seek-file #$hsd_n";
        }
        return $blocks_arr;
    }
    public function readSeekTable($hsd_n = false, $skip_blk_cnt = 0, $can_repair = true)
    {
        if ($hsd_n === false) {
            $hsd_n = $this->hsd_n;
        }
        $blocks_arr = $this->readSeekTbl($hsd_n, $skip_blk_cnt);
        if ($blocks_arr === true && $can_repair) {
            $blocks_arr = $this->repairSeekFile($hsd_n);
        }
        return $blocks_arr;
    }
    public function readSeekTbl($hsd_n = false, $skip_blk_cnt = 0)
    {
        if ($hsd_n === false) {
            $hsd_n = $this->hsd_n;
        }
        if (!is_numeric($hsd_n) || $hsd_n < 1 || $hsd_n > 4294967295) {
            return "Bad hsd-file number";
        }
        $seek_file = $this->satFileName('s', $hsd_n);
        if (is_file($seek_file)) {
            $file_size = filesize($seek_file);
            if (empty($file_size) || ($file_size % 4)) {
                return true; // "Seek-file #$hsd_n corrupted"; // need repair
            }
            $blocks_cnt = $file_size / 4 - 1;
            $f = fopen($seek_file, 'rb');
            if (!$f) {
                return "Can't read seek-file #$hsd_n";
            }
            $seek = 0;
        } else {
            $parr = $this->openRead($hsd_n);
            if (!is_array($parr)) {
                return "Can't read hsd-file #$hsd_n";
            }
            if (is_array($parr) && !$parr['ff']) {
                return true; //"Seek-file #$hsd_n not found"; need repair
            }
            $f = $parr['f'];
            $seek = fseek($f, 28) ? '' : fread($f, 4);
            if (strlen($seek) != 4) {
                return "Can't read hsd-file #$hsd_n";
            }
            $blocks_cnt = $parr['blocks_cnt'];
            $seek = unpack('N', $seek)[1];
        }
        if ($skip_blk_cnt) {
            $seek += 4 * $skip_blk_cnt;
        }
        fseek($f, $seek);
        $blocks_arr = [];
        $prev_seek = false;
        for ($in_blk_n = $skip_blk_cnt; $in_blk_n <= $blocks_cnt; $in_blk_n++) {
            $seek = fread($f, 4);
            if (strlen($seek) != 4) {
                return "Error reading seek-table #$hsd_n";
            }
            $seek = unpack('N', $seek)[1];
            if (!$seek) {
                $seek = $this->tryGetSC($hsd_n, $in_blk_n);
                if (!$seek && $prev_seek) {
                    $blk_arr = $this->scanBlockBySeek($hsd_n, $prev_seek);
                    if (is_array($blk_arr)) {
                        $seek = $blk_arr['end_seek'];
                    }
                }
                if ($seek) {
                    $this->writeSeekFile($in_blk_n, $seek, $hsd_n);
                }
            }
            if ($prev_seek !== false) {
                $blk_len = $seek - $prev_seek;
                if ($blk_len < 0) {
                    fclose($f);
                    return true; //"Seek-table corrupted";
                }
                $blocks_arr[$in_blk_n - 1] = [$prev_seek, $blk_len];
            }
            $prev_seek = $seek;
        }
        fclose($f);
        return $blocks_arr;
    }

    public function _scanBlockBySeek($f, &$seek, &$fn_every_rec = false, &$head_arr = false) {
        if (!$f) {
            return false;
        }
        $end_seek = $eob = $eof = $ins = false;
        $start_seek = $seek;
        $rec_cnt = 0;
        while (!feof($f)) {
            if (fseek($f, $seek)) {
                break;
            }
            $data = fread($f, 4);
            if (is_string($data) && strlen($data)) {
                $first_byte_n = ord($data[0]);

                $ins_len = ($first_byte_n & 192) / 64;
                if ($ins_len > 1) {
                    $ins_len--;
                } else {
                    $ins_len = 1;
                }
                $ins = $this->unpackINS($first_byte_n, substr($data, 1));
                if (($first_byte_n == 192) && ($ins > -128)) {
                    $eof = true;
                }
                $eob = !$first_byte_n || ($ins < 0);
                $rec_size = $ins_len + abs($ins);

                if (false !== $fn_every_rec) {
                    $res = call_user_func($fn_every_rec, [
                        'rec_nmb' => $rec_cnt,
                        'rec_seek' => $seek,
                        'rec_size' => $rec_size,
                        'f' => $f,
                        'data' => &$data,
                        'ins' => $ins,
                        'eof' => $eof,
                        'eob' => $eob,
                        'head_arr'  => &$head_arr,
                    ]);
                }
                $seek += $rec_size;

                if ($eob || $eof) {
                    $end_seek = $seek;
                    break;
                }
            }
            $rec_cnt++;
        }
        if (!$end_seek) {
            return false;
        }
        return [
            'start_seek' => $start_seek,
            'end_seek' => $end_seek,
            'length' => $end_seek - $start_seek,
            'rec_cnt' => $rec_cnt,
            'eof' => $eof,
        ];
    }
    public function scanBlockBySeek($hsd_n, &$seek, &$fn_every_rec = false, &$head_arr = false)
    {
        $file_name = $this->makeHSDfileName($hsd_n);
        $f = fopen($file_name, 'rb');
            $ret_arr = $this->_scanBlockBySeek($f, $seek, $fn_every_rec, $head_arr);
        fclose($f);
        return $ret_arr;
    }
    public function fileWalkSeek($hsd_n, &$seek = false, &$fn_every_blk = false, &$fn_every_rec = false, &$head_arr = false)
    {
        $rarr = $this->openRead($hsd_n, $seek = false);
        if (!is_array($rarr)) {
            return $rarr;
        }
        $f = $rarr['f'];
        if (!is_numeric($seek)) {
            $seek = $rarr['bsize'];
        }
        while (!feof($f)) {
            $blk_arr = $this->_scanBlockBySeek($f, $seek, $fn_every_rec, $head_arr);
            if (!is_array($blk_arr)) {
                break;
            }
            if ($fn_every_blk !== false) {
                $res = call_user_func($fn_every_blk, [
                    'blk_arr' => &$blk_arr,
                    'rarr' => &$rarr,
                    'head_arr' => &$head_arr,
                ]);
            }
        }
    }

    public function fileScanBlocks($hsd_n, $blocks_cnt_repair = false)
    {
        $rarr = $this->openRead($hsd_n);
        if (!is_array($rarr)) {
            return $rarr;
        }
        $f = $rarr['f'];
        $buff = '';
        $seek = 36;
        fseek($f, $seek);

        $block_start = false;
        $block_size = 0;
        $blocks_arr = [];
        $walk = $this->fileWalkRecords($f, function($in_arr) use (&$block_start, &$block_size, &$blocks_arr) {
            $ins = $in_arr['ins'];
            $eof = $in_arr['eof'];
            $eob = $in_arr['eob'];
            if ($block_start === false) {
                $block_start = $in_arr['rec_seek'];
                $block_size = 0;
            }
            $block_size += $in_arr['rec_size'];
            if ($eob) {
                $blocks_arr[] = [$block_start, $block_size];
                $block_start = false;
            }
            //print_r($in_arr);
        }, $rarr, $buff, $seek, 0);

        // Repair blocks_cnt if requested and possible
        if ($blocks_cnt_repair && !$rarr['ff']) {
            $need_close = false;
            if (!$this->hsd_f) {
                $parr = $this->openWrite($hsd_n, false, true);
                if (is_array($parr)) {
                    $need_close = true;
                }
            }
            if (is_resource($this->hsd_f)) {
                if (!$parr['ff']) {
                    $blocks_bin = pack('N', \count($blocks_arr));
                    fseek($this->hsd_f, 4);
                    fwrite($this->hsd_f, $blocks_bin);
                }
            }
            if ($need_close) {
                $this->closeWrite(false);
            }
        }

        return $blocks_arr;
    }
    public static function fileWalkRecords($fd, $fn_every_trans, &$head_arr, &$buff, $seek, $p)
    {
        $walk = [];

        $eof = false;

        $rd_cnt = 0;

        //function for buffered-reading from file
        $reader = function($len, $max_read = 1100) use ($fd, &$eof, &$seek, &$buff, &$p, &$rd_cnt) {
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
            $rd_cnt += strlen($data);
            return $data;
        };

        $rec_nmb = 0;

        $rec_seek = $seek + strlen($buff) - $p;

        while (!$eof) {
            // Read INS

            $data = $reader(1);

            if ($eof) break; //eof reached means no more records

            $first_byte_n = ord($data); // 1 byte expected

            // how many bytes must be read to get full INS ?
            $fc = ($first_byte_n & 192) / 64;
            if ($fc > 1) {
                $data = $reader($fc - 1);
            }
            // unpack INS
            $ins = self::unpackINS($first_byte_n, $data);
            $a = abs($ins); // framgent length

            // read INS data
            $ml = ($a > 8190)? ($a + 3) : 8192; //max-length
            $data = $reader($a, $ml);

            if (($first_byte_n == 192) && ($ins > -128)) {
                $eof = true;
            }
            $eob = !$first_byte_n || ($ins < 0);

            $res = call_user_func($fn_every_trans, [
                'rec_nmb' => $rec_nmb,
                'rec_seek' => $rec_seek,
                'rec_size' => $rd_cnt,
                'data' => &$data,
                'ins' => $ins,
                'eof' => $eof,
                'eob' => $eob,
                'head_arr'  => &$head_arr,
            ]);
            // call user-function on readed data.
            if ($res === false) {
                break;
            }
            if (!is_null($res)) {
                $walk[$rec_nmb] = $res;
            }
            $rec_nmb++;
            $rec_seek += $rd_cnt;
            $rd_cnt = 0;
        }
        fclose ($fd);
        return $walk;
    }

    /**
     * Return:
     *  resource - if ok
     *  false = can't open file for append
     *  int EWOULDBLOCK = can't flock
     *
     * @param int $hsd_n
     * @return boolean|int
     */
    public function tryLockHC($hsd_n = false)
    {
        $hc_file = $this->satFileName('x', $hsd_n);
        $f = fopen($hc_file, 'ab+');
        if (!$f) {
            return false;
        }
        $wblk = 0;
        if (!flock($f, LOCK_EX | LOCK_NB, $wblk)) {
            fclose($f);
            return $wblk;
        }
        return $f;
    }
    public function releaseHC($f)
    {
        flock($f, LOCK_UN);
        fclose($f);
    }

    /**
     * Return:
     *  false = error
     *  true = ok
     *
     * @param resource $f
     * @param int $in_hash_n
     * @param string $blk_hash
     * @return boolean
     */
    public function pushHC($f, $in_hash_n, $blk_hash)
    {
        $l = strlen($blk_hash);
        if ($l != $this->hash_size) {
            return false;
        }
        $data = pack('N', $in_hash_n) . $blk_hash;
        $wb = fwrite($f, $data);
        return  $wb === $l + 4;
    }

    /**
     * Loading hashes from hc-file to array
     *
     * Return: array (if ok) or integer (if error)
     * Errors:
     * 0 - hc-file not found
     * 1 - empty hc_file or bad length
     * 2 - can't open hc-file for read
     * 4 - in_blk_n overflow (bad data in file)
     *
     * @param int $hsd_n
     * @return array|int
     */
    public function loadHC($hsd_n, $from_in_hash_n = 0)
    {
        $hash_size = $this->hash_size;
        $hc_file = $this->satFileName('x', $hsd_n);
        if (!is_file($hc_file)) {
            return 0;
        }
        $rec_size = 4 + $hash_size; // in_blk_n + hash_bin
        $file_size = filesize($hc_file);
        $el_cnt = $file_size / $rec_size;
        if (empty($file_size) || ($file_size % $rec_size) || ($file_size > $rec_size * 16777216)) {
            return 1;
        }
        $hc = fopen($hc_file, 'rb');
        if (!$hc) {
            return 2;
        }
        $min_in = 4294967296;
        $max_in = 0;
        $rd_point = 0;
        $hashes_arr = [];
        while ($rd_point < $file_size) {
            $data = fread($hc, $rec_size);
            if (!is_string($data) || (strlen($data) != $rec_size)) {
                break;
            }
            $rd_point += $rec_size;
            $un = unpack('Nin_hash_n/A*hash_bin', $data);
            extract($un); // $in_hash_n, $hash_bin
            if ($in_hash_n < $from_in_hash_n) {
                continue;
            }
            $hashes_arr[$in_hash_n] = $hash_bin;
            if ($in_hash_n > $max_in) {
                $max_in = $in_hash_n;
            }
            if ($in_hash_n < $min_in) {
                $min_in = $in_hash_n;
            }
        }
        fclose($hc);
        if ($max_in > 16777215) {
            return 4;
        }
        if (empty($hashes_arr)) {
            return [];
        }
        return compact('min_in', 'max_in', 'hashes_arr');
    }
    public function mergeHC($hsd_n, $have_hashes_cnt = 0)
    {
        $hash_size = $this->hash_size;

        $hash_file = $this->satFileName('h', $hsd_n);

        // how many hashes in hash_file ?
        if (!$have_hashes_cnt) {
            if (is_file($hash_file)) {
                $file_size = filesize($hash_file);
                if (!empty($file_size) && !($file_size % $hash_size)) {
                    $have_hashes_cnt = $file_size / $hash_size;
                }
            }
            if ($have_hashes_cnt < 1) {
                // need previous hash
                $prev_hash = $this->readPrevHash($hsd_n);
                if (empty($prev_hash)) {
                    return false;
                }
                $wb = file_put_contents($hash_file, $prev_hash);
                if ($wb != $hash_size) {
                    return false;
                }
                $have_hashes_cnt = 1;
            }
        }

        $in_hash_n = $have_hashes_cnt;

        $new_hashes_arr = $this->loadHC($hsd_n, $have_hashes_cnt);
        if (!is_array($new_hashes_arr)) {
            return false;
        }
        if (empty($new_hashes_arr)) {
            return $in_hash_n;
        }

        $f = false;
        $imported_cnt = 0;
        while (1) {
            if (!isset($new_hashes_arr['hashes_arr'][$in_hash_n])) {
                break;
            }
            if (false === $f) {
                $f = fopen($hash_file, 'ab');
            }
            $wb = fwrite($f, $new_hashes_arr['hashes_arr'][$in_hash_n]);
            if ($wb != $hash_size) {
                break;
            }
            $imported_cnt++;
            $in_hash_n++;
        }
        if ($f) {
            fclose($f);
        }
        if ($imported_cnt == \count($new_hashes_arr['hashes_arr'])) {
            $hc = $this->tryLockHC($hsd_n);
            if (is_resource($hc)) {
                ftruncate($hc, 0);
                $this->releaseHC($hc);
            }
        }
        return $in_hash_n;
    }

    /**
     * Return:
     *  string = error description
     *  false = ok, no more blocks
     *  true = can't lock hc, may be already calculate in other process
     *
     * @param int $hsd_n
     * @return boolean|string
     */
    public function calcNewHashes($hsd_n)
    {
        $parr = $this->openRead($hsd_n);
        if (!is_array($parr)) {
            return "Can't read hsd-file #$hsd_n";
        }
        $blocks_cnt = $parr['blocks_cnt'];
        if (!$blocks_cnt) {
            return "No blocks in hsd-file";
        }

        // hash-file records calculate
        $hash_size = $parr['hash_size'];
        $hash_file = $this->satFileName('h', $hsd_n);

        $need_repair = !is_file($hash_file);
        if (!$need_repair) {
            $file_size = filesize($hash_file);
            if (!$file_size || $file_size % $hash_size) {
                $need_repair = true;
            } else {
                $hashes_cnt = $file_size / $hash_size;
                $miss_blk = $blocks_cnt - $hashes_cnt + 1;
                if (!$miss_blk) {
                    // No new blocks
                    return false;
                }
                if ($miss_blk < 0) {
                    $need_repair = true;
                }
            }
        }
        if ($need_repair) {
            return $this->repairHashFile($hsd_n);
        }

        // miss_blk > 0 - how many new hashes need to calculate

        $new_hashes_cnt = $this->mergeHC($hsd_n, $hashes_cnt); // try to merge already calculated hashes

        if (($new_hashes_cnt !== false) && ($hashes_cnt != $new_hashes_cnt)) {
            $hashes_cnt = $new_hashes_cnt;
            $miss_blk = $blocks_cnt - $hashes_cnt + 1;
            if ($miss_blk <= 0) {
                // All hashes calculated or error
                return false;
            }
        }
        // read new-blocks seek-table
        $blocks_arr = $this->readSeekTable($hsd_n, $hashes_cnt - 1);
        if (!is_array($blocks_arr)) {
            return $blocks_arr;
        }

        // try open and Lock HC-file for exclusive write
        $hc = $this->tryLockHC($hsd_n);
        if (!is_resource($hc)) {
            return true;
        }

        // calculate new hases
        $hash_alg = $this->hash_alg;
        $f = $parr['f'];
        $in_blk_n = $hashes_cnt - 1;

        $blk_hash = false;
        while ($in_blk_n < $blocks_cnt) {
            $start_seek = $blocks_arr[$in_blk_n][0];
            $end_seek = $start_seek + $blocks_arr[$in_blk_n][1];
            $blk_hash = $this->blockHashCalc($f, $in_blk_n, $start_seek, $end_seek, $hash_alg, $hash_size, $blk_hash);
            if (empty($blk_hash)) {
                $this->releaseHC($hc);
                return "Can't calculate hash $hash_alg for in_blk #$in_blk_n in hsd-file #$hsd_n";
            }
            if (!$this->pushHC($hc, $in_blk_n + 1, $blk_hash)) {
                $this->releaseHC($hc);
                return "Can't write hc-file #$hsd_n";
            }
            $in_blk_n++;
        }
        $this->releaseHC($hc);

        fclose($f);

        // try to merge calculated hashes
        $new_hashes_cnt = $this->mergeHC($hsd_n, $hashes_cnt);
        if ($new_hashes_cnt !== false) {
            $hashes_cnt = $new_hashes_cnt;
        }

        // open hsd-file again and check blocks_cnt
        $parr = $this->openRead($hsd_n);
        if (!is_array($parr)) {
            return "Can't re-open hsd-file #$hsd_n";
        }
        $blocks_cnt = $parr['blocks_cnt'];

        $miss_blk = $blocks_cnt - $hashes_cnt + 1;

        // Clear HC flag (if need)
        if (!$miss_blk && $parr['hc']) {
            fclose ($parr['f']);
            if (false === $this->writeHCflag($parr['file_name'], 0, $hash_size)) {
                return "Can't clear hc-flag in hsd-file #$hsd_n";
            }
            // already check blocks_cnt
            $parr = $this->openRead($hsd_n);
            if (is_array($parr)) {
                $check_blocks_cnt = $parr['blocks_cnt'];
                if (!$parr['hc'] && ($check_blocks_cnt > $blocks_cnt)) {
                    fclose ($parr['f']);
                    // set hc flag
                    if (false === $this->writeHCflag($parr['file_name'], 1, $hash_size)) {
                        return "Can't restore hc-flag in hsd-file #$hsd_n";
                    }
                }
                $miss_blk = $check_blocks_cnt - $hashes_cnt + 1;
            }
        }
        return $miss_blk === 0;
    }
    public function writeHCflag($file_name, $flag, $hash_size)
    {
        $f = fopen($file_name, 'rb+');
        if (!$f || fseek($f, 2) || empty($hash_size)) {
            return false;
        }
        $ret = 1 == fwrite($f, chr($hash_size + ($flag ? 128 : 0)));
        fclose($f);
        return $ret;
    }
    public function calcHashes($hsd_n = false, $ret_array = true, $blocks_arr = false, $prev_hash = false)
    {
        if ($hsd_n === false) {
            $hsd_n = $this->hsd_n;
        }
        if ($blocks_arr === false) {
            $blocks_arr = $this->readSeekTable($hsd_n);
        }
        if (is_string($blocks_arr)) {
            return $blocks_arr;
        }
        if ($prev_hash === false) {
            $prev_hash = $this->readPrevHash($hsd_n);
            if (empty($prev_hash)) {
                $prev_hash = $this->readEdgeHash($hsd_n, 0);
            }
        }

        $parr = $this->openRead($hsd_n);
        if (!is_array($parr)) {
            return $parr;
        }
        $f = $parr['f'];

        if ($hsd_n == 1) {
            $zero_hash = $this->calcZeroHash();
            if (empty($prev_hash)) {
                $prev_hash = $zero_hash;
            } else {
                if ($prev_hash != $zero_hash) {
                    return "Different in Zero-hash";
                }
            }
        }
        if (empty($prev_hash)) {
            return "Can't read prev_hash";
        }
        $hash_alg = $this->hash_alg;
        $hash_size = strlen($prev_hash);
        $hash_arr = [$prev_hash];
        foreach($blocks_arr as $in_blk_n => $seek_len) {
            $seek = $seek_len[0];
            $len = $seek_len[1];
            $end_seek = $seek + $len;
            $blk_hash = $this->blockHashCalc($f, $in_blk_n, $seek, $end_seek, $hash_alg, $hash_size, $prev_hash);
            if (empty($blk_hash)) {
                return "Error hash calculate block #$in_blk_n in hsd-file #$hsd_n";
            }
            if ($ret_array) {
                $hash_arr[] = $blk_hash;
            }
            $prev_hash = $blk_hash;
        }
        fclose($f);
        if ($ret_array) {
            return $hash_arr;
        }
        return $blk_hash;
    }

    public function blockHashCalc($f, $blk_n, $start_seek, $end_seek, $hash_alg, $hash_size, $prev_hash = false)
    {
        $bytes_len = $end_seek - $start_seek;
        if (!$f || ($bytes_len < 0) || ($bytes_len > 16777215)) {
            return false;
        }
        if ($prev_hash === false) {
            $prev_hash = $this->readHashFile($blk_n, $hash_size);
        }
        if (empty($prev_hash)) {
            return false;
        }
        $hs = hash_init($hash_alg);
        if (empty($hs)) {
            return false;
        }
        hash_update($hs, $prev_hash);
        if (fseek($f, $start_seek)) {
            return false;
        }
        $size = hash_update_stream($hs, $f, $bytes_len);
        if ($bytes_len != $size) return false;
        $hash = hash_final($hs, true);
        return $hash;
    }
}