<?php
namespace ierusalim\hsd;

class hsdWalk
{
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