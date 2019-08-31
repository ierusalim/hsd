<?php
namespace ierusalim\hsd;

class vc85
{
    private $vc85c;
    private $int_cp = 'cp1251';
    public $work_cp = 'utf-8';

    public function __construct($work_cp = 'utf-8')
    {
        $this->work_cp = $work_cp;
        $this->vc85c = '0123456789'
              . 'ABCDEFGHJKLMNPQRSTUVWXYZ'
              . 'abcdefghijkmnopqrstuvwxyz'
              //. 'згджилпфцчшюэ'
              //. 'БГДЖИЛПФЦЧШЮЯ'
              . hex2bin('e7e3e4e6e8ebeff4f6f7f8fefdc1c3c4c6c8cbcfd4d6d7d8dedf');
    }

    /**
     * Encode bytes-string to vc85 non-fixed-size string
     *
     * Output code-page (work_cp) if 'utf-8' by default
     *
     * @param string $src
     * @param false|string $output_cp
     * @return string
     */
    public function encode($src, $output_cp = false)
    {
        if (!$output_cp) {
            $output_cp = $this->work_cp;
        }
        $enc = $this->encode_cp1251($src);
        if ($enc !== false && $output_cp != $this->int_cp) {
            $enc = \mb_convert_encoding($enc, $output_cp, $this->int_cp);
        }
        return $enc;
    }

    /**
     * Decode vc85 non-fixed-size string to bytes string
     *
     * @param string $src
     * @param false|string $from_cp
     * @return false|string
     */
    public function decode($src, $from_cp = false)
    {
        if (!$from_cp) {
            $from_cp = $this->work_cp;
        }
        if ($from_cp != $this->int_cp) {
            $src = \mb_convert_encoding($src, $this->int_cp, $from_cp);
        }
        return $this->decode_cp1251($src);
    }

    /**
     * Encode bytes to non-fixed-size vc85 string in bytes-code (cp1251 base)
     *
     * each 4 bytes encode to 5 vc85-bytes
     *
     * @param string $src
     * @return string
     */
    public function encode_cp1251($src)
    {
        $first_c = $this->vc85c[0];
        $wrk_arr = str_split($src, 4);
        $last_k = count($wrk_arr) - 1;
        $last_s = $wrk_arr[$last_k];
        $last_a = 4 - strlen($last_s);
        if ($last_a) {
            $last_k--;
        }
        for($k = 0; $k <= $last_k; $k++) {
            $b85 = $this->base85_encode(unpack('N', $wrk_arr[$k])[1]);
            if ($a = 5 - strlen($b85)) {
                $b85 = str_repeat($first_c, $a) . $b85;
            }
            $wrk_arr[$k]= $b85;
        }
        if ($last_a && ($last_a < 4)) { // 1 (if 3 byte), 2 (if 2 byte), 3 (if 1 byte), 4 (empty)
            $s4 = str_repeat(chr(0), $last_a) . $last_s;
            $wrk_arr[$k] = str_pad(
                $this->base85_encode(unpack('N', $s4)[1]),
                5 - $last_a, $first_c, \STR_PAD_LEFT);
        }
        return implode($wrk_arr);
    }

    /**
     * Decode vc85 non-fixed-size string in bytes-code (cp1251 base code-page)
     *
     * @param string $src
     * @return string
     */
    public function decode_cp1251($src)
    {
        if (!strlen($src)) {
            return '';
        }

        $wrk_arr = \str_split($src, 5);
        $last_k = \count($wrk_arr) - 1;
        $last_s = $wrk_arr[$last_k];
        $last_a = 5 - \strlen($last_s);
        if ($last_a) {
            $last_k--;
        }
        for($k = 0; $k <= $last_k; $k++) {
            $c4 = pack('N', $this->base85_decode($wrk_arr[$k]));
            if ($a = 4 - \strlen($c4)) {
                $c4 = str_repeat(chr(0), $a) . $c4;
            }
            $wrk_arr[$k] = $c4;
        }
        if ($last_a) { // 1 (if 3 byte), 2 (if 2 byte), 3 (if 1 byte), 4 (if 1 byte)
            $dec = $this->base85_decode($last_s);
            $wrk_arr[$k] = \substr(pack('N', $dec), ($last_a < 3) ? $last_a : 3 - 4);
        }
        return \implode($wrk_arr);
    }

    /**
     * Encode integer value to vc85 fixed-size string
     *
     * @param int $dec (0 .. 2724905250390624)
     * @param int $len (1..8) Output string size
     * @return string|false
     */
    public function encode_fixed_int($dec, $len)
    {
        if ($len < 1 || $len > 8 || $dec < 0 || $dec > 2724905250390624) {
            return false;
        }
        $enc = $this->base85_encode($dec);
        if (is_string($enc)) {
            $l = strlen($enc);
            if ($l > $len) {
                return false;
            } elseif ($l < $len) {
                $first_c = $this->vc85c[0];
                $enc = str_pad($enc, $len, $first_c, \STR_PAD_LEFT);
            }
        }
        if (is_string($enc) && $this->work_cp != $this->int_cp) {
            $enc = \mb_convert_encoding($enc, $this->work_cp, $this->int_cp);
        }
        return $enc;
    }

    /**
     * Decode fixed-size vc85-string (1..8 bytes) to integer
     *
     * @param string $src
     * @return integer|false
     */
    public function decode_fixed_int($src)
    {
        if (!is_string($src)) {
            return false;
        }
        if ($this->work_cp != $this->int_cp) {
            $src = \mb_convert_encoding($src, $this->int_cp, $this->work_cp);
        }
        if (strlen($src) > 8) {
            return false;
        }
        return $this->base85_decode($src);
    }

    /**
     * Decode string from base85 to integer
     *
     * @param string $src
     * @return string|false
     */
    private function base85_decode($src)
    {
        $r = 0;
        for ($i = 0; $i < \strlen($src); $i++) {
            $ch = $src[$i];
            $c = \strpos($this->vc85c, $src[$i]);
            if ($c === false) {
                return false;
            }
            $r *= 85;
            $r += $c;
        }
        return $r;
    }

    /**
     * Convert from decimal to base85
     *
     * @param string $dec
     * @return string|false
     */
    private function base85_encode($dec)
    {
        if (!is_numeric($dec)) {
            return false;
        }
        $r = '';
        while ((integer)$dec > 0) {
            $dv = $dec / 85;
            $i = $dec % 85;
            $dec = $dv;
            $r .= $this->vc85c[$i];
        }
        return \strrev($r);
    }
}
