<?php
namespace ierusalim\hsd;

class hsdIndex
{
/*
 stb-file format:
 0000 - start-block-number in hsb-file 1
 xxxx - start-block-number in hsb-file 2
 xxxx - start-block-number in hsb-file 3
 ...

 hsd-folder-file format:
 xxxx xxxx    xxxx      xxxx       xxxx      xxxx      xxxx      xxxx
   sid     wr_hsd_n  wr_trans_n   wr_seek  hash_seek  wr_blk_n  st_hsd_n

 */
    public function stbFileName()
    {
        return
            $this->base_path .
            $this->base_name .
            '-hsd.stb';
    }

    public function folderFileName()
    {
        return
            $this->base_path . 'hsd.list';
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

}
