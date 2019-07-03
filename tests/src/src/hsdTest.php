<?php
namespace ierusalim\hsd;

/**
 * Generated by PHPUnit_SkeletonGenerator on 2019-07-02 at 12:11:37.
 */
class hsdTest extends \PHPUnit_Framework_TestCase
{
    protected $base_name = '0123456789abcdef';
    /**
     * @var hsd
     */
    protected $object;

    /**
     * Sets up the fixture, for example, opens a network connection.
     * This method is called before a test is executed.
     */
    protected function setUp()
    {
        $file_records_base = 'tests' . DIRECTORY_SEPARATOR . 'tmp';
        $this->object = new hsd($file_records_base, $this->base_name);
    }

    /**
     * Tears down the fixture, for example, closes a network connection.
     * This method is called after a test is executed.
     */
    protected function tearDown()
    {
        $hsd = $this->object;
        $file_name = $hsd->makeHSDfileName(1);
        $locker_name = $hsd->lockerFileName();

        // remove old files if exists
        if (is_file($file_name)) {
            unlink($file_name);
        }
        if (is_file($locker_name)) {
            unlink($locker_name);
        }
    }

    public function testConstruct()
    {
        $file_records_base = 'tests' . DIRECTORY_SEPARATOR . 'tmp';

        $hsd = new hsd($file_records_base, $this->base_name);
        $this->assertEquals($this->base_name, $hsd->base_name);

        // test path not found
        $this->setExpectedException("\Exception");
        $hsd = new hsd($file_records_base . 'bad', '0123456789abcdef');
    }

    /**
     * @covers ierusalim\hsd\hsd::makeHSDfileName
     * @todo   Implement testMakeHSDfileName().
     */
    public function testMakeHSDfileName()
    {
        $hsd = $this->object;
        $file_name = $hsd->makeHSDfileName(1);
        // create hsd with default parameters
        $par_arr = $hsd->createHSD();
        $this->assertTrue(is_file($file_name));
    }

    /**
     * @covers ierusalim\hsd\hsd::lockerFileName
     * @todo   Implement testLockerFileName().
     */
    public function testLockerFileName()
    {
        $hsd = $this->object;
        $locker_name = $hsd->lockerFileName();
        // create hsd with default parameters
        $par_arr = $hsd->createHSD();
        $this->assertTrue(is_file($locker_name));
    }

    /**
     * @covers ierusalim\hsd\hsdIndex::writeLocker
     * @todo   Implement testWriteLocker().
     */
    public function testWriteLocker()
    {
        $hsd = $this->object;
        $locker_name = $hsd->lockerFileName();

        $str = 'test';
        $r = hsdIndex::writeLocker($locker_name, $str);
        $this->assertFalse($r);
        $r = hsdIndex::writeLocker($locker_name, $str);
        $this->assertTrue(is_string($r));
    }

    /**
     * @covers ierusalim\hsd\hsd::packLocker
     * @todo   Implement testPackLocker().
     */
    public function testPackLocker()
    {
        $hsd = $this->object;
        $locker_str = $hsd->packLocker(
            32,//$hash_size
            'LW', //alg
            1, //$wr_hsd_n
            2, //$wr_trans_n
            3, //$wr_seek
            4, //$hash_seek
            5, //$wr_blk_n
            6, //$st_blk_n
            7, //$hsd_folder
            '' //$iii_str
        );
        $this->assertTrue(is_string($locker_str));

        $unp_arr = $hsd->unpackLocker($locker_str, true);
        $this->assertArrayHasKey('fix_arr', $unp_arr);
        $fix_arr = $unp_arr['fix_arr'];
        $i = 1;
        foreach($fix_arr as $k => $v) {
            $this->assertEquals($i++, $v);
        }
        $this->assertEquals(8, $i);
    }

    /**
     * @covers ierusalim\hsd\hsd::unpackLocker
     * @todo   Implement testUnpackLocker().
     */
    public function testUnpackLocker()
    {
        $hsd = $this->object;
        $locker_str = $hsd->packLocker(
            32,//$hash_size
            'LW', //alg
            1, //$wr_hsd_n
            2, //$wr_trans_n
            3, //$wr_seek
            4, //$hash_seek
            5, //$wr_blk_n
            6, //$st_blk_n
            7, //$hsd_folder
            '' //$iii_str
        );
        $this->assertTrue(is_string($locker_str));
        $unp_arr = $hsd->unpackLocker($locker_str, true);
        $this->assertArrayHasKey('fix_arr', $unp_arr);
        $fix_arr = $unp_arr['fix_arr'];
        $i = 1;
        foreach($fix_arr as $k => $v) {
            $this->assertEquals($i++, $v);
        }
        $this->assertEquals(8, $i);

        // "Not string"
        $u = $hsd->unpackLocker(false);
        $this->assertEquals("Not string", $u);

        // bad zero-byte
        $old = $locker_str[0];
        $locker_str[0] = chr(0);
        $u = $hsd->unpackLocker($locker_str);
        $this->assertTrue(is_string($u));
        $locker_str[0] = $old;

        // bad alg
        $locker_str[1] = 'U';
        $u = $hsd->unpackLocker($locker_str);
        $this->assertTrue(is_string($u));
        $locker_str[1] = 'L';

        // too short
        $u = $hsd->unpackLocker(substr($locker_str, 0, 31));
        $this->assertEquals("Header too short", $u);

        // unpack iii
        $u = $hsd->unpackLocker($locker_str, false);
        $this->arrayHasKey('iii_arr', $u);

        // Unsupported ehl
        $locker_str[3] = chr(99);
        $u = $hsd->unpackLocker($locker_str);
        $this->assertTrue(is_string($u));

    }

    /**
     * @covers ierusalim\hsd\hsd::checkHSDpar
     * @todo   Implement testCheckHSDpar().
     */
    public function testCheckHSDpar()
    {
        $hsd = $this->object;
        $par_arr = $hsd->checkHSDpar();
        $this->assertTrue(is_array($par_arr));

        $check_arr = $hsd->checkHSDpar($par_arr);
        $this->assertEquals($par_arr, $check_arr);

        // err: array required
        $s = $hsd->checkHSDpar('bad');
        $this->assertTrue(is_string($s));
        $this->assertEquals('Array reqired', $s);

        foreach($par_arr as $k => $v) {
            $bad_arr = $par_arr;
            unset($bad_arr[$k]);
            $s = $hsd->checkHSDpar($bad_arr);
            $this->assertTrue(is_string($s));
            if(is_array($v)) {
                foreach($v as $sk => $x) {
                    $bad_arr = $par_arr;
                    unset($bad_arr[$k][$sk]);
                    $s = $hsd->checkHSDpar($bad_arr);
                    $this->assertTrue(is_string($s));
                }
            }
        }

    }

    /**
     * @covers ierusalim\hsd\hsd::createHSD
     * @todo   Implement testCreateHSD().
     */
    public function testCreateHSD()
    {
        $hsd = $this->object;
        $file_name = $hsd->makeHSDfileName(1);
        $locker_name = $hsd->lockerFileName();


        // remove old files if exists
        if (is_file($file_name)) {
            unlink($file_name);
        }
        if (is_file($locker_name)) {
            unlink($locker_name);
        }

        // create hsd with default parameters
        $par_arr = $hsd->createHSD();
        $this->assertArrayHasKey('alg', $par_arr);

        // check created files
        $this->AssertTrue(is_file($file_name));
        $this->AssertTrue(is_file($locker_name));

        // error: already exist
        $par_str = $hsd->createHSD();
        $this->AssertTrue(is_string($par_str));

        $default_size = filesize($file_name);
        $default_locker = file_get_contents($locker_name);
        // remove files
        unlink($file_name);
        unlink($locker_name);

        // error: bad hsd-par
        $par_arr = ['bad' => 1];
        $par_str = $hsd->createHSD($par_arr);
        $this->AssertTrue(is_string($par_str));

        // error: Bad prev-hash size
        $par_str = $hsd->createHSD(false, 1, 0, '123');
        $this->AssertTrue(is_string($par_str));

        $par_arr = $hsd->createHSD(false, 1, 0, hash('sha256', '123', true));

        $this->assertTrue(is_array($par_arr));

        // check file size: with prev_hash and without prev_hash
        $fsize = filesize($file_name);
        $this->assertEquals($default_size + 32, $fsize);

        $prevhash_locker = file_get_contents($locker_name);

        $this->assertNotEquals($prevhash_locker, $default_locker);

        // check re-write opened locker
        $b = $hsd->beginWrite();
        $this->assertTrue(is_array($b));
        $par_arr = $hsd->createHSD();
        $this->assertTrue(is_array($par_arr));

        // compare rewrited locker with default locker
        $new_locker = file_get_contents($locker_name);
        $this->assertEquals($new_locker, $default_locker);

    }

    /**
     * @covers ierusalim\hsd\hsd::packHSDheader
     * @todo   Implement testPackHSDheader().
     */
    public function testPackHSDheader()
    {
        // Remove the following lines when you implement this test.
        $this->markTestIncomplete(
            'This test has not been implemented yet.'
        );
    }

    /**
     * @covers ierusalim\hsd\hsd::unpackHSDheader
     * @todo   Implement testUnpackHSDheader().
     */
    public function testUnpackHSDheader()
    {
        // Remove the following lines when you implement this test.
        $this->markTestIncomplete(
            'This test has not been implemented yet.'
        );
    }

    /**
     * @covers ierusalim\hsd\hsd::packINS
     * @todo   Implement testPackINS().
     */
    public function testPackINS()
    {
        $hsd = $this->object;

        $p = $hsd->packINS(0);

        $this->assertEquals(chr(0), $p);

        $p = $hsd->packINS(127);

        $this->assertEquals(chr(127), $p);

        $p = $hsd->packINS(128);

        $this->assertEquals(chr(128) . chr(128), $p);

        $p = $hsd->packINS(255);

        $this->assertEquals(chr(128) . chr(255), $p);

        $p = $hsd->packINS(256);

        $this->assertEquals(chr(129) . chr(0), $p);

        $p = $hsd->packINS(16383);

        $this->assertEquals(chr(191) . chr(255), $p);

        $p = $hsd->packINS(16384);

        $this->assertEquals(chr(192) . chr(64) . chr(0), $p);

        $p = $hsd->packINS(32768);

        $this->assertEquals(chr(192) . chr(128) . chr(0), $p);

        $p = $hsd->packINS(4194303);

        $this->assertEquals(chr(255) . chr(255) . chr(255), $p);

        $b = $hsd->unpackINS(ord($p), substr($p,1));
        $this->assertEquals(4194303, $b);

        $p = $hsd->packINS(4194304);
        $this->assertFalse($p);

        $p = $hsd->packINS(-1);

        $this->assertEquals(chr(128) . chr(1), $p);

        $p = $hsd->packINS(-127);

        $this->assertEquals(chr(128) . chr(127), $p);

        $p = $hsd->packINS(-128);

        $this->assertEquals(chr(192) . chr(0) . chr(128), $p);

        $p = $hsd->packINS(-16383); //c03fff

        $this->assertEquals(chr(192) . chr(63) . chr(255), $p);

        $p = $hsd->packINS(-16384);
        $this->assertFalse($p);

        $p = $hsd->packINS(111111111111111);
        $this->assertFalse($p);
        $p = $hsd->packINS(-111111111111111);
        $this->assertFalse($p);

    }

    /**
     * @covers ierusalim\hsd\hsd::unpackINS
     * @todo   Implement testUnpackINS().
     */
    public function testUnpackINS()
    {
        $hsd = $this->object;

        foreach([
            0 => 1,
            127 => 1,
            128 => 2,
            255 => 2,
            256 => 2,
            16383 => 2,
            16384 => 3,
            32767 => 3,
            32768 => 3,
            65535 => 3,
            65536 => 3,
            4194303 => 3,
            4194304 => 0,
            -1 => 2,
            -127 => 2,
            -128 => 3,
            -16383 => 3,
            -16384 => 0,
        ] as $n => $l) {
            $p = $hsd->packINS($n);
            $this->assertEquals($l, strlen($p));
            if ($p !== false) {
                $f = ord($p[0]);
                $u = $hsd->unpackINS($f, substr($p,1));
                $this->assertEquals($n, $u);
            }
        }
    }

    /**
     * @covers ierusalim\hsd\hsd::packIII
     * @todo   Implement testPackIII().
     */
    public function testPackIII()
    {
        // Remove the following lines when you implement this test.
        $this->markTestIncomplete(
            'This test has not been implemented yet.'
        );
    }

    /**
     * @covers ierusalim\hsd\hsd::unpackIII
     * @todo   Implement testUnpackIII().
     */
    public function testUnpackIII()
    {
        // Remove the following lines when you implement this test.
        $this->markTestIncomplete(
            'This test has not been implemented yet.'
        );
    }

    /**
     * @covers ierusalim\hsd\hsd::beginWrite
     * @todo   Implement testBeginWrite().
     */
    public function testBeginWrite()
    {
        // Remove the following lines when you implement this test.
        $this->markTestIncomplete(
            'This test has not been implemented yet.'
        );
    }

    /**
     * @covers ierusalim\hsd\hsd::endWrite
     * @todo   Implement testEndWrite().
     */
    public function testEndWrite()
    {
        // Remove the following lines when you implement this test.
        $this->markTestIncomplete(
            'This test has not been implemented yet.'
        );
    }

    /**
     * @covers ierusalim\hsd\hsd::appendRecord
     * @todo   Implement testAppendRecord().
     */
    public function testAppendRecord()
    {
        // Remove the following lines when you implement this test.
        $this->markTestIncomplete(
            'This test has not been implemented yet.'
        );
    }

    /**
     * @covers ierusalim\hsd\hsd::stdFinalCheck
     * @todo   Implement testStdFinalCheck().
     */
    public function testStdFinalCheck()
    {
        // Remove the following lines when you implement this test.
        $this->markTestIncomplete(
            'This test has not been implemented yet.'
        );
    }

    /**
     * @covers ierusalim\hsd\hsd::hashCalcInFile
     * @todo   Implement testHashCalcInFile().
     */
    public function testHashCalcInFile()
    {
        // Remove the following lines when you implement this test.
        $this->markTestIncomplete(
            'This test has not been implemented yet.'
        );
    }

    /**
     * @covers ierusalim\hsd\hsd::FileWalkBlocks
     * @todo   Implement testFileWalkBlocks().
     */
    public function testFileWalkBlocks()
    {
        // Remove the following lines when you implement this test.
        $this->markTestIncomplete(
            'This test has not been implemented yet.'
        );
    }

    /**
     * @covers ierusalim\hsd\hsd::FileVerifyBlockHashes
     * @todo   Implement testFileVerifyBlockHashes().
     */
    public function testFileVerifyBlockHashes()
    {
        // Remove the following lines when you implement this test.
        $this->markTestIncomplete(
            'This test has not been implemented yet.'
        );
    }

    /**
     * @covers ierusalim\hsd\hsd::FileWalkTrans
     * @todo   Implement testFileWalkTrans().
     */
    public function testFileWalkTrans()
    {
        // Remove the following lines when you implement this test.
        $this->markTestIncomplete(
            'This test has not been implemented yet.'
        );
    }
}
