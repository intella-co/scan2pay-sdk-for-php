<?php

	
/**
 * DES/AES加密封装
 *
 * 1、默認使用 Pkcs7 填充加密內容。
 * 2、默認加密向量是 "\0\0\0\0\0\0\0\0"。
 * 3、默認情況下，金鑰（key）經過處理：過長剪取，過短填充。
 * 
 * DES/AES加密封裝
 * 
 * 1、默认使用Pkcs7填充加密内容。
 * 2、默认加密向量是"\0\0\0\0\0\0\0\0"
 * 3、默认情况下key做了处理：过长截取，过短填充
 *
 * DES/AES Encryption Wrapper
 * 
 * 1. By default, Pkcs7 padding is used for encrypting the content.
 * 2. The default encryption vector is "\0\0\0\0\0\0\0\0".
 * 3. By default, the key undergoes processing: trimmed if too long, padded if too short.
 * 
 * @author 52fhy
 * @github https://github.com/52fhy/
 * @date 2017-5-13 17:08:57
 * Class Crypt
 */
class Crypt {
    // 加密key：如果key長度不是加解密算法能夠支持的有效長度，將自動填充 "\0"。過長則會截取。
    // 加密key：如果key长度不是加解密算法能够支持的有效长度，会自动填充 "\0"。过长则会截取。
    // Encryption Key: If the key length is not a valid length supported by the
    // encryption/decryption algorithm, it will be automatically padded with "\0".
    // If the key is too long, it will be truncated.
    private $key;
    
    // 加密向量：這裡默認填充 "\0"。假設為空，程序將隨機產生，導致加密的結果是不確定的。ECB 模式下會忽略該變數。
    // 加密向量：这里默认填充 "\0"。假设为空，程序会随机产生，导致加密的结果是不确定的。ECB 模式下会忽略该变量。
    // Encryption Vector: Here, the default padding is "\0". Assuming it is empty,
    // the program will generate a random vector,resulting in an indeterminate encryption outcome.
    // In ECB mode, this variable is ignored.
    private $iv;
    
    // 分組密碼模式：MCRYPT_MODE_modename 常數中的一個，或以下字符串中的一個："ecb"，"cbc"，"cfb"，"ofb"，"nofb" 和 "stream"。
    // 分组密码模式：MCRYPT_MODE_modename 常量中的一个，或以下字符串中的一个："ecb"，"cbc"，"cfb"，"ofb"，"nofb" 和 "stream"。
    // Block Cipher Mode: One of the constants from MCRYPT_MODE_modename or one of the following strings: "ecb," "cbc," "cfb," "ofb," "nofb," and "stream".
    private $mode;
    
    // 算法名稱：MCRYPT_ciphername 常數中的一個，或者是字符串值的算法名稱。
    // 算法名称：MCRYPT_ciphername 常量中的一个，或者是字符串值的算法名称。
    // Algorithm Name: One of the constants from MCRYPT_ciphername or the algorithm name as a string value.
    private $cipher;

    public function __construct($key, $cipher = MCRYPT_RIJNDAEL_128, $mode = MCRYPT_MODE_ECB, $iv = "\0\0\0\0\0\0\0"){
        $this->key = $key;
        $this->iv = $iv;
        $this->mode = $mode;
        $this->cipher = $cipher;
    }
    public function encrypt($input){
        $block_size = mcrypt_get_block_size($this->cipher, $this->mode);
        // 將 key 填充至 block 大小。
        // 将 key 填充至 block 大小。
        // Padding the key to the block size.
        $key = $this->_pad0($this->key, $block_size);
        $td = mcrypt_module_open($this->cipher, '', $this->mode, '');
        $iv = $this->iv ? $this->_pad0($this->iv, $block_size) : @mcrypt_create_iv (mcrypt_enc_get_iv_size($td), MCRYPT_RAND);
        $input = $this->pkcs7_pad($input, $block_size);
        //加密方法一 (Encryption Method 1)：
//        // ECB模式下，初始向量iv會被忽略。
//        // ECB模式下，初始向量iv会被忽略。
//        // In ECB mode, the initial vector (iv) will be ignored.
//        @mcrypt_generic_init($td, $key, $iv);
//        $data = mcrypt_generic($td, $input);
//        mcrypt_generic_deinit($td);
//        mcrypt_module_close($td);
        //加密方法二 (Encryption Method 2)：
        $data = mcrypt_encrypt(
            $this->cipher,
            $key,
            $input,
            $this->mode,
            // ECB模式下，初始向量iv會被忽略。
            // ECB模式下，初始向量iv会被忽略。
            // In ECB mode, the initial vector (iv) will be ignored.
            $iv
        );
        // 如需轉換二進位可改成 bin2hex 轉換。
        // 如需转换二进制可改成 bin2hex 转换。
        // If binary conversion is needed, it can be changed to bin2hex conversion.
        $data = base64_encode($data);
        return $data;
    }
    public function decrypt($encrypted){
        $block_size = mcrypt_get_block_size($this->cipher, $this->mode);
        $key = $this->_pad0($this->key, $block_size);
        $td = mcrypt_module_open($this->cipher, '', $this->mode, '');
        $iv = $this->iv ? $this->_pad0($this->iv, $block_size) : @mcrypt_create_iv (mcrypt_enc_get_iv_size($td), MCRYPT_RAND);
        //解密方法一 (Decryption Method 1)：
//        // 如需轉換二進位可改成 bin2hex 轉換。
//        // 如需转换二进制可改成 bin2hex 转换。
//        // If binary conversion is needed, it can be changed to bin2hex conversion.
//        $encrypted = base64_decode($encrypted);
//        @mcrypt_generic_init($td, $key, $iv);
//        $decrypted = mdecrypt_generic($td, $encrypted);
//        mcrypt_generic_deinit($td);
//        mcrypt_module_close($td);
        //解密方法二 (Decryption Method 2)：
        $decrypted = mcrypt_decrypt(
            $this->cipher,
            $key,
            base64_decode($encrypted),
            $this->mode,
            // ECB模式下，初始向量iv會被忽略。
            // ECB模式下，初始向量iv会被忽略。
            // In ECB mode, the initial vector (iv) will be ignored.
            $iv
        );
        return $this->_unpad($decrypted);
    }
    /**
     * 當使用 "PKCS＃5" 或 "PKCS5Padding" 別名引用該算法時，不應該假定支持 8 字節以外的區塊大小。
     * 当使用 “PKCS＃5” 或 “PKCS5Padding” 别名引用该算法时，不应该假定支持 8 字节以外的块大小。
     * When using the alias "PKCS#5" or "PKCS5Padding" to reference this algorithm, it should not be assumed to support block sizes beyond 8 bytes.
     * 
     * @url http://www.users.zetnet.co.uk/hopwood/crypto/scan/cs.html#pad_PKCSPadding
     * @param $text
     * @return string
     */
    public  function pkcs5_pad($text) {
        $pad = 8 - (strlen($text) % 8);
        // $pad = 8 - (strlen($text) & 7);  // This method can also be used.
        return $text . str_repeat(chr($pad), $pad);
    }
    public  function pkcs7_pad ($text, $blocksize) {
        $pad = $blocksize - (strlen($text) % $blocksize);
        return $text . str_repeat(chr($pad), $pad);
    }
    public  function _unpad($text){
        $pad = ord(substr($text, -1));// To obtain the ASCII code value of the last character
        if ($pad < 1 || $pad > strlen($text)) {
            $pad = 0;
        }
        return substr($text, 0, (strlen($text) - $pad));
    }
    /**
     * 金鑰 key 和向量 iv 填充算法：大於 block_size 則截取；小於則填充 "\0"。
     * 秘钥 key 和向量 iv 填充算法：大于 block_size 则截取；小于则填充 "\0"。
     * "key" and "iv" Padding Algorithm: If greater than the block_size, truncate; if smaller, pad with "\0".
     * @param $str
     * @param $block_size
     * @return string
     */
    private  function _pad0($str, $block_size) {
        // chr(0) 與 "\0" 等效，因為 "\0" 轉義後表示空字符，與 ASCII 表中的 0 代表的字符相同。
        // chr(0) 与 "\0" 等效，因为 "\0" 转义后表示空字符，与 ASCII 表里的 0 代表的字符一样。
        // chr(0) is equivalent to "\0" because "\0" represents the null character when escaped, which is the same as the character represented by ASCII 0.
        return str_pad(substr($str, 0, $block_size), $block_size, chr(0)); 
    }
}
	
	
?>
