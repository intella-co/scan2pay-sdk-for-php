<?php

/**
 * Created by PhpStorm.
 * User: Alexchiu
 * Date: 2018/3/14
 * Time: 下午 05:19
 */
class Rsa
{
    public function publicEncrypt($data, $publicKey)
    {
        openssl_public_encrypt($data, $encrypted, $publicKey);
        return $encrypted;
    }

    public function publicDecrypt($data, $publicKey)
    {
        openssl_public_decrypt($data, $decrypted, $publicKey);
        return $decrypted;
    }

    public function privateEncrypt($data, $privateKey)
    {
        openssl_private_encrypt($data, $encrypted, $privateKey);
        return $encrypted;
    }

    public function privateDecrypt($data, $privateKey)
    {
        openssl_private_decrypt($data, $decrypted, $privateKey);
        return $decrypted;
    }

    function verify($data, $sign,$publicKey ) {
        $res = openssl_get_publickey($publicKey);
        return (bool)openssl_verify($data, base64_decode($sign), $res,OPENSSL_ALGO_SHA256);
    }
}