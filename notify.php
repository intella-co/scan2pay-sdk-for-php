<?php
require_once "Rsa.php";

$data = file_get_contents("php://input");
$json = json_decode($data);
$sign = $json->Sign;
unset($json->Sign);
$cal_data = json_encode($json);

$pub_key = openssl_pkey_get_public(file_get_contents('keyforintella/stage-public.pem'));
$keyData = openssl_pkey_get_details($pub_key);

$rsa = new Rsa();
$rsa->publicKey = $keyData['key'];



if ($rsa->verify($cal_data,$sign, $rsa->publicKey))
    echo 'true';
else
    echo 'false';




?>