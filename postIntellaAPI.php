<?php
require_once "Rsa.php";
  $ApiKey='';
  $Request='';

  //以下參數請參照規格書內容

    $Data =json_encode( array(
          "TimeExpire"=>"20180125180000",
          "DeviceInfo"=>"skb0001",
          "StoreOrderNo"=>"001",
          "Body"=>"英特拉奶茶",
          "FeeType"=>"TWD",
          "TotalFee"=>"35",
          "Detail"=>"商品細節"
      ));

    $Request_Json = array(
        "Header" => array(
            "Method" => "00000",
            "ServiceType"=>"OLPay",
            "MchId"=>"S2PTXXXX",
            "TradeKey"=>"0efieojgr98uh43j9",
            "CreateTime"=>"20180125102000"
        ),
        "Data" =>$Data
    );

    $Request = json_encode($Request_Json);

    require_once "keyforintella/Crypt.php";
    $key = 'Y3UJ147HKIYRT8Ovrsik0A==';
    $iv = '8651731586517315';
    $cbc = new Crypt(base64_decode($key), MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC,$iv);//AES
    $Request = $cbc->encrypt($Request);//$Request 加密结果

    $pub_key = openssl_pkey_get_public(file_get_contents('keyforintella/stage-public.pem'));
    $keyData = openssl_pkey_get_details($pub_key);

    $rsa = new Rsa();
    $rsa->publicKey = $keyData['key'];
    $ApiKey = $rsa->publicEncrypt($key, $rsa->publicKey);
    $ApiKey = base64_encode($ApiKey);

    $PostData = json_encode( array(
        "Request" =>$Request,
        "ApiKey"=>$ApiKey
        )
    );

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, 'https://s.intella.co/allpaypass/api/general');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($ch, CURLOPT_POST, 1);
    // Edit: prior variable $postFields should be $postfields;
    curl_setopt($ch, CURLOPT_POSTFIELDS, $PostData);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0); // On dev server only!
    curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type: application/json'));
    $Result = curl_exec($ch);
    if(curl_errno($ch) !== 0) {
        print_r('cURL error when connecting to ' . $url . ': ' . curl_error($curl));
    }
    curl_close($ch);
    $Response = json_decode($Result);
    $enc = $Response->Response;
    $decrypted = $cbc->decrypt($enc);//解密结果
     print_r(($decrypted));
     echo "<br>";

?>