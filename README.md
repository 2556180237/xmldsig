Sign XML Documents with Digital Signatures for Alfa Link (https://alfabank.ru/corporate/rko/alfa-link/)

Альфа-Линк — канал интеграции с программами 1С, который позволяет направлять платежные поручения из вашей учетной системы напрямую в банк и видеть все движения по расчетному счету.

Данная библиотека позволяет интегрироваться с альфабанком используя Криптопро и php-cades. Позволяет также видить движение денежных средств, используя только php7.4 на подобии интеграции с 1с

Как использовать:
<code>

      $certificate = '';     
      $pincode = '';      
      $signer = new XmlSigner();
        
        if ($this->engine == self::CryptoPro)
        {
            $signer->setSignatureContainer($certificate, $pincode);
        }
        else 
        {
            $signer->loadPfxFile($certificate, $pincode);
        }

        $signer->signnode = 'someCode';
        $signer->signprefix = 'somePrefix';
        $signer->extratransform = ['foo' => 'bar'];
        $signedData = $signer->signXml($xmldata);  
</code>
