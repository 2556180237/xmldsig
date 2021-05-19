<?php

namespace Ostanin\XmlDSig;

use DOMDocument;
use DOMXPath;
use Ostanin\XmlDSig\Exception\XmlSignerException;
use UnexpectedValueException;

/**
 * Sign XML Documents with Digital Signatures (XMLDSIG).
 */
final class XmlSigner
{
    //
    // Signature Algorithm Identifiers, RSA (PKCS#1 v1.5)
    // https://www.w3.org/TR/xmldsig-core/#sec-PKCS1
    //
    private const SIGNATURE_SHA1_URL = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';
    private const SIGNATURE_SHA224_URL = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha224';
    private const SIGNATURE_SHA256_URL = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
    private const SIGNATURE_SHA384_URL = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384';
    private const SIGNATURE_SHA512_URL = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512';
    private const SIGNATURE_GOST2001_URL = 'urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102001-gostr3411';
    private const SIGNATURE_GOST2011_256_URL = 'urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256';
    private const SIGNATURE_GOST2011_512_URL = 'urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-512';

    //
    // Digest Algorithm Identifiers
    // https://www.w3.org/TR/xmldsig-core/#sec-AlgID
    //
    private const DIGEST_SHA1_URL = 'http://www.w3.org/2000/09/xmldsig#sha1';
    private const DIGEST_SHA224_URL = 'http://www.w3.org/2001/04/xmldsig-more#sha224';
    private const DIGEST_SHA256_URL = 'http://www.w3.org/2001/04/xmlenc#sha256';
    private const DIGEST_SHA384_URL = 'http://www.w3.org/2001/04/xmldsig-more#sha384';
    private const DIGEST_SHA512_URL = 'http://www.w3.org/2001/04/xmlenc#sha512';
    private const DIGEST_GOST2001_URL = 'urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr3411';
    private const DIGEST_GOST2012_256_URL = 'urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256';
    private const DIGEST_GOST2012_512_URL = 'urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-512';
    /**
     * @var int
     */
    private $sslAlgorithm;

    /**
     * @var string
     */
    private $algorithmName;

    /**
     * @var string
     */
    private $signatureAlgorithmUrl;

    /**
     * @var string
     */
    private $digestAlgorithmUrl;

    /**
     * @var resource|false
     */
    private $privateKeyId;

    /**
     * @var string
     */
    private $referenceUri = '';

    /**
     * @var string
     */
    private $modulus;

    /**
     * @var string
     */
    private $publicExponent;

    /**
     * @var XmlReader
     */
    private $xmlReader;

    /**
     * @var string
     */
    private $password;

    /**
     * @var string
     */
    private $thumbprint;

    /**
     *
     * @var string
     */
    public $signnode;

    /**
     *
     * @var string
     */
    public $signprefix;

    /**
     *
     * @var string
     */
    public $extratransform;

    /**
     * The constructor.
     */
    public function __construct()
    {
        $this->xmlReader = new XmlReader();
    }

    /**
     * Read and load the pfx file.
     *
     * @param string $filename PFX filename
     * @param string $password PFX password
     *
     * @throws XmlSignerException
     *
     * @return bool Success
     */
    public function loadPfxFile(string $filename, string $password): bool
    {
        if (!file_exists($filename)) {
            throw new XmlSignerException(sprintf('File not found: %s', $filename));
        }

        $certStore = file_get_contents($filename);

        if (!$certStore) {
            throw new XmlSignerException(sprintf('File could not be read: %s', $filename));
        }

        $status = openssl_pkcs12_read($certStore, $certInfo, $password);

        if (!$status) {
            throw new XmlSignerException('Invalid PFX password');
        }

        // Read the private key
        $this->privateKeyId = openssl_pkey_get_private((string)$certInfo['pkey']);

        if (!$this->privateKeyId) {
            throw new XmlSignerException('Invalid private key');
        }

        $this->loadPrivateKeyDetails();

        return true;
    }

    private function SetupCertificates($location, $name, $mode)
    {
        $store = new \CPStore();
        $store->Open($location, $name, $mode);
        return $store->get_Certificates();
    }

    private function SetupCertificate($location, $name, $mode,
                           $find_type, $query, $valid_only,
                           $number)
    {
        $certs = $this->SetupCertificates($location, $name, $mode);
        if ($find_type != NULL)
        {
            $certs = $certs->Find($find_type, $query, $valid_only);
            if (is_string($certs))
                return $certs;
            else
                return $certs->Item($number);
        }
        else
        {
            $cert = $certs->Item($number);
            return $cert;
        }
    }

    public function setSignatureContainer(string $thumbprint, string $password) {
        $this->thumbprint = $thumbprint;
        $this->password = $password;
        $this->privateKeyId = $this->SetupCertificate(CURRENT_USER_STORE, "my", STORE_OPEN_READ_ONLY,
        CERTIFICATE_FIND_SHA1_HASH, $thumbprint, 0, 1);
    }

    public function GetCPHash($content) {
        $hash = new \CPHashedData();
        $algId = 100;
        switch($this->digestAlgorithmUrl) {
            case self::DIGEST_SHA1_URL: $algId = 0; break;
            case self::DIGEST_SHA224_URL: $algId = 1; break;
            case self::DIGEST_SHA256_URL: $algId = 1; break;
            case self::DIGEST_SHA384_URL: $algId = 2; break;
            case self::DIGEST_SHA512_URL: $algId = 2; break;
            case self::DIGEST_GOST2001_URL: $algId = 100; break;
            case self::DIGEST_GOST2012_256_URL: $algId = 101; break;
            case self::DIGEST_GOST2012_512_URL: $algId = 102; break;
        }
        $hash->set_Algorithm($algId);
        $hash->Hash($content);
        return base64_encode(hex2bin($hash->get_Value()));
    }

    public function GetCPCert() {
        return $this->privateKeyId->Export(0);
    }

    public function GetCPSignature($content) {
        $signer = new \CPSigner();
        $signer->set_Certificate($this->privateKeyId);
        $signer->set_KeyPin($this->password);
        $signer->set_Options(2);
    
        $sd = new \CPSignedXml();
        $sd->set_SignatureType(2);
        $sd->set_Content($content);
        $sd->set_DigestMethod($this->digestAlgorithmUrl);
        $sd->set_SignatureMethod($this->signatureAlgorithmUrl);
            
        $signedXml = $sd->Sign($signer, "//*[local-name()='Signature' and position()=last()]");
        return $signedXml;
    }
    /**
     * Read and load a private key file.
     *
     * @param string $filename The PEM filename
     * @param string $password The PEM password
     *
     * @throws XmlSignerException
     *
     * @return bool Success
     */
    public function loadPrivateKeyFile(string $filename, string $password): bool
    {
        if (!file_exists($filename)) {
            throw new XmlSignerException(sprintf('File not found: %s', $filename));
        }

        $certStore = file_get_contents($filename);

        if (!$certStore) {
            throw new XmlSignerException(sprintf('File could not be read: %s', $filename));
        }

        // Read the private key
        $this->privateKeyId = openssl_pkey_get_private($certStore, $password);

        if (!$this->privateKeyId) {
            throw new XmlSignerException('Invalid password or private key');
        }

        $this->loadPrivateKeyDetails();

        return true;
    }

    /**
     * Load private key details.
     *
     * @throws UnexpectedValueException
     *
     * @return void
     */
    private function loadPrivateKeyDetails(): void
    {
        if (!$this->privateKeyId) {
            throw new UnexpectedValueException('Private key is not defined');
        }

        $details = openssl_pkey_get_details($this->privateKeyId);

        if ($details === false) {
            throw new UnexpectedValueException('Invalid private key');
        }

        $key = $this->getPrivateKeyDetailKey($details['type']);
        $this->modulus = base64_encode($details[$key]['n']);
        $this->publicExponent = base64_encode($details[$key]['e']);
    }

    /**
     * Get private key details key type.
     *
     * @param int $type The type
     *
     * @return string The array key
     */
    private function getPrivateKeyDetailKey(int $type): string
    {
        $key = '';
        $key = $type === OPENSSL_KEYTYPE_RSA ? 'rsa' : $key;
        $key = $type === OPENSSL_KEYTYPE_DSA ? 'dsa' : $key;
        $key = $type === OPENSSL_KEYTYPE_DH ? 'dh' : $key;
        $key = $type === OPENSSL_KEYTYPE_EC ? 'ec' : $key;

        return $key;
    }

    /**
     * Sign an XML file and save the signature in a new file.
     * This method does not save the public key within the XML file.
     *
     * @param string $filename Input file
     * @param string $outputFilename Output file
     * @param string $algorithm For example: sha1, sha224, sha256, sha384, sha512
     *
     * @throws XmlSignerException
     *
     * @return bool Success
     */
    public function signXmlFile(string $filename, string $outputFilename, string $algorithm): bool
    {
        if (!file_exists($filename)) {
            throw new XmlSignerException(sprintf('File not found: %s', $filename));
        }

        $contents = file_get_contents($filename);

        $signedData = $this->signXml($contents, $algorithm);

        file_put_contents($outputFilename, $signedData);

        return true;
    }

    /**
     * Runs child process and concats stdout and stderr together
     *
     * @param string $command Command
     * @param integer $retval Retrun code
     * @return string Mixed stdout and stderr output
     */
    private function system(string $command, &$retval) {
        $descriptorspec = array(
            0 => array("pipe", "r"),  // stdin - канал, из которого дочерний процесс будет читать
            1 => array("pipe", "w"),  // stdout - канал, в который дочерний процесс будет записывать 
            2 => array("pipe", "w")   // stderr - канал, в который дочерний процесс будет записывать 
        );
         
        $cwd = '/tmp';
        $env = array();
         
        $process = proc_open($command, $descriptorspec, $pipes, $cwd, $env);
         
        $output = '';
        if(is_resource($process)) {
            // $pipes теперь выглядит так:
            // 0 => записывающий обработчик, подключенный к дочернему stdin
            // 1 => читающий обработчик, подключенный к дочернему stdout
            // 2 => читающий обработчик, подключенный к дочернему stderr
         
            fclose($pipes[0]);

            $output .= stream_get_contents($pipes[1]);
            fclose($pipes[1]);

            $output .= stream_get_contents($pipes[2]);
            fclose($pipes[2]);
         
            // Важно закрывать все каналы перед вызовом
            // proc_close во избежание мертвой блокировки
            $retval = proc_close($process);
        }
        return $output;        
    }

    /**
     * Sign an XML data and return the signed data one.
     * This method does not save the public key within the XML file.
     *
     * @param string $data Input data
     * @param string $algorithm For example: sha1, sha224, sha256, sha384, sha512
     *
     * @throws XmlSignerException
     *
     * @return mixed Signed data or false if failed
     */
    public function signXml(string $data, string $algorithm = 'sha256')
    {
        if (!($this->privateKeyId)) {
            throw new XmlSignerException('No private key provided');
        }

        $this->setAlgorithm($algorithm);

        // Read the xml file content
        $xml = new DOMDocument();

        // Whitespaces must be preserved
        $xml->preserveWhiteSpace = true;

        $xml->formatOutput = false;

        $xml->loadXML($data);  
        // Canonicalize the content, exclusive and without comments
        if (!$xml->documentElement) {
            throw new UnexpectedValueException('Undefined document element');
        }
        if($this->signnode) {
            $nodes = $xml->getElementsByTagName($this->signnode);
            $node = $nodes->item(0);
            $count = $node->childNodes->length;
            for($i = 0; $i < $count; $i++) {
               $node->removeChild($node->childNodes->item(0));
            } 
        }
        $canonicalData = $xml->documentElement->C14N(true, false);
        $xml->loadXML($data);  

        if(isset($this->thumbprint)) {          
            $cprocsp = '/opt/cprocsp/bin/amd64/certmgr';
            if(!file_exists($cprocsp)) {
                $cprocsp = '/opt/cprocsp/bin/i386/certmgr';
            } elseif(!file_exists($cprocsp)) {
                $cprocsp = '/opt/cprocsp/bin/arm/certmgr';
            } elseif(!file_exists($cprocsp)) {
                $cprocsp = '/opt/cprocsp/bin/aarch64/certmgr';
            } elseif(!file_exists($cprocsp)) {
                $cprocsp = '/opt/cprocsp/bin/e2k/certmgr';
            } elseif(!file_exists($cprocsp)) {
                throw new \Exception("CProCSP Not found");
            }
            $cprocsp .= ' -list -thumbprint '.$this->thumbprint;
            $retval = 0;
            $result = $this->system($cprocsp, $retval);
            $result = explode("\n", $result);
            if($retval) {
                $code = array_pop($result);
                preg_match('/0x[0-9A-Fa-f]+/', $code, $match);
                throw new \Exception('Ошибка криптопровайдера: '.$match[1]);
            } else {
                foreach($result as $line) {
                    if(strpos($line, 'Provider Info')===0) {
                        if(preg_match('/ProvType: ([0-9]+),/', $line, $match)) {
                            switch($match[1]) {
                                case '75': $algorithm = 'gost2001'; break;
                                case '80': $algorithm = 'gost2012_256'; break;
                                case '81': $algorithm = 'gost2012_512'; break;
                                default: $algorithm = 'sha1'; break;
                            }
                        } else {
                            $algorithm = 'sha1';
                        }
                        $this->setAlgorithm($algorithm);
                    }                
                }
            }

            $digestValue = '';//$this->GetCPHash($canonicalData);
        } else {
            // Calculate and encode digest value
            $digestValue = openssl_digest($canonicalData, $this->algorithmName, true);
            if ($digestValue === false) {
                throw new UnexpectedValueException('Invalid digest value');
            }

            $digestValue = base64_encode($digestValue);
        }
        $this->appendSignature($xml, $digestValue, $this->signnode);
        if(isset($this->thumbprint)) {          
            $xmlData = (string) $xml->saveXML();
            return $this->GetCPSignature($xmlData);
        } else {
            return (string) $xml->saveXML();
        }
    }

    /**
     * Set reference URI.
     *
     * @param string $referenceUri The reference URI
     *
     * @return void
     */
    public function setReferenceUri(string $referenceUri)
    {
        $this->referenceUri = $referenceUri;
    }

    /**
     * Create the XML representation of the signature.
     *
     * @param DOMDocument $xml The xml document
     * @param string $digestValue The digest value
     *
     * @throws UnexpectedValueException
     *
     * @return void The DOM document
     */
    private function appendSignature(DOMDocument &$xml, string $digestValue, $nodename = null)
    {
        $signatureElement = $xml->createElement(($this->signprefix?($this->signprefix.':'):'').'Signature');
        $signatureElement->setAttribute('xmlns', 'http://www.w3.org/2000/09/xmldsig#');

        // Append the element to the XML document.
        // We insert the new element as root (child of the document)

        if (!$xml->documentElement) {
            throw new UnexpectedValueException('Undefined document element');
        }

        if($nodename) {
            $signaturesElement = $xml->getElementsByTagName($nodename);
            $signaturesElement = $signaturesElement->item(0);
            $signaturesElement->appendChild($signatureElement);
        } else {
            $xml->documentElement->appendChild($signatureElement);
        }

        $signedInfoElement = $xml->createElement(($this->signprefix?($this->signprefix.':'):'').'SignedInfo');
        $signatureElement->appendChild($signedInfoElement);

        $canonicalizationMethodElement = $xml->createElement(($this->signprefix?($this->signprefix.':'):'').'CanonicalizationMethod');
        $canonicalizationMethodElement->setAttribute('Algorithm', 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315');
        $signedInfoElement->appendChild($canonicalizationMethodElement);

        $signatureMethodElement = $xml->createElement(($this->signprefix?($this->signprefix.':'):'').'SignatureMethod');
        $signatureMethodElement->setAttribute('Algorithm', $this->signatureAlgorithmUrl);
        $signedInfoElement->appendChild($signatureMethodElement);

        $referenceElement = $xml->createElement(($this->signprefix?($this->signprefix.':'):'').'Reference');
        $referenceElement->setAttribute('URI', $this->referenceUri);
        $signedInfoElement->appendChild($referenceElement);

        $transformsElement = $xml->createElement(($this->signprefix?($this->signprefix.':'):'').'Transforms');
        $referenceElement->appendChild($transformsElement);

        // Enveloped: the <Signature> node is inside the XML we want to sign
        $transformElement = $xml->createElement(($this->signprefix?($this->signprefix.':'):'').'Transform');
        $transformElement->setAttribute('Algorithm', 'http://www.w3.org/2000/09/xmldsig#enveloped-signature');
        $transformsElement->appendChild($transformElement);

        if($this->extratransform) {
          $transformElement = $xml->createElement(($this->signprefix?($this->signprefix.':'):'').'Transform');
          $xmlcontent = $xml->createDocumentFragment();
          $xmlcontent->appendXML($this->extratransform['value']);
          $transformElement->appendChild($xmlcontent);
          $transformElement->setAttribute('Algorithm', $this->extratransform['alg']);
          $transformsElement->appendChild($transformElement);
        }

        $digestMethodElement = $xml->createElement(($this->signprefix?($this->signprefix.':'):'').'DigestMethod');
        $digestMethodElement->setAttribute('Algorithm', $this->digestAlgorithmUrl);
        $referenceElement->appendChild($digestMethodElement);

        $digestValueElement = $xml->createElement(($this->signprefix?($this->signprefix.':'):'').'DigestValue', $digestValue);
        $referenceElement->appendChild($digestValueElement);

        $signatureValueElement = $xml->createElement(($this->signprefix?($this->signprefix.':'):'').'SignatureValue', '');
        $signatureElement->appendChild($signatureValueElement);

        $keyInfoElement = $xml->createElement(($this->signprefix?($this->signprefix.':'):'').'KeyInfo');
        $signatureElement->appendChild($keyInfoElement);

        if(isset($this->thumbprint)) {

            $x509DataElement = $xml->createElement(($this->signprefix?($this->signprefix.':'):'').'X509Data');
            $keyInfoElement->appendChild($x509DataElement);
 
            $certData = '';//$this->GetCPCert();
            $x509CertificateElement = $xml->createElement(($this->signprefix?($this->signprefix.':'):'').'X509Certificate', $certData);
            $x509DataElement->appendChild($x509CertificateElement);

        } else {

            $keyValueElement = $xml->createElement(($this->signprefix?($this->signprefix.':'):'').'KeyValue');
            $keyInfoElement->appendChild($keyValueElement);

            $rsaKeyValueElement = $xml->createElement(($this->signprefix?($this->signprefix.':'):'').'RSAKeyValue');
            $keyValueElement->appendChild($rsaKeyValueElement);

            $modulusElement = $xml->createElement(($this->signprefix?($this->signprefix.':'):'').'Modulus', $this->modulus);
            $rsaKeyValueElement->appendChild($modulusElement);

            $exponentElement = $xml->createElement(($this->signprefix?($this->signprefix.':'):'').'Exponent', $this->publicExponent);
            $rsaKeyValueElement->appendChild($exponentElement);

        }

        if($this->thumbprint) {
            $signatureValue = '';//$this->GetCPSignature($c14nSignedInfo);
        } else {
            // http://www.soapclient.com/XMLCanon.html
            $c14nSignedInfo = $signedInfoElement->C14N(true, false);
            // Calculate and encode digest value
            if (!$this->privateKeyId) {
                throw new UnexpectedValueException('Undefined private key');
            }

            $status = openssl_sign($c14nSignedInfo, $signatureValue, $this->privateKeyId, $this->sslAlgorithm);

            if (!$status) {
                throw new XmlSignerException('Computing of the signature failed');
            }
            $xpath = new DOMXpath($xml);
            $signatureValueElement = $this->xmlReader->queryDomNode($xpath, '//*[name()=\''.($this->signprefix?($this->signprefix.':'):'').'SignatureValue\']', $signatureElement);
            $signatureValueElement->nodeValue = base64_encode($signatureValue);
        }
    }

    /**
     * Set signature and digest algorithm.
     *
     * @param string $algorithm For example: sha1, sha224, sha256, sha384, sha512
     */
    private function setAlgorithm(string $algorithm): void
    {
        switch ($algorithm) {
            case 'sha1':
                $this->signatureAlgorithmUrl = self::SIGNATURE_SHA1_URL;
                $this->digestAlgorithmUrl = self::DIGEST_SHA1_URL;
                $this->sslAlgorithm = OPENSSL_ALGO_SHA1;
                break;
            case 'sha224':
                $this->signatureAlgorithmUrl = self::SIGNATURE_SHA224_URL;
                $this->digestAlgorithmUrl = self::DIGEST_SHA224_URL;
                $this->sslAlgorithm = OPENSSL_ALGO_SHA224;
                break;
            case 'sha256':
                $this->signatureAlgorithmUrl = self::SIGNATURE_SHA256_URL;
                $this->digestAlgorithmUrl = self::DIGEST_SHA256_URL;
                $this->sslAlgorithm = OPENSSL_ALGO_SHA256;
                break;
            case 'sha384':
                $this->signatureAlgorithmUrl = self::SIGNATURE_SHA384_URL;
                $this->digestAlgorithmUrl = self::DIGEST_SHA384_URL;
                $this->sslAlgorithm = OPENSSL_ALGO_SHA384;
                break;
            case 'sha512':
                $this->signatureAlgorithmUrl = self::SIGNATURE_SHA512_URL;
                $this->digestAlgorithmUrl = self::DIGEST_SHA512_URL;
                $this->sslAlgorithm = OPENSSL_ALGO_SHA512;
                break;
            case 'gost2001':
                $this->signatureAlgorithmUrl = self::SIGNATURE_GOST2001_URL;
                $this->digestAlgorithmUrl = self::DIGEST_GOST2001_URL;
                $this->sslAlgorithm = OPENSSL_ALGO_MD4;
                break;
            case 'gost2012_256':
                $this->signatureAlgorithmUrl = self::SIGNATURE_GOST2011_256_URL;
                $this->digestAlgorithmUrl = self::DIGEST_GOST2012_256_URL;
                $this->sslAlgorithm = OPENSSL_ALGO_SHA256;
                break;
            case 'gost2012_512':
                $this->signatureAlgorithmUrl = self::SIGNATURE_GOST2011_512_URL;
                $this->digestAlgorithmUrl = self::DIGEST_GOST2012_512_URL;
                $this->sslAlgorithm = OPENSSL_ALGO_SHA512;
                break;
            default:
                throw new XmlSignerException("Cannot validate digest: Unsupported algorithm <$algorithm>");
        }

        $this->algorithmName = $algorithm;
    }

    /**
     * Destructor.
     */
    public function __destruct()
    {
        // Free the key from memory
        if(!isset($this->thumbprint)) {          
          if ($this->privateKeyId) {
            openssl_free_key($this->privateKeyId);
          }
        }
    }
}
