<?php

/**
 * Create Nonce's (Number Used Once) in php. Can be used in a 'fake' nonce mode that 
 * doesn't require a database by setting $store to false. Not recommended though. 
 * When $store is set to true, it's possible to safely delete any nonce in the DB 
 * that are older than $expire. This can be done through a cron job and will help to 
 * keep the size of the database much smaller.
 * 
 * A MYSQL database can be created using the following SQL:
 *
 *   CREATE TABLE `nonce` (
 *     `nonce` varchar(128) NOT NULL DEFAULT '',
 *     `timestamp` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
 *     PRIMARY KEY (`nonce`)
 *   ) ENGINE=InnoDB DEFAULT CHARSET=utf8;
 *
 * Remeber, if you're using a hash type that is larger than 512bit then you'll need
 * to increase the size of the varchar for nonce.
 *
 * Don't forget to set $secret or the class will throw an exception.
 *
 * @version 1.0
 * @author Nick Verwymeren
 **/
class Nonce
{
  /**
   * How long in seconds the nonce will be good for. If you don't want the token to expire use -1.
   *
   * @var int
   **/
  protected $expire = 43200; // 12 Hours
  
  /**
   * A secret string that is hashed with a unique id and time. The longer
   * and more complex this is the better.
   *
   * @var string
   **/
  private $secret = "";
  
  /**
   * The hashing type used to create the nonce. 
   *
   * @var string
   **/
  protected $hash = 'sha256';
  
  /**
   * The amount of iternations done on a hash. This is done to enhance security. Larger 
   * numbers will be more secure but will increase the time needed to create the hash.
   *
   * @var int
   **/
  protected $iter = 100;
  
  /**
   * If true nonces will be stored in a database to ensure only one use.
   *
   * @var boolean
   **/
  protected $store = true;
  
  /**
   * The database username. Only used if $store is set to true.
   *
   * @var string
   **/
  private $db_user = "";
  
  /**
   * The database password. Only used if $store is set to true.
   *
   * @var string
   **/
  private $db_pass = "";
  
  /**
   * The database name. Only used if $store is set to true.
   *
   * @var string
   **/
  private $db_name = "my_site";
  
  /**
   * The database table name. Only used if $store is set to true.
   *
   * @var string
   **/
  private $db_table = "nonce";
  
  /**
   * The database host. Only used if $store is set to true.
   *
   * @var string
   **/
  private $db_host = "127.0.0.1";
  
  /**
   * Is a PDO database handler object. Only used if $store is set to true.
   *
   * @var object
   **/
  protected $dbh;
  

  public function __construct()
  {
    if(!$this->secret) throw new Exception("You cannot leave \$secret blank. Please set it to a random string.");
    if(strlen($this->secret) < 32) throw new Exception("Your secret key should be at least 32 characters");
    $this->secret = hash('sha224', $this->secret);

    if($this->store){
      try{
        $this->dbh = new PDO('mysql:host=' . $this->db_host . ';dbname=' . $this->db_name, $this->db_user, $this->db_pass);
        $this->dbh->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
      }catch (PDOException $e){
        throw new Exception($e);
      }
    }
  }
  
  
  /**
   * Checks the validity of a nonce. If valid (and $store is true) the nonce 
   * will become 'used' and invalid (meaning it cannot be used again).
   *
   * @param int $timestamp the time in the form of the unix epoch
   * @param float $uid a unique id created by php's uniqid() function (although this can technically be anything). 
   * @return Boolean true on success or will throw exception on error.
   **/
  public function validateAndUseNonce($timestamp, $uid, $nonce)
  {
    $hash = $this->getNonce($timestamp, $uid, strlen($nonce));

    // Check to see if nonce has been used. Only checks if nonce's are being stored.
    if($this->store && $this->nonceExists($nonce)){
      throw new Exception("This form has already been submitted once.");
    }

    // Check to see if time has expired
    if($this->expire > -1){
      if(time() > $timestamp + $this->expire){
        throw new Exception("This form has expired. Please reload the page and try submitting again.");
      }
    }

    if($nonce == $hash){
      if($this->store) $this->storeNonce($nonce);
      return true;
    } else {
      throw new Exception("Invalid form request. Please try again.");
    }
  }
  
  /**
   * Creates a unique nonce string with an optional length. Max length is dependent upon hashing algorithm.
   * @param int $timestamp the time in the form of the unix epoch
   * @param float $uid a unique id created by php's uniqid() function (although this can technically be anything). 
   * @param int length optional the length of the returned nonce. Max Dependent upon hashing algorithm.
   * @return string the nonce.
   **/
  public function getNonce($timestamp, $uid, $length = NULL)
  {
    global $site;
    $hash = hash($this->hash, $timestamp . $this->secret . $uid);
    $i = 0;
    do{
      $hash = hash($this->hash, $hash);
      $i++;
    } while ($i < $this->iter);
        
    if($length){
      $hash = substr($hash, 0, $length);
    }
    
    return $hash;
  }
  
  /** 
   * Store the nonce in the database.
   * @param string $nonce
   * @return boolean true on success false on failure 
   **/
  private function storeNonce($nonce)
  { 
    $sql = "INSERT INTO " . $this->db_table . " (nonce) VALUES (:nonce)";
    $q = $this->dbh->prepare($sql);
    return $q->execute(array(":nonce" => $nonce));
  }
  
  /** 
   * Checks the existence of a nonce in a database
   * @param string $nonce
   * @return mixed boolean false if does not exist, or int 1 if it does 
   **/
  private function nonceExists($nonce)
  {
    if(!$this->store) throw new Exception("Cannot determine if this nonce has been used since \$store is set to false. Set \$store to true in order to track nonce usage.");
    
    $sql = "SELECT COUNT(*) FROM " . $this->db_table . " WHERE nonce = :nonce LIMIT 1";
    $q = $this->dbh->prepare($sql);
    $q->execute(array(":nonce" => $nonce));
    return $q->fetchColumn();
  }

  /**
   * This may be called to validate a form that was generated using generateFormFields()
   *
   * @return boolean true if valid
   **/
  public function validateForm()
  {
    $plain = $this->fnDecrypt($_POST['key']);
    $plain = explode(' ', $plain, 2);

    $time = $plain[0];
    $uid = $plain[1];
    
    return $this->validateAndUseNonce($time, $uid, $_REQUEST['nonce']);
  }
  
  /**
   * Generates 3 hidden fields to add nonce capability to a form. Forms using this method
   * can be validated using validateForm().
   *
   * @return string
   **/
  public function generateFormFields($length = NULL)
  {
    $time = time();
    $uid = $this->generateUid();
    $key = $time . " " . $uid;
    
    // We'll need this info later so we don't want to simply hash it. We could just send it in plain
    // text but this is a little more secure and makes things very difficult to break.
    $key = $this->fnEncrypt($key);

    echo "\r\n<input type='hidden' name='nonce' value='" . $this->getNonce($time, $uid, $length) . "'>\r\n";
    echo "<input type='hidden' name='key' value='$key'>\r\n";
  }
  
  /**
   * Checks to see if a form was posted that contains fields generated by generateFormFields().
   *
   * @return boolean true if form was posted
   **/
  public function isFormPosted()
  {
    if(isset($_REQUEST['key']) && isset($_REQUEST['nonce'])) return true;
  }
  
  /**
   * Creates a cryptographically secure random string. Tries first using urandom (for *nix systems),
   * then tries openssl_random_pseudo_bytes and as a last resort mt_rand.
   *
   * @return string a random string
   **/
  public function generateUid($length = 32)
  {
    // Best option, but only on *nix systems. Also some web servers don't have access to this.
    if(is_readable('/dev/urandom')){
      $f = fopen('/dev/urandom', 'r');
      $seed = fgets($f, $length); // note that this will always return full bytes
      fclose($f);
      return base64_encode($seed);
    }
    
    // Next best thing but requires openssl
    if(extension_loaded('openssl')){
      $seed = bin2hex(openssl_random_pseudo_bytes($length));
      return base64_encode($seed);
    }
    
    // Last resort, mt_rand
    for ($i = 0; $i < $length; $i++) {
        $seed .= chr(mt_rand(0, 255));
    }

    return base64_encode($seed);
  }
  
  private function fnEncrypt($sValue)
  {
    return trim(
      base64_encode(
        mcrypt_encrypt(
          MCRYPT_RIJNDAEL_256,
          hash($this->hash, $this->secret, true), $sValue, 
          MCRYPT_MODE_ECB, 
          mcrypt_create_iv(
            mcrypt_get_iv_size(
              MCRYPT_RIJNDAEL_256, 
              MCRYPT_MODE_ECB
            ), 
            MCRYPT_RAND
          )
        )
      )
    );
  }

  private function fnDecrypt($sValue)
  {
    return trim(
      mcrypt_decrypt(
        MCRYPT_RIJNDAEL_256, 
        hash($this->hash, $this->secret, true), 
        base64_decode($sValue), 
        MCRYPT_MODE_ECB,
        mcrypt_create_iv(
          mcrypt_get_iv_size(
            MCRYPT_RIJNDAEL_256,
            MCRYPT_MODE_ECB
          ), 
        MCRYPT_RAND
        )
      )
    );
  }
  
  /**
   * Deletes any nonce's from the DB that are older than $expire. Nonce's older than $expire
   * can be safely deleted since they cannot be used anymore.
   *
   * @return boolean true on success
   **/
  public function cleanUpDb()
  {
    $sql = "DELETE FROM " . $this->db_table . " WHERE timestamp < DATE_ADD(now(), INTERVAL -:expire second)";
    $q = $this->dbh->prepare($sql);
    return $q->execute(array(":expire" => $this->expire));
  }
}