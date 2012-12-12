PHP Nonce
=========
This class can be used to insert an nonce into a form. The nonce can optionally be set to expire. Also nonce's can be stored in a mysql database to ensure that they are only ever used once.

What is an Nonce?
-----------------
A nonce is a 'Number Used Once'. This is usually used where you want an action to be performed only once. For example if a user on your site is presented a for to delete a blog post, we want to make sure this action can only be performed once with the given url. Including a Nonce in the url can ensure that this action will be performed only once.

Usage
-----
###Include class and create a new php-nonce object
  include 'nonce.php';
  $n = new Nonce;

###Make sure to set a minimum 32 character random string for $secret
  private $secret = "my super secret string";

###Set storage option
  protected $store = true; // set to true by default

When this is true nonce's will be tracked in a database and will only ensure that the nonce can only be used once. When this is set to true, you'll need to make sure that you have correclty setup your database details. Also a database should be created using th following:

  CREATE TABLE `nonce` (
    `nonce` varchar(128) NOT NULL DEFAULT '',
    `timestamp` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`nonce`)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8;

###Generate the nonce fields in your form
  <form action="process.php" method="post">
    <input type="submit" value="Delete">
    <?php $n->generateFormFields() ?>
  </form>

###In proces.php validate the nonce
  if($n->isFormPosted()){
    try{
      $msg = $n->validateForm();
    }catch (Exception $e){
      $msg = $e->getMessage(); 
    }
  }

If `$msg` is `true` then the form was successfully submitted. If it contains a string then an error occurred.

A full example can be seen in `example.php`

Options
-------
Review `nonce.php` to see the full list of options.
