<?php 
require_once("nonce.php");

$n = new Nonce;
$msg = '';

if($n->isFormPosted()){
  try{
    // Wil return true if valid.
    $msg = $n->validateForm();
  }catch (Exception $e){
    $msg = $e->getMessage(); 
  }
}
?>
<!DOCTYPE html>

<html lang="en">
<head>
	<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
	<title>test-nonce</title>
</head>
<body>
<?php if($msg === true) : ?>
  <div style="padding:10px;background:#D1FAAF;color:#306B28;border:1px solid #306B28">
    Form succesfully validated!
  </div>
<?php elseif($msg): ?>
  <div style="padding:10px;background:#FAB3AF;color:#6B2B28;border:1px solid #6B2B28">
    <?php echo $msg; ?>
  </div>
<?php endif; ?>
<form action="" method="post" accept-charset="utf-8">
  <?php $n->generateFormFields() ?>
  <p><input type="submit" value="Continue &rarr;"></p>
</form>
</body>
</html>
