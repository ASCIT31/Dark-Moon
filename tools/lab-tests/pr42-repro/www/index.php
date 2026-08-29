<?php
if (!isset($_GET['page'])) { header('Location: /index.php?page=home&lang=en'); exit; }
$page = $_GET['page'];
echo '<h1>Lupin Corp Intranet</h1>';
echo '<p>page=' . htmlspecialchars($page) . '</p>';
if ($page === 'debug') {
  echo "<pre>Fatal error: require(): Failed opening required '/var/www/html/includes/db_connect.php' in /var/www/html/index.php on line 42\ninclude_path='/usr/local/lib/php:/var/www/html/includes'</pre>";
}
echo '<a href="/~myfiles/">staff files</a>';
echo '<p>Partner portal: <a href="http://172.18.0.6/">partner site</a></p>';
