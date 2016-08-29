<?php
// Originally from https://aai-viewer.switch.ch/viewer.php?source version 2007-07-26
// Original author: Lukas Haemmerle <lukas.haemmerle@switch.ch>

// Specify your attribute-map.xml file and make sure it is readable by the web server
$attribute_map_file = '/etc/shibboleth/attribute-map.xml';

// Set header
header('Content-type: text/html; charset=utf-8');

?><!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <title>Shibboleth attribute viewer</title>
    <link rel="stylesheet" type="text/css" href="assets/styles/style.css">
  </head>
  <body>
    <header>
      <nav class="navbar">
        <div class="container">
          <div class="nav">
            <a href="https://shibboleth.net/">
              <img src="assets/images/shibboleth-logo.png" alt="shibboleth-logo">
            </a>
            <?php
            // Uncomment this for proprietary logout support
            /*
            $pos = strpos($_SERVER['Shib-Identity-Provider'], '/idp');
            $logout_url = substr($_SERVER['Shib-Identity-Provider'], 0, $pos) . '/idp/profile/Logout';
            echo "<a href=\"{$logout_url}\">Log out</a>\n"
            */
            // Or uncomment this for SAML logout support
            /*
            echo "<a href=\"/Shibboleth.sso/Logout\">Log out</a>\n"
            */
            ?>
          </div>
        </div>
      </nav>
    </header>
    <div class="container content">
      <h1>Attribute viewer</h1>
      <table>
        <tr>
          <th>Attributes</th>
          <th>Values</th>
        </tr>
<?php
// Get the contents of the Shibboleth SP attribute map file
$attribute_map_lines = file($attribute_map_file);
$attribute_map = '';
foreach($attribute_map_lines as $line){
    $attribute_map .= $line;
}

// Parse the attribute map XML contents
$p = xml_parser_create();
xml_parse_into_struct($p, $attribute_map, $vals, $index);
xml_parser_free($p);

// Get the ID of each attribute in the attribute map file and add it to $HTTP_SHIB_HEADERS
$HTTP_SHIB_HEADERS = array();
foreach ($vals as $element){
    if ($element['tag'] == 'ATTRIBUTE' && isset($element['attributes']['ID'])){
        $HTTP_SHIB_HEADERS[$element['attributes']['ID']] = $element['attributes']['ID'];
    }
}

$status = '00';

// Dump all received Shibboleth attributes defined in attribute map
foreach ($_SERVER as $key => $value) {
    if (isset($HTTP_SHIB_HEADERS[$key])){
        $status[1] = '1';
        echo "        <tr>\n";
        echo '          <td>' . $HTTP_SHIB_HEADERS[$key] . "</td>\n";

        // Multivalued attributes are separated by semicolons, so replace them with newlines for now
        $value = str_replace(';', "\n", $value);

        // Escape any special characters
        $clean_value = htmlspecialchars(stripslashes($value));

        // Format multivalued attributes
        if (strpos($clean_value, "\n")) {
            $clean_value = str_replace("\n", '</pre></li><li><pre>', $clean_value);
            $clean_value = '<ul><li><pre>' . $clean_value . '</pre></li></ul>';

        // Format single-valued attributes
        } else {
            $clean_value = '<pre>' . $clean_value . '</pre>';
        }

        echo '          <td>' . $clean_value . "</td>\n";
        echo "        </tr>\n";
    }
}

// Dump all attributes starting with Shib-
foreach ($_SERVER as $key => $value) {
    if (eregi('Shib', $key)) {
        $status[0] = '1';
        echo "        <tr>\n";
        echo '          <td><span style="color: grey; font-style: italic;">' . $key . "</span></td>\n";
        echo '          <td><span style="color: grey; font-style: italic;"><pre>' . wordwrap(htmlspecialchars($value), 70, "<br>\n", true) . "</pre></span></td>\n";
        echo "        </tr>\n";
    }
}

// Check status
if ($status == '10' ) {
    echo '<tr>';
    echo '<td colspan=2><b>Valid Shibboleth session but no user attributes received!</b></td>';
    echo '</tr>';
    echo '<tr>';
    echo '<td colspan=2>Hint to Home Organization administrators:<br>Please verify your metadata and ARP files.</td>';
    echo '</tr>';
}

elseif ($status == '00') {
    echo '<tr>';
    echo '<td colspan=2><b>No valid Shibboleth session!</b></td>';
    echo '</tr>';
    echo '<tr>';
    echo '<td colspan=2>This web page is probably not protected with Shibboleth. Hint to Home Organization administrators:<br>Have a look at your web server or Shibboleth configuration</td>';
    echo '</tr>';
}
?>
      </table>
    </div>
  </body>
</html>
