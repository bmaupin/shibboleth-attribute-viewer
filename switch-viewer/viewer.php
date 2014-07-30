<?php
// Version: 2007-07-26
// Latest version of this script will be on https://aai-viewer.switch.ch/viewer.php?source
//
// Author: Lukas Haemmerle <lukas.haemmerle@switch.ch>
// Bug reports etc. please to aai@switch.ch

// Specify your attribute-map.xml file and make sure it is readable by the web server
$attribute_map_file = '/etc/shibboleth/attribute-map.xml';

//Set header
header('Content-type: text/html; charset=utf-8');

// Show source
if (isset($_REQUEST['source'])) {
    highlight_file(__FILE__);
    exit;
}
?><!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">

<html>
<head>
    <title>SWITCH Attribute Viewer</title>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
    <style type="text/css">
<!--
a
{
    color: #1B3E93;
    font-size: 14px;
    font-weight: bold;
    text-decoration: none;
}

a:hover
{
    color: #FE911B;
    text-decoration: underline;
}

body 
{
    background-color: white;
    font-family: Verdana, Arial, Helvetica, sans-serif;
}

h1
{
    font-family: Verdana, Arial, Helvetica, sans-serif;
    font-size: 18px;
    font-weight: bold;
    text-decoration: none;
}

.logo
{
    color: white;
    text-decoration: none;
}

.border-blue
{
    border-style: solid;
    border-width: 1px;
    border-color: rgb(0,43,127);
    font-family: Verdana, Arial, Helvetica, sans-serif;
    font-size: 13px;
}

.border-orange
{
    border-style: solid;
    border-width: 1px;
    border-color: rgb(226,140,5);
    font-family: Verdana, Arial, Helvetica, sans-serif;
    font-size: 13px;
}

.blue
{
    color: rgb(0,43,127);
}

.orange
{
    color: rgb(226,140,5);
}

td.top-left {
    background-image: url('images/topleft.gif');
    height: 14px;
    width: 14px;
}

td.top-middle {
    background-image: url('images/topcenter.gif');
    height: 14px;
}

td.top-right {
    background-image: url('images/topright.gif');
    height: 14px;
    width: 14px;
}
td.middle-left {
    background-image: url('images/middleleft.gif');
    width: 14px;
}

td.middle-right {
    background-image: url('images/middleright.gif');
    width: 14px;
}

td.bottom-left {
    background-image: url('images/bottomleft.gif');
    height: 14px;
    width: 14px;
}

td.bottom-middle {
    background-image: url('images/bottomcenter.gif');
    height: 14px;
}

td.bottom-right {
    background-image: url('images/bottomright.gif');
    height: 14px;
    width: 14px;
}
-->
</style>
</head>

<body>
<div align="center">

<table border="0" cellpadding="0" cellspacing="0">
<!-- top left corner + middle bar + right corner -->
<tr>
    <td class="top-left"></td>
    <td class="top-middle"></td>
    <td class="top-right"></td>
</tr>
<!-- left border + content + right border -->
<tr>
    <!-- left border -->
    <td class="middle-left"></td>
    <!-- content -->
    <td>
    <a class="logo" href="http://www.switch.ch/aai">
        <img alt="SWITCHaai logo" src="images/switch-aai-logo.gif" style="padding-bottom: 7px" /></a>
    <h1>SWITCH Attribute Viewer</h1>

<!-- table content -->
<table width="100%">
<tr>
<td class="blue">Attributes</td><td class="orange">Values</td>
</tr>
<?php 

$attribute_map_lines = file($attribute_map_file);
$attribute_map = '';
foreach($attribute_map_lines as $line){
    $attribute_map .= $line;
}

$p = xml_parser_create();
xml_parse_into_struct($p, $attribute_map, $vals, $index);
xml_parser_free($p);

$HTTP_SHIB_HEADERS = array();
foreach ($vals as $element){
    if ($element['tag'] == 'ATTRIBUTE' && isset($element['attributes']['ID'])){
        $HTTP_SHIB_HEADERS[$element['attributes']['ID']] = $element['attributes']['ID'];
    }
}

// Dump all received Shibboleth attributes
$status = '00';
foreach ($_SERVER as $key => $value){
    // Do we have any variables defined in attribute map
    if (isset($HTTP_SHIB_HEADERS[$key])){
        $status[1] = '1';
        echo '<tr valign="top">';
        echo '<td class="border-blue" valign="top">'.$HTTP_SHIB_HEADERS[$key].'</td>';
        $clean_value = ereg_replace('\$','<br>',htmlspecialchars(stripslashes($value)));
        if (ereg(';', $clean_value)){
            $clean_value = ereg_replace(";",'</tt></li><li><tt>',$clean_value); 
            $clean_value = '<ul><li><tt>'.$clean_value.'</tt></li></ul>';
        }
        else {
            $clean_value = '<tt>'.$clean_value.'</tt>';
        }
        
        echo '<td class="border-orange">'.$clean_value.'</td>';
        echo '</tr>';
    }
    // or any attributes starting with Shib-
    elseif (eregi('Shib', $key) ) {
        $status[0] = '1';
        echo '<tr>';
        echo '<td class="border-blue" valign="top"><span style="color: grey; font-style:italic;">'.$key.'</span></td>';
        echo '<td class="border-orange"><span style="color: grey; font-style:italic;"><tt>'.wordwrap(htmlspecialchars($value), 70, "<br/>\n", true).'</tt></span></td>';
        echo "</tr>\n";
    }
}
if (isset($_REQUEST['assertions'])) {
    $counter = 1;
    foreach ($_SERVER as $key=>$value){
        
        // Check if it is an assertion
        if (ereg('Shib-Assertion-Count', $key)  || !eregi('Shib-Assertion', $key)) {
            continue;
        }
        
        // Download the assertion
        $value = ereg_replace('dieng.switch.ch','127.0.0.1',stripslashes($value));
        
        $assertion = '';
        $handle = fopen($value, 'rb');
        if ($handle){
            while (!feof($handle)) {
                $tmp = fread($handle, 8192);
                if (!$tmp){
                    break;
                }
                $assertion .= $tmp;
            }
            fclose($handle);
        }
        
        echo '<tr><td colspan="2" class="border-orange"><h4>Assertion '.$counter.':</h4>';
        $assertion = ereg_replace('<', "\n<", $assertion);
        $assertion = preg_replace('/>(.+)/', ">\n$1", $assertion);
        $assertion = preg_replace("/\s([\S]+)=\"([^\"]+)/", "\n$1=\"$2",$assertion);
        $elements = preg_split('/\n/',$assertion);
        echo '<pre>';
        $indent = -1;
        foreach ($elements as $element){
            if (ereg('</', $element) && ereg('/>', $element)){
                echo '';
            }
            else if (ereg('/>', $element)){
                $reduce_indent = true;
                echo '';
            }
            elseif (ereg('</', $element)){
                $reduce_indent = true;
            }
            elseif (ereg('<', $element)){
                $indent++;
            }
            else {
                echo '&nbsp;&nbsp;';
            }
            
            for($i = 0; $i < $indent; $i++)
                echo '    ';
            
            // Syntax highlighting
            $element = ereg_replace('<','&lt;',$element);
            $element = ereg_replace('>','&gt;',$element);
            
            $element = preg_replace('/(\w+)="(.+)"/', " <span style=\"color:green\">$1</span>=<span style=\"color:brown\">&quot;$2&quot;</span>", $element);
            $element = preg_replace('/(&lt;.+)/', "<span style=\"color:blue\">$1</span>", $element);
            $element = ereg_replace('span>&gt;', "span><span style=\"color:blue\">&gt;</span>", $element);
            
            
            if (!ereg('=', $element) && !ereg('&lt;', $element))
                echo  '<span style="color:black;">'.wordwrap($element."\n", 120, "\n", 1).'</span>';
            else
                echo  wordwrap($element."\n", 120, "\n", 1);
            
            if ($reduce_indent){
                $indent--;
                $reduce_indent = false;
            }
        }
        
        echo '</pre>';
        echo '</td></tr>';
        
        $counter++;
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

else {
?>
<tr>
    <td colspan="2" align="center">
<?php
    if (isset($_REQUEST['assertions'])) {
        echo '<a href=".">Hide Shibboleth assertions</a>'; 
    } 
    else {
        echo '<a href="?assertions">Show Shibboleth assertions</a>'; 
    }
    
    if (isset($_REQUEST['all_variables'])) {
        echo ' | <a href=".">Hide all HTTP variables</a>'; 
    }
    else {
        echo ' | <a href="?all_variables">Show all HTTP variables</a>'; 
    }
?>
 | <a href="?source">Show PHP source</a>
    </td>
</tr>
<?php
}
?>
</table>
<!-- end content -->
</td>
  <!-- right border -->
  <td class="middle-right"></td>
</tr>
<!-- bottom left corner + middle bar + right corner -->
<tr>
  <td class="bottom-left"></td>
  <td><img src="images/bottomcenter.gif" height="14" width="100%" alt="bottomcenter" /></td>
  <td class="bottom-right"></td>
</tr>
</table>

<!-- all HTTP variables -->
<?php
    if (isset($_REQUEST['all_variables'])) {
        ?>
<p>&nbsp;</p>
    <table>
        <tr>
            <td><strong>HTTP Environment Variables</strong></td><td><strong>Raw Values</strong></td></tr>
        <?php
        ksort($_SERVER);
        foreach ($_SERVER as $key => $value) {
            if ( ereg('^Shib-', $key)  || isset($HTTP_SHIB_HEADERS[$key])) 
            { 
                $class= "border-orange"; 
            }
            else {
                $class= "border-blue";
            }
            echo '<tr valign="top">';
            echo '<td class="'.$class.'">'.$key.'</td>';
            if (is_array($value)){
                echo '<td class="'.$class.'">';
                if (!empty($value)){
                    echo '<ul>';
                    foreach($value as $item){
                        echo '<li><tt>'.wordwrap($item, 70, '<br>', true).'</tt></li>';
                    }
                    echo '</ul>';
                }
                echo '</td>';
            } else {
                echo '<td class="'.$class.'"><tt>'.wordwrap(htmlspecialchars(stripslashes($value)), 70, '<br>', true).'</tt></td>';
            }
            echo "</tr>\n";
        }
    ?>
    </table>
    <?php
    } 
?>
</div>
</body>
</html>

