<?php
function run($client) {
    $out = $client->chat()->create(['max_tokens' => 256])->choices[0]->message->content;
    exec("ls");
    return $out;
}
