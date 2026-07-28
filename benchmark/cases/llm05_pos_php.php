<?php
function run($client) {
    $out = $client->chat()->create([])->choices[0]->message->content;
    exec($out);
}
