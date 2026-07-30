<?php
$result = $client->chat()->create([
    'model' => 'gpt-4o',
    'messages' => $messages,
    'max_tokens' => 256,
]);
