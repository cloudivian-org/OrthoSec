<?php function h($request){
  $msg = ["role" => "system", "content" => $request->input("p")];
}
