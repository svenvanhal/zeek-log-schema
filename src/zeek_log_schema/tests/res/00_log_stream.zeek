event bro_init() &priority=5
	{
	Log::create_stream(Test::LOG, [$columns=Test::Info, $ev=log_test, $path="test"]);
	}

event bro_init() &priority=5
	{
	Log::create_stream(LOG, [$columns=Info, $ev=log_pe, $path="pe"]);
	}
