
This is a beta command line version of dirwatch based on code from James E Beveridge Copyright (c) 2010 

	
	-save <dir>         save changed files to dir. Can create, parent path must exist
	-watch <dir>        a directory to watch, always recursive, must exist, default c:\\
	-ex <path/pattern>  exclude a path/fragment or pattern (supports: *?[])
	-exf <path>         added excludes from <path>
	-si                 show ignored paths in output
	-log                manually specify log file (does not require -save)
	-h -? -help         this help screen. Note switches support / or - prefix.
	Auto saves log<date>.txt to save dir if specified.");
	Based on ReadDirectoryChangesW sample from James E Beveridge Copyright (c) 2010\n

