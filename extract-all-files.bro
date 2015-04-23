module ExtractAllFiles;

export {
	## Path to save extracted files to
	const path = "./" &redef;

	## This table contains a conversion of common mime types to their
	## corresponding 'normal' file extensions.
	const common_types: table[string] of string = {
		["text/plain"] = "txt",
		["text/html"] = "html",
		["text/json"] = "json",
		["text/x-perl"] = "pl",
		["text/x-python"] = "py",
		["text/x-ruby"] = "rb",
		["text/x-lua"] = "lua",
		["text/x-php"] = "php",
		["image/gif"] = "gif",
		["image/x-ms-bmp"] = "bmp",
		["image/jpeg"] = "jpg",
		["image/png"] = "png",
		["application/x-dosexec"] = "exe",
		["application/msword"] = "doc",
		["application/vnd.openxmlformats-officedocument.wordprocessingml.document"] = "docx",
		["application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"] = "xlsx",
		["application/vnd.openxmlformats-officedocument.presentationml.presentation"] = "pptx",
		["application/xml"] = "xml",
		["application/java-archive"] = "jar",
		["application/x-java-applet"] = "jar",
		["application/x-shockwave-flash"] = "swf",
		["application/javascript"] = "js"
	};
}

event file_sniff(f: fa_file, meta: fa_metadata)
	{
	if ( !meta?$mime_type )
		return;

	local ftype = "";
	if ( meta$mime_type in common_types )
		ftype = common_types[meta$mime_type];
	else
		ftype = split_string(meta$mime_type, /\//)[1];

	local fname = fmt("%s%s-%s.%s", path, f$source, f$id, ftype);
	Files::add_analyzer(f, Files::ANALYZER_EXTRACT, [$extract_filename=fname]);
	}