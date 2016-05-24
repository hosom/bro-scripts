module PDF;

export {
    ## Patterns that indicate dynamic content within PDF files.
    const dynamic_content_pattern = /\/JS|\/JavaScript|\/AA|\/OpenAction|\/RichMedia|\/Launch/ &redef;
    ## Event fired whenever the dynamic_content_pattern is matched.
    global dynamic_content_found: event(f: fa_file, data: string);

    ## Toggles logging of matches to pdf.log.
    const logging = T &redef;


    redef enum Log::ID += { LOG };

    type Info: record {
        ts:   time    &log;
        ## The ID of the file to link to files.log.
        fuid: string  &log;
        ## The data that matched the dynamic_content_pattern.
        data: string  &log;
    };

    global log_pdf: event(rec: Info);
}

event PDF::dynamic_content_found(f: fa_file, data: string)
    {
    if ( logging )
        {
        local rec: PDF::Info = [$ts=network_time(), $fuid=f$id, $data=data];
        Log::write(PDF::LOG, rec);
        }
    }

event pdf_data(f: fa_file, data: string)
    {
    if ( dynamic_content_pattern in data )
        {
        event PDF::dynamic_content_found(f, data);
        }
    }

event file_sniff(f: fa_file, meta: fa_metadata)
    {
    if ( meta?$mime_type &&  meta$mime_type == "application/pdf")
        Files::add_analyzer(f, Files::ANALYZER_DATA_EVENT, [$stream_event=pdf_data]);
    }

event bro_init() &priority=5
    {
    Log::create_stream(PDF::LOG, [$columns=Info, $ev=log_pdf]);
    }
