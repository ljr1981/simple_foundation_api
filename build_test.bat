@echo off
set SIMPLE_XML=D:\prod\simple_xml
set SIMPLE_JSON=D:\prod\simple_json
set SIMPLE_BASE64=D:\prod\simple_base64
set SIMPLE_HASH=D:\prod\simple_hash
set SIMPLE_UUID=D:\prod\simple_uuid
set SIMPLE_CSV=D:\prod\simple_csv
set SIMPLE_MARKDOWN=D:\prod\simple_markdown
set SIMPLE_VALIDATION=D:\prod\simple_validation
set SIMPLE_PROCESS=D:\prod\simple_process
set SIMPLE_RANDOMIZER=D:\prod\simple_randomizer
set SIMPLE_HTMX=D:\prod\simple_htmx
set SIMPLE_LOGGER=D:\prod\simple_logger
set TESTING_EXT=D:\prod\testing_ext

cd /d D:\prod\simple_foundation_api
"C:\Program Files\Eiffel Software\EiffelStudio 25.02 Standard\studio\spec\win64\bin\ec.exe" -batch -config simple_foundation_api.ecf -target simple_foundation_api_tests -c_compile
