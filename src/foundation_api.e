note
	description: "[
		Unified API facade for foundation-level operations.

		Provides single entry point to:
		- Base64 encoding/decoding (simple_base64)
		- Cryptographic hashing (simple_hash)
		- UUID generation (simple_uuid)
		- JSON parsing/building (simple_json)
		- CSV parsing/generation (simple_csv)
		- Markdown to HTML conversion (simple_markdown)
		- Data validation (simple_validation)
		- Process execution (simple_process)
		- Random data generation (simple_randomizer)
		- HTMX element generation (simple_htmx)
		- Structured logging (simple_logger)
		- XML parsing/building (simple_xml)
		- Date/time operations (simple_datetime)

		Usage:
			create foundation.make
			foundation.sha256 ("data")
			foundation.base64_encode ("Hello")
			foundation.new_uuid
			foundation.parse_json ("{%"key%": %"value%"}")
			foundation.parse_csv ("a,b,c%N1,2,3")
			foundation.markdown_to_html ("# Hello")
			foundation.new_validator.required.email.validate ("test@test.com")
			foundation.random_integer_in_range (1, 100)
			foundation.log.info ("Application started")
			foundation.new_logger.info_fields ("Event", << ["user_id", "123"] >>)
			foundation.parse_xml ("<root><item>value</item></root>").text_at ("root/item")
			foundation.new_date (2025, 12, 7).to_iso8601
			foundation.today.plus_days (7)
			foundation.new_duration (0, 2, 30, 0).to_human
	]"
	author: "Larry Rix"
	date: "$Date$"
	revision: "$Revision$"

class
	FOUNDATION_API

create
	make

feature {NONE} -- Initialization

	make
			-- Initialize foundation API.
		do
			create hasher.make
			create encoder.make
			create uuid_generator.make
			create json_parser
			create csv_parser.make
			create markdown_converter.make
			create process_helper
			create randomizer.make
			create logger_instance.make
			create xml_processor.make
		ensure
			hasher_ready: hasher /= Void
			encoder_ready: encoder /= Void
			uuid_ready: uuid_generator /= Void
			json_ready: json_parser /= Void
			csv_ready: csv_parser /= Void
			markdown_ready: markdown_converter /= Void
			process_ready: process_helper /= Void
			randomizer_ready: randomizer /= Void
			logger_ready: logger_instance /= Void
			xml_ready: xml_processor /= Void
		end

feature -- Base64 Encoding

	base64_encode (a_input: STRING): STRING
			-- Encode `a_input' to Base64.
		require
			input_not_void: a_input /= Void
		do
			Result := encoder.encode (a_input)
		end

	base64_decode (a_encoded: STRING): STRING
			-- Decode Base64 `a_encoded' to original string.
		require
			encoded_not_void: a_encoded /= Void
		do
			Result := encoder.decode (a_encoded)
		end

	base64_url_encode (a_input: STRING): STRING
			-- Encode `a_input' to URL-safe Base64.
		require
			input_not_void: a_input /= Void
		do
			Result := encoder.encode_url (a_input)
		ensure
			url_safe: not Result.has ('+') and not Result.has ('/')
		end

	base64_url_decode (a_encoded: STRING): STRING
			-- Decode URL-safe Base64 `a_encoded' to original string.
		require
			encoded_not_void: a_encoded /= Void
		do
			Result := encoder.decode_url (a_encoded)
		end

	base64_encode_bytes (a_bytes: ARRAY [NATURAL_8]): STRING
			-- Encode byte array `a_bytes' to Base64 string.
		require
			bytes_not_void: a_bytes /= Void
		do
			Result := encoder.encode_bytes (a_bytes)
		end

feature -- Hashing: SHA-256

	sha256 (a_input: STRING): STRING
			-- Compute SHA-256 hash of `a_input' as 64-char hex string.
		require
			input_not_void: a_input /= Void
		do
			Result := hasher.sha256 (a_input)
		ensure
			correct_length: Result.count = 64
			lowercase_hex: across Result as c all c.item.is_lower or c.item.is_digit end
		end

	sha256_bytes (a_input: STRING): ARRAY [NATURAL_8]
			-- Compute SHA-256 hash of `a_input' as 32 bytes.
		require
			input_not_void: a_input /= Void
		do
			Result := hasher.sha256_bytes (a_input)
		ensure
			correct_length: Result.count = 32
		end

feature -- Hashing: SHA-1

	sha1 (a_input: STRING): STRING
			-- Compute SHA-1 hash of `a_input' as 40-char hex string.
			-- Note: SHA-1 is deprecated for security; use SHA-256 for new applications.
		require
			input_not_void: a_input /= Void
		do
			Result := hasher.sha1 (a_input)
		ensure
			correct_length: Result.count = 40
			lowercase_hex: across Result as c all c.item.is_lower or c.item.is_digit end
		end

	sha1_bytes (a_input: STRING): ARRAY [NATURAL_8]
			-- Compute SHA-1 hash of `a_input' as 20 bytes.
		require
			input_not_void: a_input /= Void
		do
			Result := hasher.sha1_bytes (a_input)
		ensure
			correct_length: Result.count = 20
		end

feature -- Hashing: MD5

	md5 (a_input: STRING): STRING
			-- Compute MD5 hash of `a_input' as 32-char hex string.
			-- WARNING: MD5 is cryptographically broken. Use only for checksums.
		require
			input_not_void: a_input /= Void
		do
			Result := hasher.md5 (a_input)
		ensure
			correct_length: Result.count = 32
			lowercase_hex: across Result as c all c.item.is_lower or c.item.is_digit end
		end

	md5_bytes (a_input: STRING): ARRAY [NATURAL_8]
			-- Compute MD5 hash of `a_input' as 16 bytes.
		require
			input_not_void: a_input /= Void
		do
			Result := hasher.md5_bytes (a_input)
		ensure
			correct_length: Result.count = 16
		end

feature -- Hashing: HMAC

	hmac_sha256 (a_key, a_message: STRING): STRING
			-- Compute HMAC-SHA256 of `a_message' using `a_key'.
			-- Returns 64-char hex string.
		require
			key_not_void: a_key /= Void
			message_not_void: a_message /= Void
		do
			Result := hasher.hmac_sha256 (a_key, a_message)
		ensure
			correct_length: Result.count = 64
		end

	hmac_sha256_bytes (a_key, a_message: STRING): ARRAY [NATURAL_8]
			-- Compute HMAC-SHA256 of `a_message' using `a_key'.
			-- Returns 32 bytes.
		require
			key_not_void: a_key /= Void
			message_not_void: a_message /= Void
		do
			Result := hasher.hmac_sha256_bytes (a_key, a_message)
		ensure
			correct_length: Result.count = 32
		end

feature -- Hashing: Security

	secure_compare (a_str1, a_str2: STRING): BOOLEAN
			-- Compare two strings in constant time to prevent timing attacks.
			-- Use for comparing hashes, tokens, or secrets.
		require
			str1_not_void: a_str1 /= Void
			str2_not_void: a_str2 /= Void
		do
			Result := hasher.secure_compare (a_str1, a_str2)
		end

feature -- UUID Generation

	new_uuid: STRING
			-- Generate new random UUID v4 as string (36 chars with hyphens).
			-- Format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
		do
			Result := uuid_generator.new_v4_string
		ensure
			correct_length: Result.count = 36
			has_hyphens: Result.occurrences ('-') = 4
		end

	new_uuid_compact: STRING
			-- Generate new random UUID v4 without hyphens (32 chars).
		do
			Result := uuid_generator.new_v4_compact
		ensure
			correct_length: Result.count = 32
			no_hyphens: not Result.has ('-')
		end

	is_valid_uuid (a_string: STRING): BOOLEAN
			-- Is `a_string' a valid UUID format?
		require
			string_not_void: a_string /= Void
		do
			Result := uuid_generator.is_valid_uuid (a_string)
		end

feature -- JSON Parsing

	parse_json (a_json_text: STRING_32): detachable SIMPLE_JSON_VALUE
			-- Parse `a_json_text' and return JSON value.
			-- Returns Void on parse error; check `json_has_errors'.
		require
			text_not_empty: not a_json_text.is_empty
		do
			Result := json_parser.parse (a_json_text)
		end

	is_valid_json (a_json_text: STRING_32): BOOLEAN
			-- Is `a_json_text' valid JSON?
		require
			text_not_empty: not a_json_text.is_empty
		do
			Result := json_parser.is_valid_json (a_json_text)
		end

	json_has_errors: BOOLEAN
			-- Did last JSON parse have errors?
		do
			Result := json_parser.has_errors
		end

	json_errors: STRING_32
			-- Errors from last JSON parse.
		do
			Result := json_parser.errors_as_string
		end

	new_json_object: SIMPLE_JSON_OBJECT
			-- Create new JSON object builder.
		do
			Result := json_parser.new_object
		end

	new_json_array: SIMPLE_JSON_ARRAY
			-- Create new JSON array builder.
		do
			Result := json_parser.new_array
		end

feature -- CSV Parsing

	parse_csv (a_csv_text: STRING)
			-- Parse `a_csv_text' into CSV data.
			-- Access data via `csv_field', `csv_row_count', etc.
		require
			text_not_void: a_csv_text /= Void
		do
			csv_parser.parse (a_csv_text)
		end

	parse_csv_with_header (a_csv_text: STRING)
			-- Parse `a_csv_text' with first row as header.
		require
			text_not_void: a_csv_text /= Void
		do
			create csv_parser.make_with_header
			csv_parser.parse (a_csv_text)
		end

	csv_row_count: INTEGER
			-- Number of data rows in parsed CSV.
		do
			Result := csv_parser.row_count
		end

	csv_column_count: INTEGER
			-- Number of columns in parsed CSV.
		do
			Result := csv_parser.column_count
		end

	csv_field (a_row, a_column: INTEGER): STRING
			-- Get CSV field at `a_row', `a_column' (1-based).
		require
			valid_row: a_row >= 1 and a_row <= csv_row_count
			valid_column: a_column >= 1 and a_column <= csv_column_count
		do
			Result := csv_parser.field (a_row, a_column)
		end

	csv_to_string: STRING
			-- Generate CSV string from current data.
		do
			Result := csv_parser.to_csv
		end

feature -- Markdown Conversion

	markdown_to_html (a_markdown: STRING): STRING
			-- Convert `a_markdown' to HTML.
		require
			markdown_not_void: a_markdown /= Void
		do
			Result := markdown_converter.to_html (a_markdown)
		end

	markdown_to_html_fragment (a_markdown: STRING): STRING
			-- Convert `a_markdown' inline elements only (no block wrapping).
		require
			markdown_not_void: a_markdown /= Void
		do
			Result := markdown_converter.to_html_fragment (a_markdown)
		end

	markdown_table_of_contents: STRING
			-- Generate HTML table of contents from last markdown conversion.
		do
			Result := markdown_converter.table_of_contents
		end

feature -- Validation

	new_validator: SIMPLE_VALIDATOR
			-- Create new validator with fluent API.
			-- Usage: new_validator.required.email.validate ("test@test.com")
		do
			create Result.make
		end

	is_valid_email (a_value: STRING): BOOLEAN
			-- Is `a_value' a valid email address?
		require
			value_not_void: a_value /= Void
		local
			v: SIMPLE_VALIDATOR
		do
			create v.make
			Result := v.email.is_valid (a_value)
		end

	is_valid_url (a_value: STRING): BOOLEAN
			-- Is `a_value' a valid URL?
		require
			value_not_void: a_value /= Void
		local
			v: SIMPLE_VALIDATOR
		do
			create v.make
			Result := v.url.is_valid (a_value)
		end

feature -- Process Execution

	execute_command (a_command: STRING_32): STRING_32
			-- Execute shell `a_command' and return output.
		require
			command_not_empty: not a_command.is_empty
		do
			Result := process_helper.output_of_command (a_command, Void)
		end

	execute_command_in_directory (a_command, a_directory: STRING_32): STRING_32
			-- Execute shell `a_command' in `a_directory' and return output.
		require
			command_not_empty: not a_command.is_empty
			directory_not_empty: not a_directory.is_empty
		do
			Result := process_helper.output_of_command (a_command, a_directory)
		end

	has_file_in_path (a_name: STRING): BOOLEAN
			-- Does `a_name' exist in system PATH?
		require
			name_not_void: a_name /= Void
		do
			Result := process_helper.has_file_in_path (a_name)
		end

feature -- Random Generation

	random_integer: INTEGER
			-- A random integer.
		do
			Result := randomizer.random_integer
		end

	random_integer_in_range (a_lower, a_upper: INTEGER): INTEGER
			-- A random integer between `a_lower' and `a_upper'.
		require
			valid_range: a_lower <= a_upper
		do
			Result := randomizer.random_integer_in_range (a_lower |..| a_upper)
		ensure
			in_range: Result >= a_lower and Result <= a_upper
		end

	random_real: REAL_64
			-- A random real between 0 and 1.
		do
			Result := randomizer.random_real
		ensure
			in_range: Result >= 0 and Result <= 1
		end

	random_boolean: BOOLEAN
			-- A random boolean (approximately 50/50).
		do
			Result := randomizer.random_boolean
		end

	random_word: STRING
			-- A random pronounceable word.
		do
			Result := randomizer.random_word
		end

	random_sentence: STRING
			-- A random sentence.
		do
			Result := randomizer.random_sentence
		end

	random_alphanumeric_string (a_length: INTEGER): STRING
			-- A random alphanumeric string of `a_length'.
		require
			positive_length: a_length > 0
		do
			Result := randomizer.random_alphanumeric_string (a_length)
		ensure
			correct_length: Result.count = a_length
		end

	random_uuid_string: STRING
			-- A random UUID as string.
		do
			Result := randomizer.random_uuid_string
		end

feature -- Logging

	new_logger: SIMPLE_LOGGER
			-- Create new logger instance.
		do
			create Result.make
		end

	new_logger_with_level (a_level: INTEGER): SIMPLE_LOGGER
			-- Create new logger with specified level.
		require
			valid_level: a_level >= {SIMPLE_LOGGER}.Level_debug and a_level <= {SIMPLE_LOGGER}.Level_fatal
		do
			create Result.make_with_level (a_level)
		ensure
			level_set: Result.level = a_level
		end

	new_logger_to_file (a_path: STRING): SIMPLE_LOGGER
			-- Create new logger outputting to file.
		require
			path_not_empty: not a_path.is_empty
		do
			create Result.make_to_file (a_path)
		ensure
			file_output: Result.is_file_output
		end

	log: SIMPLE_LOGGER
			-- Shared logger instance for simple logging needs.
		do
			Result := logger_instance
		end

feature -- XML Processing

	parse_xml (a_xml: STRING): SIMPLE_XML_DOCUMENT
			-- Parse `a_xml' string and return document.
		require
			xml_not_void: a_xml /= Void
		do
			Result := xml_processor.parse (a_xml)
		end

	parse_xml_file (a_path: STRING): SIMPLE_XML_DOCUMENT
			-- Parse XML file at `a_path' and return document.
		require
			path_not_void: a_path /= Void
		do
			Result := xml_processor.parse_file (a_path)
		end

	build_xml (a_root_name: STRING): SIMPLE_XML_BUILDER
			-- Create XML builder with root element named `a_root_name'.
		require
			name_not_void: a_root_name /= Void
			name_not_empty: not a_root_name.is_empty
		do
			Result := xml_processor.build (a_root_name)
		end

	new_xml_document (a_root_name: STRING): SIMPLE_XML_DOCUMENT
			-- Create empty XML document with root named `a_root_name'.
		require
			name_not_void: a_root_name /= Void
			name_not_empty: not a_root_name.is_empty
		do
			Result := xml_processor.new_document (a_root_name)
		ensure
			is_valid: Result.is_valid
		end

feature -- DateTime Operations

	new_date (a_year, a_month, a_day: INTEGER): SIMPLE_DATE
			-- Create date from year, month, day.
		require
			valid_month: a_month >= 1 and a_month <= 12
			valid_day: a_day >= 1 and a_day <= 31
		do
			create Result.make (a_year, a_month, a_day)
		end

	new_time (a_hour, a_minute, a_second: INTEGER): SIMPLE_TIME
			-- Create time from hour, minute, second.
		require
			valid_hour: a_hour >= 0 and a_hour <= 23
			valid_minute: a_minute >= 0 and a_minute <= 59
			valid_second: a_second >= 0 and a_second <= 59
		do
			create Result.make (a_hour, a_minute, a_second)
		end

	new_datetime (a_year, a_month, a_day, a_hour, a_minute, a_second: INTEGER): SIMPLE_DATE_TIME
			-- Create datetime from components.
		do
			create Result.make (a_year, a_month, a_day, a_hour, a_minute, a_second)
		end

	new_duration (a_days, a_hours, a_minutes, a_seconds: INTEGER): SIMPLE_DURATION
			-- Create duration from days, hours, minutes, seconds.
		do
			create Result.make (a_days, a_hours, a_minutes, a_seconds)
		end

	new_duration_seconds (a_seconds: INTEGER_64): SIMPLE_DURATION
			-- Create duration from total seconds.
		do
			create Result.make_seconds (a_seconds)
		end

	new_date_range (a_start, a_end: SIMPLE_DATE): SIMPLE_DATE_RANGE
			-- Create date range from start to end.
		require
			start_before_end: a_start.is_before (a_end) or a_start.is_equal (a_end)
		do
			create Result.make (a_start, a_end)
		end

	new_age (a_years, a_months, a_days: INTEGER): SIMPLE_AGE
			-- Create age from years, months, days.
		do
			create Result.make (a_years, a_months, a_days)
		end

	age_from_dates (a_birth_date, a_reference_date: SIMPLE_DATE): SIMPLE_AGE
			-- Calculate age from birth date to reference date.
		require
			birth_before_reference: a_birth_date.is_before (a_reference_date) or a_birth_date.is_equal (a_reference_date)
		do
			create Result.make_from_dates (a_birth_date, a_reference_date)
		end

	today: SIMPLE_DATE
			-- Current date.
		do
			create Result.make_now
		end

	now: SIMPLE_TIME
			-- Current time.
		do
			create Result.make_now
		end

	current_datetime: SIMPLE_DATE_TIME
			-- Current date and time.
		do
			create Result.make_now
		end

feature -- Utilities

	bytes_to_hex (a_bytes: ARRAY [NATURAL_8]): STRING
			-- Convert byte array to lowercase hex string.
		require
			bytes_not_void: a_bytes /= Void
		do
			Result := hasher.bytes_to_hex (a_bytes)
		ensure
			correct_length: Result.count = a_bytes.count * 2
		end

	hex_to_bytes (a_hex: STRING): ARRAY [NATURAL_8]
			-- Convert hex string to byte array.
		require
			hex_not_void: a_hex /= Void
			even_length: a_hex.count \\ 2 = 0
		do
			Result := hasher.hex_to_bytes (a_hex)
		ensure
			correct_length: Result.count = a_hex.count // 2
		end

feature -- Direct Access

	json: SIMPLE_JSON
			-- Direct access to JSON parser for advanced operations.
		do
			Result := json_parser
		end

	csv: SIMPLE_CSV
			-- Direct access to CSV parser for advanced operations.
		do
			Result := csv_parser
		end

	markdown: SIMPLE_MARKDOWN
			-- Direct access to markdown converter for advanced operations.
		do
			Result := markdown_converter
		end

	process: SIMPLE_PROCESS_HELPER
			-- Direct access to process helper for advanced operations.
		do
			Result := process_helper
		end

	random: SIMPLE_RANDOMIZER
			-- Direct access to randomizer for advanced operations.
		do
			Result := randomizer
		end

	logger: SIMPLE_LOGGER
			-- Direct access to logger for advanced operations.
		do
			Result := logger_instance
		end

	xml: SIMPLE_XML
			-- Direct access to XML processor for advanced operations.
		do
			Result := xml_processor
		end

feature {NONE} -- Implementation

	hasher: SIMPLE_HASH
			-- Hash computation engine.

	encoder: SIMPLE_BASE64
			-- Base64 encoding engine.

	uuid_generator: SIMPLE_UUID
			-- UUID generation engine.

	json_parser: SIMPLE_JSON
			-- JSON parsing engine.

	csv_parser: SIMPLE_CSV
			-- CSV parsing engine.

	markdown_converter: SIMPLE_MARKDOWN
			-- Markdown conversion engine.

	process_helper: SIMPLE_PROCESS_HELPER
			-- Process execution helper.

	randomizer: SIMPLE_RANDOMIZER

	logger_instance: SIMPLE_LOGGER
			-- Shared logging engine.

	xml_processor: SIMPLE_XML
			-- XML parsing/building engine.

invariant
	hasher_exists: hasher /= Void
	encoder_exists: encoder /= Void
	uuid_exists: uuid_generator /= Void
	json_exists: json_parser /= Void
	csv_exists: csv_parser /= Void
	markdown_exists: markdown_converter /= Void
	process_exists: process_helper /= Void
	randomizer_exists: randomizer /= Void
	logger_exists: logger_instance /= Void
	xml_exists: xml_processor /= Void

end
