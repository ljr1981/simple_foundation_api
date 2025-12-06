note
	description: "Test set for FOUNDATION API"
	author: "Larry Rix"
	date: "$Date$"
	revision: "$Revision$"
	testing: "type/manual"

class
	FOUNDATION_TEST_SET

inherit
	TEST_SET_BASE

feature -- Base64 Tests

	test_base64_encode
			-- Test Base64 encoding.
		note
			testing: "covers/{FOUNDATION}.base64_encode"
		local
			f: FOUNDATION
		do
			create f.make
			assert_strings_equal ("hello", "SGVsbG8=", f.base64_encode ("Hello"))
			assert_strings_equal ("empty", "", f.base64_encode (""))
			assert_strings_equal ("world", "V29ybGQ=", f.base64_encode ("World"))
		end

	test_base64_decode
			-- Test Base64 decoding.
		note
			testing: "covers/{FOUNDATION}.base64_decode"
		local
			f: FOUNDATION
		do
			create f.make
			assert_strings_equal ("hello", "Hello", f.base64_decode ("SGVsbG8="))
			assert_strings_equal ("empty", "", f.base64_decode (""))
			assert_strings_equal ("world", "World", f.base64_decode ("V29ybGQ="))
		end

	test_base64_roundtrip
			-- Test Base64 encode/decode roundtrip.
		note
			testing: "covers/{FOUNDATION}.base64_encode"
			testing: "covers/{FOUNDATION}.base64_decode"
		local
			f: FOUNDATION
			original: STRING
		do
			create f.make
			original := "The quick brown fox jumps over the lazy dog."
			assert_strings_equal ("roundtrip", original, f.base64_decode (f.base64_encode (original)))
		end

	test_base64_url_encode
			-- Test URL-safe Base64 encoding.
		note
			testing: "covers/{FOUNDATION}.base64_url_encode"
		local
			f: FOUNDATION
			encoded: STRING
		do
			create f.make
			encoded := f.base64_url_encode ("Hello World!")
			assert_false ("no_plus", encoded.has ('+'))
			assert_false ("no_slash", encoded.has ('/'))
		end

	test_base64_url_roundtrip
			-- Test URL-safe Base64 roundtrip.
		note
			testing: "covers/{FOUNDATION}.base64_url_encode"
			testing: "covers/{FOUNDATION}.base64_url_decode"
		local
			f: FOUNDATION
			original: STRING
		do
			create f.make
			original := "Data with special chars: +/="
			assert_strings_equal ("url_roundtrip", original, f.base64_url_decode (f.base64_url_encode (original)))
		end

feature -- SHA-256 Tests

	test_sha256
			-- Test SHA-256 hashing.
		note
			testing: "covers/{FOUNDATION}.sha256"
		local
			f: FOUNDATION
		do
			create f.make
			-- Known test vector
			assert_strings_equal ("hello_world",
				"dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f",
				f.sha256 ("Hello, World!"))
		end

	test_sha256_empty
			-- Test SHA-256 of empty string.
		note
			testing: "covers/{FOUNDATION}.sha256"
		local
			f: FOUNDATION
		do
			create f.make
			assert_strings_equal ("empty",
				"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
				f.sha256 (""))
		end

	test_sha256_bytes
			-- Test SHA-256 as bytes.
		note
			testing: "covers/{FOUNDATION}.sha256_bytes"
		local
			f: FOUNDATION
		do
			create f.make
			assert_integers_equal ("byte_count", 32, f.sha256_bytes ("test").count)
		end

feature -- SHA-1 Tests

	test_sha1
			-- Test SHA-1 hashing.
		note
			testing: "covers/{FOUNDATION}.sha1"
		local
			f: FOUNDATION
		do
			create f.make
			-- Known test vector
			assert_strings_equal ("test",
				"a94a8fe5ccb19ba61c4c0873d391e987982fbbd3",
				f.sha1 ("test"))
		end

	test_sha1_bytes
			-- Test SHA-1 as bytes.
		note
			testing: "covers/{FOUNDATION}.sha1_bytes"
		local
			f: FOUNDATION
		do
			create f.make
			assert_integers_equal ("byte_count", 20, f.sha1_bytes ("test").count)
		end

feature -- MD5 Tests

	test_md5
			-- Test MD5 hashing.
		note
			testing: "covers/{FOUNDATION}.md5"
		local
			f: FOUNDATION
		do
			create f.make
			-- Known test vector
			assert_strings_equal ("hello",
				"5d41402abc4b2a76b9719d911017c592",
				f.md5 ("hello"))
		end

	test_md5_bytes
			-- Test MD5 as bytes.
		note
			testing: "covers/{FOUNDATION}.md5_bytes"
		local
			f: FOUNDATION
		do
			create f.make
			assert_integers_equal ("byte_count", 16, f.md5_bytes ("test").count)
		end

feature -- HMAC Tests

	test_hmac_sha256
			-- Test HMAC-SHA256.
		note
			testing: "covers/{FOUNDATION}.hmac_sha256"
		local
			f: FOUNDATION
		do
			create f.make
			assert_integers_equal ("length", 64, f.hmac_sha256 ("key", "message").count)
		end

	test_hmac_sha256_bytes
			-- Test HMAC-SHA256 as bytes.
		note
			testing: "covers/{FOUNDATION}.hmac_sha256_bytes"
		local
			f: FOUNDATION
		do
			create f.make
			assert_integers_equal ("byte_count", 32, f.hmac_sha256_bytes ("key", "message").count)
		end

feature -- UUID Tests

	test_new_uuid_format
			-- Test UUID format.
		note
			testing: "covers/{FOUNDATION}.new_uuid"
		local
			f: FOUNDATION
			uuid: STRING
		do
			create f.make
			uuid := f.new_uuid
			assert_integers_equal ("length", 36, uuid.count)
			assert_integers_equal ("hyphens", 4, uuid.occurrences ('-'))
			assert_true ("hyphen_pos_8", uuid.item (9) = '-')
			assert_true ("hyphen_pos_13", uuid.item (14) = '-')
			assert_true ("hyphen_pos_18", uuid.item (19) = '-')
			assert_true ("hyphen_pos_23", uuid.item (24) = '-')
		end

	test_new_uuid_uniqueness
			-- Test UUID uniqueness.
		note
			testing: "covers/{FOUNDATION}.new_uuid"
		local
			f: FOUNDATION
			uuid1, uuid2: STRING
		do
			create f.make
			uuid1 := f.new_uuid
			uuid2 := f.new_uuid
			assert_false ("unique", uuid1 ~ uuid2)
		end

	test_new_uuid_compact
			-- Test compact UUID format.
		note
			testing: "covers/{FOUNDATION}.new_uuid_compact"
		local
			f: FOUNDATION
			uuid: STRING
		do
			create f.make
			uuid := f.new_uuid_compact
			assert_integers_equal ("length", 32, uuid.count)
			assert_false ("no_hyphens", uuid.has ('-'))
		end

	test_is_valid_uuid
			-- Test UUID validation.
		note
			testing: "covers/{FOUNDATION}.is_valid_uuid"
		local
			f: FOUNDATION
		do
			create f.make
			assert_true ("valid", f.is_valid_uuid ("550e8400-e29b-41d4-a716-446655440000"))
			assert_true ("generated", f.is_valid_uuid (f.new_uuid))
		end

feature -- Utility Tests

	test_bytes_to_hex
			-- Test bytes to hex conversion.
		note
			testing: "covers/{FOUNDATION}.bytes_to_hex"
		local
			f: FOUNDATION
			bytes: ARRAY [NATURAL_8]
		do
			create f.make
			bytes := <<0xDE, 0xAD, 0xBE, 0xEF>>
			assert_strings_equal ("deadbeef", "deadbeef", f.bytes_to_hex (bytes))
		end

	test_hex_to_bytes
			-- Test hex to bytes conversion.
		note
			testing: "covers/{FOUNDATION}.hex_to_bytes"
		local
			f: FOUNDATION
			bytes: ARRAY [NATURAL_8]
		do
			create f.make
			bytes := f.hex_to_bytes ("deadbeef")
			assert_integers_equal ("count", 4, bytes.count)
			assert_integers_equal ("de", 0xDE, bytes [1].to_integer_32)
			assert_integers_equal ("ad", 0xAD, bytes [2].to_integer_32)
			assert_integers_equal ("be", 0xBE, bytes [3].to_integer_32)
			assert_integers_equal ("ef", 0xEF, bytes [4].to_integer_32)
		end

feature -- JSON Tests

	test_parse_json
			-- Test JSON parsing.
		note
			testing: "covers/{FOUNDATION}.parse_json"
		local
			f: FOUNDATION
		do
			create f.make
			assert_true ("valid_json", attached f.parse_json ("{%"name%": %"test%"}"))
			assert_false ("no_errors", f.json_has_errors)
		end

	test_is_valid_json
			-- Test JSON validation.
		note
			testing: "covers/{FOUNDATION}.is_valid_json"
		local
			f: FOUNDATION
		do
			create f.make
			assert_true ("valid", f.is_valid_json ("{%"key%": %"value%"}"))
			assert_false ("invalid", f.is_valid_json ("{invalid}"))
		end

	test_new_json_object
			-- Test JSON object creation.
		note
			testing: "covers/{FOUNDATION}.new_json_object"
		local
			f: FOUNDATION
			obj: SIMPLE_JSON_OBJECT
		do
			create f.make
			obj := f.new_json_object
			assert_true ("object_created", obj /= Void)
		end

feature -- CSV Tests

	test_parse_csv
			-- Test CSV parsing.
		note
			testing: "covers/{FOUNDATION}.parse_csv"
		local
			f: FOUNDATION
		do
			create f.make
			f.parse_csv ("a,b,c%N1,2,3%N4,5,6")
			assert_integers_equal ("rows", 3, f.csv_row_count)
			assert_integers_equal ("cols", 3, f.csv_column_count)
		end

	test_csv_field_access
			-- Test CSV field access.
		note
			testing: "covers/{FOUNDATION}.csv_field"
		local
			f: FOUNDATION
		do
			create f.make
			f.parse_csv ("a,b,c%N1,2,3")
			assert_strings_equal ("first", "a", f.csv_field (1, 1))
			assert_strings_equal ("last", "3", f.csv_field (2, 3))
		end

feature -- Markdown Tests

	test_markdown_to_html
			-- Test markdown conversion.
		note
			testing: "covers/{FOUNDATION}.markdown_to_html"
		local
			f: FOUNDATION
			html: STRING
		do
			create f.make
			html := f.markdown_to_html ("# Hello")
			assert_true ("has_h1", html.has_substring ("<h1"))
			assert_true ("has_hello", html.has_substring ("Hello"))
		end

	test_markdown_emphasis
			-- Test markdown emphasis.
		note
			testing: "covers/{FOUNDATION}.markdown_to_html"
		local
			f: FOUNDATION
			html: STRING
		do
			create f.make
			html := f.markdown_to_html ("**bold** and *italic*")
			assert_true ("has_bold", html.has_substring ("<strong>") or html.has_substring ("<b>"))
		end

feature -- Validation Tests

	test_new_validator
			-- Test validator creation.
		note
			testing: "covers/{FOUNDATION}.new_validator"
		local
			f: FOUNDATION
			v: SIMPLE_VALIDATOR
		do
			create f.make
			v := f.new_validator
			assert_true ("validator_created", v /= Void)
		end

	test_is_valid_email
			-- Test email validation.
		note
			testing: "covers/{FOUNDATION}.is_valid_email"
		local
			f: FOUNDATION
		do
			create f.make
			assert_true ("valid_email", f.is_valid_email ("test@example.com"))
			assert_false ("invalid_email", f.is_valid_email ("notanemail"))
		end

	test_is_valid_url
			-- Test URL validation.
		note
			testing: "covers/{FOUNDATION}.is_valid_url"
		local
			f: FOUNDATION
		do
			create f.make
			assert_true ("valid_url", f.is_valid_url ("https://example.com"))
			assert_false ("invalid_url", f.is_valid_url ("notaurl"))
		end

feature -- Random Tests

	test_random_integer_in_range
			-- Test random integer generation.
		note
			testing: "covers/{FOUNDATION}.random_integer_in_range"
		local
			f: FOUNDATION
			r: INTEGER
			i: INTEGER
		do
			create f.make
			from i := 1 until i > 10 loop
				r := f.random_integer_in_range (1, 100)
				assert_true ("in_range", r >= 1 and r <= 100)
				i := i + 1
			end
		end

	test_random_word
			-- Test random word generation.
		note
			testing: "covers/{FOUNDATION}.random_word"
		local
			f: FOUNDATION
			word: STRING
		do
			create f.make
			word := f.random_word
			assert_true ("not_empty", not word.is_empty)
		end

	test_random_alphanumeric
			-- Test random alphanumeric string.
		note
			testing: "covers/{FOUNDATION}.random_alphanumeric_string"
		local
			f: FOUNDATION
			s: STRING
		do
			create f.make
			s := f.random_alphanumeric_string (10)
			assert_integers_equal ("length", 10, s.count)
		end

end
