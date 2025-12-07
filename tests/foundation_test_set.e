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
			testing: "covers/{FOUNDATION_API}.base64_encode"
		local
			api: FOUNDATION_API
		do
			create api.make
			assert_strings_equal ("hello", "SGVsbG8=", api.base64_encode ("Hello"))
			assert_strings_equal ("empty", "", api.base64_encode (""))
			assert_strings_equal ("world", "V29ybGQ=", api.base64_encode ("World"))
		end

	test_base64_decode
			-- Test Base64 decoding.
		note
			testing: "covers/{FOUNDATION_API}.base64_decode"
		local
			api: FOUNDATION_API
		do
			create api.make
			assert_strings_equal ("hello", "Hello", api.base64_decode ("SGVsbG8="))
			assert_strings_equal ("empty", "", api.base64_decode (""))
			assert_strings_equal ("world", "World", api.base64_decode ("V29ybGQ="))
		end

	test_base64_roundtrip
			-- Test Base64 encode/decode roundtrip.
		note
			testing: "covers/{FOUNDATION_API}.base64_encode"
			testing: "covers/{FOUNDATION_API}.base64_decode"
		local
			api: FOUNDATION_API
			original: STRING
		do
			create api.make
			original := "The quick brown fox jumps over the lazy dog."
			assert_strings_equal ("roundtrip", original, api.base64_decode (api.base64_encode (original)))
		end

	test_base64_url_encode
			-- Test URL-safe Base64 encoding.
		note
			testing: "covers/{FOUNDATION_API}.base64_url_encode"
		local
			api: FOUNDATION_API
			encoded: STRING
		do
			create api.make
			encoded := api.base64_url_encode ("Hello World!")
			assert_false ("no_plus", encoded.has ('+'))
			assert_false ("no_slash", encoded.has ('/'))
		end

	test_base64_url_roundtrip
			-- Test URL-safe Base64 roundtrip.
		note
			testing: "covers/{FOUNDATION_API}.base64_url_encode"
			testing: "covers/{FOUNDATION_API}.base64_url_decode"
		local
			api: FOUNDATION_API
			original: STRING
		do
			create api.make
			original := "Data with special chars: +/="
			assert_strings_equal ("url_roundtrip", original, api.base64_url_decode (api.base64_url_encode (original)))
		end

feature -- SHA-256 Tests

	test_sha256
			-- Test SHA-256 hashing.
		note
			testing: "covers/{FOUNDATION_API}.sha256"
		local
			api: FOUNDATION_API
		do
			create api.make
			-- Known test vector
			assert_strings_equal ("hello_world",
				"dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f",
				api.sha256 ("Hello, World!"))
		end

	test_sha256_empty
			-- Test SHA-256 of empty string.
		note
			testing: "covers/{FOUNDATION_API}.sha256"
		local
			api: FOUNDATION_API
		do
			create api.make
			assert_strings_equal ("empty",
				"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
				api.sha256 (""))
		end

	test_sha256_bytes
			-- Test SHA-256 as bytes.
		note
			testing: "covers/{FOUNDATION_API}.sha256_bytes"
		local
			api: FOUNDATION_API
		do
			create api.make
			assert_integers_equal ("byte_count", 32, api.sha256_bytes ("test").count)
		end

feature -- SHA-1 Tests

	test_sha1
			-- Test SHA-1 hashing.
		note
			testing: "covers/{FOUNDATION_API}.sha1"
		local
			api: FOUNDATION_API
		do
			create api.make
			-- Known test vector
			assert_strings_equal ("test",
				"a94a8fe5ccb19ba61c4c0873d391e987982fbbd3",
				api.sha1 ("test"))
		end

	test_sha1_bytes
			-- Test SHA-1 as bytes.
		note
			testing: "covers/{FOUNDATION_API}.sha1_bytes"
		local
			api: FOUNDATION_API
		do
			create api.make
			assert_integers_equal ("byte_count", 20, api.sha1_bytes ("test").count)
		end

feature -- MD5 Tests

	test_md5
			-- Test MD5 hashing.
		note
			testing: "covers/{FOUNDATION_API}.md5"
		local
			api: FOUNDATION_API
		do
			create api.make
			-- Known test vector
			assert_strings_equal ("hello",
				"5d41402abc4b2a76b9719d911017c592",
				api.md5 ("hello"))
		end

	test_md5_bytes
			-- Test MD5 as bytes.
		note
			testing: "covers/{FOUNDATION_API}.md5_bytes"
		local
			api: FOUNDATION_API
		do
			create api.make
			assert_integers_equal ("byte_count", 16, api.md5_bytes ("test").count)
		end

feature -- HMAC Tests

	test_hmac_sha256
			-- Test HMAC-SHA256.
		note
			testing: "covers/{FOUNDATION_API}.hmac_sha256"
		local
			api: FOUNDATION_API
		do
			create api.make
			assert_integers_equal ("length", 64, api.hmac_sha256 ("key", "message").count)
		end

	test_hmac_sha256_bytes
			-- Test HMAC-SHA256 as bytes.
		note
			testing: "covers/{FOUNDATION_API}.hmac_sha256_bytes"
		local
			api: FOUNDATION_API
		do
			create api.make
			assert_integers_equal ("byte_count", 32, api.hmac_sha256_bytes ("key", "message").count)
		end

feature -- Security Tests

	test_secure_compare_equal
			-- Test secure compare with equal strings.
		note
			testing: "covers/{FOUNDATION_API}.secure_compare"
		local
			api: FOUNDATION_API
		do
			create api.make
			assert_true ("equal_strings", api.secure_compare ("secret123", "secret123"))
			assert_true ("equal_empty", api.secure_compare ("", ""))
		end

	test_secure_compare_different
			-- Test secure compare with different strings.
		note
			testing: "covers/{FOUNDATION_API}.secure_compare"
		local
			api: FOUNDATION_API
		do
			create api.make
			assert_false ("different_strings", api.secure_compare ("secret123", "secret456"))
			assert_false ("different_length", api.secure_compare ("short", "longer"))
		end

feature -- Base64 Bytes Tests

	test_base64_encode_bytes
			-- Test Base64 encoding of byte array.
		note
			testing: "covers/{FOUNDATION_API}.base64_encode_bytes"
		local
			api: FOUNDATION_API
			bytes: ARRAY [NATURAL_8]
			encoded: STRING
		do
			create api.make
			bytes := <<72, 101, 108, 108, 111>>  -- "Hello" as bytes
			encoded := api.base64_encode_bytes (bytes)
			assert_strings_equal ("hello_bytes", "SGVsbG8=", encoded)
		end

	test_base64_encode_bytes_empty
			-- Test Base64 encoding of empty byte array.
		note
			testing: "covers/{FOUNDATION_API}.base64_encode_bytes"
		local
			api: FOUNDATION_API
			bytes: ARRAY [NATURAL_8]
		do
			create api.make
			create bytes.make_empty
			assert_strings_equal ("empty_bytes", "", api.base64_encode_bytes (bytes))
		end

feature -- UUID Tests

	test_new_uuid_format
			-- Test UUID format.
		note
			testing: "covers/{FOUNDATION_API}.new_uuid"
		local
			api: FOUNDATION_API
			uuid: STRING
		do
			create api.make
			uuid := api.new_uuid
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
			testing: "covers/{FOUNDATION_API}.new_uuid"
		local
			api: FOUNDATION_API
			uuid1, uuid2: STRING
		do
			create api.make
			uuid1 := api.new_uuid
			uuid2 := api.new_uuid
			assert_false ("unique", uuid1 ~ uuid2)
		end

	test_new_uuid_compact
			-- Test compact UUID format.
		note
			testing: "covers/{FOUNDATION_API}.new_uuid_compact"
		local
			api: FOUNDATION_API
			uuid: STRING
		do
			create api.make
			uuid := api.new_uuid_compact
			assert_integers_equal ("length", 32, uuid.count)
			assert_false ("no_hyphens", uuid.has ('-'))
		end

	test_is_valid_uuid
			-- Test UUID validation.
		note
			testing: "covers/{FOUNDATION_API}.is_valid_uuid"
		local
			api: FOUNDATION_API
		do
			create api.make
			assert_true ("valid", api.is_valid_uuid ("550e8400-e29b-41d4-a716-446655440000"))
			assert_true ("generated", api.is_valid_uuid (api.new_uuid))
		end

feature -- Utility Tests

	test_bytes_to_hex
			-- Test bytes to hex conversion.
		note
			testing: "covers/{FOUNDATION_API}.bytes_to_hex"
		local
			api: FOUNDATION_API
			bytes: ARRAY [NATURAL_8]
		do
			create api.make
			bytes := <<0xDE, 0xAD, 0xBE, 0xEF>>
			assert_strings_equal ("deadbeef", "deadbeef", api.bytes_to_hex (bytes))
		end

	test_hex_to_bytes
			-- Test hex to bytes conversion.
		note
			testing: "covers/{FOUNDATION_API}.hex_to_bytes"
		local
			api: FOUNDATION_API
			bytes: ARRAY [NATURAL_8]
		do
			create api.make
			bytes := api.hex_to_bytes ("deadbeef")
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
			testing: "covers/{FOUNDATION_API}.parse_json"
		local
			api: FOUNDATION_API
		do
			create api.make
			assert_true ("valid_json", attached api.parse_json ("{%"name%": %"test%"}"))
			assert_false ("no_errors", api.json_has_errors)
		end

	test_is_valid_json
			-- Test JSON validation.
		note
			testing: "covers/{FOUNDATION_API}.is_valid_json"
		local
			api: FOUNDATION_API
		do
			create api.make
			assert_true ("valid", api.is_valid_json ("{%"key%": %"value%"}"))
			assert_false ("invalid", api.is_valid_json ("{invalid}"))
		end

	test_new_json_object
			-- Test JSON object creation.
		note
			testing: "covers/{FOUNDATION_API}.new_json_object"
		local
			api: FOUNDATION_API
			obj: SIMPLE_JSON_OBJECT
		do
			create api.make
			obj := api.new_json_object
			assert_true ("object_created", obj /= Void)
		end

feature -- CSV Tests

	test_parse_csv
			-- Test CSV parsing.
		note
			testing: "covers/{FOUNDATION_API}.parse_csv"
		local
			api: FOUNDATION_API
		do
			create api.make
			api.parse_csv ("a,b,c%N1,2,3%N4,5,6")
			assert_integers_equal ("rows", 3, api.csv_row_count)
			assert_integers_equal ("cols", 3, api.csv_column_count)
		end

	test_csv_field_access
			-- Test CSV field access.
		note
			testing: "covers/{FOUNDATION_API}.csv_field"
		local
			api: FOUNDATION_API
		do
			create api.make
			api.parse_csv ("a,b,c%N1,2,3")
			assert_strings_equal ("first", "a", api.csv_field (1, 1))
			assert_strings_equal ("last", "3", api.csv_field (2, 3))
		end

feature -- Markdown Tests

	test_markdown_to_html
			-- Test markdown conversion.
		note
			testing: "covers/{FOUNDATION_API}.markdown_to_html"
		local
			api: FOUNDATION_API
			html: STRING
		do
			create api.make
			html := api.markdown_to_html ("# Hello")
			assert_true ("has_h1", html.has_substring ("<h1"))
			assert_true ("has_hello", html.has_substring ("Hello"))
		end

	test_markdown_emphasis
			-- Test markdown emphasis.
		note
			testing: "covers/{FOUNDATION_API}.markdown_to_html"
		local
			api: FOUNDATION_API
			html: STRING
		do
			create api.make
			html := api.markdown_to_html ("**bold** and *italic*")
			assert_true ("has_bold", html.has_substring ("<strong>") or html.has_substring ("<b>"))
		end

feature -- Validation Tests

	test_new_validator
			-- Test validator creation.
		note
			testing: "covers/{FOUNDATION_API}.new_validator"
		local
			api: FOUNDATION_API
			v: SIMPLE_VALIDATOR
		do
			create api.make
			v := api.new_validator
			assert_true ("validator_created", v /= Void)
		end

	test_is_valid_email
			-- Test email validation.
		note
			testing: "covers/{FOUNDATION_API}.is_valid_email"
		local
			api: FOUNDATION_API
		do
			create api.make
			assert_true ("valid_email", api.is_valid_email ("test@example.com"))
			assert_false ("invalid_email", api.is_valid_email ("notanemail"))
		end

	test_is_valid_url
			-- Test URL validation.
		note
			testing: "covers/{FOUNDATION_API}.is_valid_url"
		local
			api: FOUNDATION_API
		do
			create api.make
			assert_true ("valid_url", api.is_valid_url ("https://example.com"))
			assert_false ("invalid_url", api.is_valid_url ("notaurl"))
		end

feature -- XML Tests

	test_parse_xml
			-- Test XML parsing.
		note
			testing: "covers/{FOUNDATION_API}.parse_xml"
		local
			api: FOUNDATION_API
			doc: SIMPLE_XML_DOCUMENT
		do
			create api.make
			doc := api.parse_xml ("<root><item>value</item></root>")
			assert_true ("doc_valid", doc.is_valid)
			if attached doc.root as l_root then
				assert_strings_equal ("root_name", "root", l_root.name)
			else
				assert_true ("has_root", False)
			end
		end

	test_build_xml
			-- Test XML building.
		note
			testing: "covers/{FOUNDATION_API}.build_xml"
		local
			api: FOUNDATION_API
			builder: SIMPLE_XML_BUILDER
			xml_string: STRING
		do
			create api.make
			builder := api.build_xml ("root")
			builder := builder.element ("item").text ("value").done
			xml_string := builder.to_string
			assert_true ("has_root", xml_string.has_substring ("<root"))
			assert_true ("has_item", xml_string.has_substring ("<item>"))
		end

	test_new_xml_document
			-- Test XML document creation.
		note
			testing: "covers/{FOUNDATION_API}.new_xml_document"
		local
			api: FOUNDATION_API
			doc: SIMPLE_XML_DOCUMENT
		do
			create api.make
			doc := api.new_xml_document ("config")
			assert_true ("doc_valid", doc.is_valid)
			if attached doc.root as l_root then
				assert_strings_equal ("root_name", "config", l_root.name)
			else
				assert_true ("has_root", False)
			end
		end

feature -- Random Tests

	test_random_integer_in_range
			-- Test random integer generation.
		note
			testing: "covers/{FOUNDATION_API}.random_integer_in_range"
		local
			api: FOUNDATION_API
			r: INTEGER
			i: INTEGER
		do
			create api.make
			from i := 1 until i > 10 loop
				r := api.random_integer_in_range (1, 100)
				assert_true ("in_range", r >= 1 and r <= 100)
				i := i + 1
			end
		end

	test_random_word
			-- Test random word generation.
		note
			testing: "covers/{FOUNDATION_API}.random_word"
		local
			api: FOUNDATION_API
			word: STRING
		do
			create api.make
			word := api.random_word
			assert_true ("not_empty", not word.is_empty)
		end

	test_random_alphanumeric
			-- Test random alphanumeric string.
		note
			testing: "covers/{FOUNDATION_API}.random_alphanumeric_string"
		local
			api: FOUNDATION_API
			s: STRING
		do
			create api.make
			s := api.random_alphanumeric_string (10)
			assert_integers_equal ("length", 10, s.count)
		end

end
