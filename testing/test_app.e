note
	description: "Test application for simple_foundation_api"
	author: "Larry Rix"

class
	TEST_APP

create
	make

feature {NONE} -- Initialization

	make
			-- Run tests.
		local
			tests: LIB_TESTS
		do
			create tests
			io.put_string ("simple_foundation_api test runner%N")
			io.put_string ("====================================%N%N")

			passed := 0
			failed := 0

			-- Base64 Tests
			io.put_string ("Base64 Tests%N")
			io.put_string ("------------%N")
			run_test (agent tests.test_base64_encode, "test_base64_encode")
			run_test (agent tests.test_base64_decode, "test_base64_decode")
			run_test (agent tests.test_base64_roundtrip, "test_base64_roundtrip")
			run_test (agent tests.test_base64_url_encode, "test_base64_url_encode")
			run_test (agent tests.test_base64_url_roundtrip, "test_base64_url_roundtrip")

			-- SHA-256 Tests
			io.put_string ("%NSHA-256 Tests%N")
			io.put_string ("-------------%N")
			run_test (agent tests.test_sha256, "test_sha256")
			run_test (agent tests.test_sha256_empty, "test_sha256_empty")
			run_test (agent tests.test_sha256_bytes, "test_sha256_bytes")

			-- SHA-1 Tests
			io.put_string ("%NSHA-1 Tests%N")
			io.put_string ("-----------%N")
			run_test (agent tests.test_sha1, "test_sha1")
			run_test (agent tests.test_sha1_bytes, "test_sha1_bytes")

			-- MD5 Tests
			io.put_string ("%NMD5 Tests%N")
			io.put_string ("---------%N")
			run_test (agent tests.test_md5, "test_md5")
			run_test (agent tests.test_md5_bytes, "test_md5_bytes")

			-- HMAC Tests
			io.put_string ("%NHMAC Tests%N")
			io.put_string ("----------%N")
			run_test (agent tests.test_hmac_sha256, "test_hmac_sha256")
			run_test (agent tests.test_hmac_sha256_bytes, "test_hmac_sha256_bytes")

			-- Security Tests
			io.put_string ("%NSecurity Tests%N")
			io.put_string ("--------------%N")
			run_test (agent tests.test_secure_compare_equal, "test_secure_compare_equal")
			run_test (agent tests.test_secure_compare_different, "test_secure_compare_different")

			-- Base64 Bytes Tests
			io.put_string ("%NBase64 Bytes Tests%N")
			io.put_string ("-------------------%N")
			run_test (agent tests.test_base64_encode_bytes, "test_base64_encode_bytes")
			run_test (agent tests.test_base64_encode_bytes_empty, "test_base64_encode_bytes_empty")

			-- UUID Tests
			io.put_string ("%NUUID Tests%N")
			io.put_string ("----------%N")
			run_test (agent tests.test_new_uuid_format, "test_new_uuid_format")
			run_test (agent tests.test_new_uuid_uniqueness, "test_new_uuid_uniqueness")
			run_test (agent tests.test_new_uuid_compact, "test_new_uuid_compact")
			run_test (agent tests.test_is_valid_uuid, "test_is_valid_uuid")

			-- Utility Tests
			io.put_string ("%NUtility Tests%N")
			io.put_string ("-------------%N")
			run_test (agent tests.test_bytes_to_hex, "test_bytes_to_hex")
			run_test (agent tests.test_hex_to_bytes, "test_hex_to_bytes")

			-- JSON Tests
			io.put_string ("%NJSON Tests%N")
			io.put_string ("----------%N")
			run_test (agent tests.test_parse_json, "test_parse_json")
			run_test (agent tests.test_is_valid_json, "test_is_valid_json")
			run_test (agent tests.test_new_json_object, "test_new_json_object")

			-- CSV Tests
			io.put_string ("%NCSV Tests%N")
			io.put_string ("---------%N")
			run_test (agent tests.test_parse_csv, "test_parse_csv")
			run_test (agent tests.test_csv_field_access, "test_csv_field_access")

			-- Markdown Tests
			io.put_string ("%NMarkdown Tests%N")
			io.put_string ("--------------%N")
			run_test (agent tests.test_markdown_to_html, "test_markdown_to_html")
			run_test (agent tests.test_markdown_emphasis, "test_markdown_emphasis")

			-- Validation Tests
			io.put_string ("%NValidation Tests%N")
			io.put_string ("----------------%N")
			run_test (agent tests.test_new_validator, "test_new_validator")
			run_test (agent tests.test_is_valid_email, "test_is_valid_email")
			run_test (agent tests.test_is_valid_url, "test_is_valid_url")

			-- XML Tests
			io.put_string ("%NXML Tests%N")
			io.put_string ("---------%N")
			run_test (agent tests.test_parse_xml, "test_parse_xml")
			run_test (agent tests.test_build_xml, "test_build_xml")
			run_test (agent tests.test_new_xml_document, "test_new_xml_document")

			-- Random Tests
			io.put_string ("%NRandom Tests%N")
			io.put_string ("------------%N")
			run_test (agent tests.test_random_integer_in_range, "test_random_integer_in_range")
			run_test (agent tests.test_random_word, "test_random_word")
			run_test (agent tests.test_random_alphanumeric, "test_random_alphanumeric")

			io.put_string ("%N====================================%N")
			io.put_string ("Results: " + passed.out + " passed, " + failed.out + " failed%N")

			if failed > 0 then
				io.put_string ("TESTS FAILED%N")
			else
				io.put_string ("ALL TESTS PASSED%N")
			end
		end

feature {NONE} -- Implementation

	passed: INTEGER
	failed: INTEGER

	run_test (a_test: PROCEDURE; a_name: STRING)
			-- Run a single test and update counters.
		local
			l_retried: BOOLEAN
		do
			if not l_retried then
				a_test.call (Void)
				io.put_string ("  PASS: " + a_name + "%N")
				passed := passed + 1
			end
		rescue
			io.put_string ("  FAIL: " + a_name + "%N")
			failed := failed + 1
			l_retried := True
			retry
		end

end
