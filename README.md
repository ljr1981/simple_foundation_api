# simple_foundation_api

![simple_* logo](docs/images/logo.png)

**Unified Foundation Library for Eiffel Projects**

[Documentation](https://ljr1981.github.io/simple_foundation_api/) | [GitHub](https://github.com/ljr1981/simple_foundation_api)

## Overview

`simple_foundation_api` is a unified facade that bundles essential foundation libraries for any Eiffel project. Instead of managing multiple library dependencies, use a single `FOUNDATION` class that provides access to encoding, hashing, UUID generation, JSON handling, CSV processing, markdown conversion, validation, and more.

## Features

- **Base64** - Standard and URL-safe Base64 encoding/decoding
- **Hashing** - SHA-256, SHA-1, MD5, and HMAC-SHA256 algorithms
- **UUID** - Generate v4 UUIDs in standard and compact formats
- **JSON** - Parse, validate, and build JSON with JSONPath queries
- **CSV** - Parse and generate CSV data with header support
- **Markdown** - Convert Markdown to HTML with table of contents
- **Validation** - Fluent data validation with chainable rules
- **Process** - Execute shell commands and capture output
- **Random** - Generate random integers, strings, words, and UUIDs

## Dependencies

This library bundles the following simple_* libraries:

| Library | Purpose | Environment Variable |
|---------|---------|---------------------|
| [simple_base64](https://github.com/ljr1981/simple_base64) | Base64 encoding/decoding | `$SIMPLE_BASE64` |
| [simple_hash](https://github.com/ljr1981/simple_hash) | Cryptographic hashing | `$SIMPLE_HASH` |
| [simple_uuid](https://github.com/ljr1981/simple_uuid) | UUID generation | `$SIMPLE_UUID` |
| [simple_json](https://github.com/ljr1981/simple_json) | JSON parsing/building | `$SIMPLE_JSON` |
| [simple_csv](https://github.com/ljr1981/simple_csv) | CSV processing | `$SIMPLE_CSV` |
| [simple_markdown](https://github.com/ljr1981/simple_markdown) | Markdown conversion | `$SIMPLE_MARKDOWN` |
| [simple_validation](https://github.com/ljr1981/simple_validation) | Data validation | `$SIMPLE_VALIDATION` |
| [simple_process](https://github.com/ljr1981/simple_process) | Process execution | `$SIMPLE_PROCESS` |
| [simple_randomizer](https://github.com/ljr1981/simple_randomizer) | Random generation | `$SIMPLE_RANDOMIZER` |

## Installation

1. Clone all required repositories
2. Set environment variables for each library
3. Add to your ECF:

```xml
<library name="simple_foundation_api"
        location="$SIMPLE_FOUNDATION_API\simple_foundation_api.ecf"/>
```

## Quick Start

```eiffel
local
    foundation: FOUNDATION
do
    create foundation.make

    -- Base64 encoding
    foundation.base64_encode ("Hello")  -- "SGVsbG8="

    -- SHA-256 hashing
    foundation.sha256 ("data")

    -- UUID generation
    foundation.new_uuid  -- "550e8400-e29b-41d4-a716-446655440000"

    -- JSON parsing
    if attached foundation.parse_json ("{%"name%": %"test%"}") as json then
        ...
    end

    -- Markdown conversion
    foundation.markdown_to_html ("# Hello World")

    -- Validation
    if foundation.is_valid_email ("test@example.com") then
        ...
    end

    -- Random generation
    foundation.random_integer_in_range (1, 100)
end
```

## API Summary

### Base64
- `base64_encode`, `base64_decode`
- `base64_url_encode`, `base64_url_decode`
- `base64_encode_bytes` - Encode byte arrays (for binary data)

### Hashing
- `sha256`, `sha256_bytes`
- `sha1`, `sha1_bytes`
- `md5`, `md5_bytes`
- `hmac_sha256`, `hmac_sha256_bytes`
- `secure_compare` - Constant-time string comparison (timing-attack safe)

### UUID
- `new_uuid`, `new_uuid_compact`
- `is_valid_uuid`

### JSON
- `parse_json`, `is_valid_json`
- `new_json_object`, `new_json_array`
- `json_has_errors`, `json_errors`

### CSV
- `parse_csv`, `parse_csv_with_header`
- `csv_field`, `csv_row_count`, `csv_column_count`
- `csv_to_string`

### Markdown
- `markdown_to_html`, `markdown_to_html_fragment`
- `markdown_table_of_contents`

### Validation
- `new_validator`
- `is_valid_email`, `is_valid_url`

### Random
- `random_integer`, `random_integer_in_range`
- `random_real`, `random_boolean`
- `random_word`, `random_sentence`
- `random_alphanumeric_string`

### Utilities
- `bytes_to_hex`, `hex_to_bytes`
- `execute_command`, `has_file_in_path`

### Direct Access
For advanced operations, access underlying libraries directly:
- `json` - SIMPLE_JSON
- `csv` - SIMPLE_CSV
- `markdown` - SIMPLE_MARKDOWN
- `process` - SIMPLE_PROCESS_HELPER
- `random` - SIMPLE_RANDOMIZER

## License

MIT License - see LICENSE file for details.

## Author

Larry Rix
