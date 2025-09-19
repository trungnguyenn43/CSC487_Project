# SDES Error Codes

This document describes the error codes that may be encountered when using the Simplified Data Encryption Standard (SDES) implementation.

## Error Codes

- `CODE_1`: Empty input provided to the SDES function.
- `CODE_2`: Invalid plaintext or hex digit encountered.
- `CODE_3`: Memory allocation failed during hex-to-binary conversion.

## Description of Error Codes

- **`CODE_1`**: This error occurs when the input provided to the SDES function is empty. The SDES algorithm requires a valid input to perform encryption or decryption. An empty input means there is no data to process, which leads to this error.

- **`CODE_2`**: This error is triggered when the plaintext input is invalid or an invalid hexadecimal digit is encountered. The SDES algorithm expects the input to be in a specific format, and any deviation from this format, such as an invalid hex digit, will cause this error.

- **`CODE_3`**: This error indicates that there was a memory allocation failure during the hex-to-binary conversion process. The SDES implementation requires dynamic memory allocation for certain operations, and if the system runs out of memory or the allocation fails for any reason, this error will be raised.
