pub fn str_to_6_u8_array(string: &str) -> [u8; 6] {
    let string_formatted = format!("{: >6}", string);
    let bytes = string_formatted.as_bytes();

    if bytes.len() != 6 {
        unreachable!("String must be exactly 6 bytes long");
    }

    let mut array = [0u8; 6];
    array.copy_from_slice(bytes);

    return array;
}
