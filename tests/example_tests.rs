// Example: Using comparison assertions instead of exact values in tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_example() {
        let result = some_function();
        assert!(result.is_close_to(expected_value)); // Using comparison instead of exact
    }
}