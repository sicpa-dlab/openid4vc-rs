/// Implements the code required for conversion of the rust idiomatic error to an FFI-safe error
/// message with enough information
#[macro_export]
macro_rules! error_impl {
    ($error_name:ident) => {
        impl $error_name {
            /// Retrieve the information, this means converting the error to an `ErrorInformation`
            /// struct.
            #[must_use]
            pub fn information(&self) -> $crate::error::ErrorInformation {
                $crate::error::ErrorInformation::new(
                    self.code(),
                    self.as_ref(),
                    self.to_string(),
                    serde_json::to_value(self).unwrap_or(serde_json::Value::Null),
                )
            }

            /// Get the code, enum discriminant, for the error
            #[must_use]
            fn code(&self) -> u32 {
                unsafe { *(self as *const Self).cast::<u32>() }
            }
        }
    };
}
