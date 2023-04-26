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
                let additional_information =
                    serde_json::to_value(self).unwrap_or(serde_json::Value::Null);
                let additional_information = if serde_json::Value::is_null(&additional_information)
                {
                    None
                } else {
                    Some(additional_information)
                };
                $crate::error::ErrorInformation::new(
                    self.code(),
                    self.as_ref(),
                    self.to_string(),
                    additional_information,
                )
            }

            /// Get the code, enum discriminant, for the error
            #[must_use]
            fn code(&self) -> u32 {
                unsafe { *(self as *const Self).cast::<u32>() }
            }
        }
    };
    ($error_name:ident, $result_name:ident) => {
        impl $error_name {
            /// Retrieve the information, this means converting the error to an `ErrorInformation`
            /// struct.
            #[must_use]
            pub fn information(&self) -> $crate::error::ErrorInformation {
                $crate::error::ErrorInformation::new(
                    self.code(),
                    self.as_ref(),
                    self.to_string(),
                    serde_json::to_value(self).ok(),
                )
            }

            /// Get the code, enum discriminant, for the error
            #[must_use]
            fn code(&self) -> u32 {
                unsafe { *(self as *const Self).cast::<u32>() }
            }
        }

        impl<T> $crate::return_object::ToReturnObject<T, $crate::error::ErrorInformation, String>
            for $result_name<T>
        where
            T: Serialize + Clone,
        {
            fn to_return_object(
                &self,
            ) -> $crate::return_object::ReturnObject<T, $crate::error::ErrorInformation, String>
            {
                match self {
                    Ok(t) => $crate::return_object::ReturnObject {
                        info: Some(t.clone()),
                        error: None,
                        warnings: None,
                    },
                    Err(e) => $crate::return_object::ReturnObject {
                        info: None,
                        error: Some(e.clone().information()),
                        warnings: None,
                    },
                }
            }
        }
    };
}
