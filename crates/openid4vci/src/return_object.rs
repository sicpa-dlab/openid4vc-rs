use serde::Serialize;

/// Return object that will be used by every function that contains: `error`, `warning` and `info`.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct ReturnObject<T, E, W>
where
    T: Serialize,
    E: Serialize,
{
    /// Generic info object which contains the expected output of a success call
    #[serde(skip_serializing_if = "Option::is_none")]
    pub info: Option<T>,

    /// Error object which will be used when an error occurs
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<E>,

    /// List of warning objects
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warnings: Option<Vec<W>>,
}

impl<T, E, W> ReturnObject<T, E, W>
where
    T: Serialize + Clone,
    E: Serialize + Clone,
    W: Serialize + Clone,
{
    /// Add a warning
    #[must_use]
    pub fn add_warning(self, warning: W) -> Self {
        let mut warnings = self.warnings.unwrap_or_default();
        warnings.push(warning);

        Self {
            warnings: Some(warnings),
            ..self
        }
    }
}

/// Trait that implements a method to go to a generic return object
pub trait ToReturnObject<T, E, W>
where
    T: Serialize + Clone,
    E: Serialize + Clone,
    W: Serialize + Clone,
{
    /// Go to a generic return object to be used over any external layer
    fn to_return_object(&self) -> ReturnObject<T, E, W>;
}
