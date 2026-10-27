# license-runtime

`license-runtime` is the customer-side SDK. It generates an activation request,
stores and loads the customer X25519 key material through application-owned
storage, verifies vendor signatures, decrypts licenses, checks hardware and
validity policy, and exposes `License.Authorize`.

It does not contain vendor signing keys or license issuance APIs.
