# Public Suffix List snapshot

The bundled list comes from the
[official Public Suffix List](https://publicsuffix.org/list/) publisher
repository, commit `3929462652695bad04f0a27afb600974014a3c8b`, dated 2026-10-07.
Both ICANN and private suffix rules are included.

`public_suffix_list.dat` has SHA-256
`2919eb9803c91a3f73a507cc6fedc934de005543c22c4016f72e3343de5dd6e7`. The upstream
Mozilla Public License 2.0 is retained in `LICENSE`.
`../src/public-suffix-data.ts` embeds this exact text for the server bundle.

The app does not refresh the list at runtime. To update it, select an upstream
commit, replace the data and license together, regenerate the embedded string,
update this record, and run the domain parser tests. The parser handles exact,
wildcard, exception and internationalized names. An IP address is not a domain.
