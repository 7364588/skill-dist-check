# Maintenance

Alpha software. Maintenance prioritizes reproducible archive, reference and
cross-platform compatibility defects, then dependency updates. A healthy audit
does not require a commit. Keep claims limited to tested static checks.

Before a release: build a wheel and source archive; install the actual source
archive in a clean environment; run the unit suite and installed CLI smoke;
rebuild the synthetic demo; inspect its interactions in a browser; verify the
current main commit's Linux, Windows and macOS CI. Update CHANGELOG and document
known limitations. Releases are GitHub assets until a registry is explicitly
announced in README.
