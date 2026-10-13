# Where the module is built (`tacplus`)

[Documentation](../README.md) › [Linux hosts](README.md)

`host enroll` reads the host's `/etc/os-release` and architecture, builds `pam_tacplus` once for that OS release in a rootless `podman` container on the server (base image plus compiler pulled with network access; the compile itself runs with no network and no capabilities), caches it under `/var/lib/tacctl/linux/builds/`, and ships the binary. The host installs it without a compiler, headers or package repository, after checking its checksum and that it loads against the host's libraries.
```
tacctl config linux builds               # list cached builds with the base image digest each used
tacctl config linux builds clear         # drop them; the next enroll of each OS release rebuilds
tacctl host enroll web1 --build-on-host  # skip the container and compile on the host
```
The host compiles from the embedded source instead when there is no image for its OS, its architecture differs from the server's, `podman` is missing or the container build fails, or the shipped module does not load there. Base images come from Docker Hub (`ubuntu:<codename>`, `debian:<codename>`, and `almalinux:<major>` for every RHEL-family host, since they share an ABI per major release) and are trusted as pulled; the digest is recorded with each build. None of this applies to `radius` (`--build-on-host` warns that it is not applicable).

`tacctl install` and every `tacctl upgrade` install the packages this needs if they are missing (`podman`, `uidmap`, the autotools set for `config linux build`, `openssh-client`), along with tacctl's core requirements.
