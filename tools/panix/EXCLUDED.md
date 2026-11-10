# PANIX techniques not planted

| Technique | ATT&CK | Why |
|---|---|---|
| `--rootkit` | T1014 | clones Diamorphine from the internet |
| `--malicious-container` | T1610 | pulls a container image from the internet |
| `--pam --module` | T1556.003 | downloads Linux-PAM source (`--pam --pam-exec` is planted instead) |
| `--grub` | T1542 | changes the bootloader of the runner |
| `--initramfs` | T1542 | rebuilds the initramfs of the runner |
| `--password-change` | T1098 | changes a password only; no artifact beyond `/etc/shadow` |

These count as "not run", never as caught or missed.
