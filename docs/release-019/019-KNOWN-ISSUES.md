# Known issues — 0.1.0-19 BETA

- Five previously reported GUI tests remain failing. Their names and current logs were not supplied as part of the accepted HP report; no new full GUI suite was claimed or run for this documentation update.
- No full package upgrade was exercised in 0.1.0-19 because no upgrades were available. The successful full-upgrade evidence belongs to 0.1.0-18.
- Validation covers the reported HP CachyOS installation, not every Arch derivative or desktop.
- The backend requires libalpm 16.0.1 and the declared library SONAMEs. A future pacman/libalpm change may prevent operation until compatibility is reviewed.
- AUR and Flatpak are outside this release’s scope.
- The corrected artifact removes private compilation paths and includes current installation instructions. It has passed local regression and package checks, but has not been installed on HP; the accepted HP evidence belongs to the prior artifact.
- No detached package signature accompanies the candidate. SHA256 alone is not proof of publisher identity.

The corrected supervisor was exercised in an isolated test environment with stubbed administrative tools. No host service or package transaction was run. Previously accepted HP results were not repeated.
