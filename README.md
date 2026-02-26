# Multi-Firmware PS4 WebKit & Kernel Exploit Chain

An exploit chain for PS4 firmware 5.05, 6.72 and [7.00 to 9.60]
> ⚠️ This repository is for research and educational purposes only.

> ⚠️ **Beta / Work in Progress**
>
> This project is still under active development and beta testing. Firmware-specific issues may occur.

## Overview
This repository is a research-focused fork and consolidation of multiple public exploit projects. Its primary goal is to improve the reliability, stability and execution determinism of existing WebKit and kernel exploit chains across supported firmware versions.

The project focuses on:

- **Increasing stability and success rate** through refined timing control, improved error handling and sequential execution flow.

- **Reducing platform compatibility constraints** by converting the original `.mjs` modular structure into a plain `.js` implementation.

Additionally, the project utilizes **firmware-aware dynamic script loading** to ensure that only the required exploit stages are loaded at runtime. This approach improves timing consistency, reduces ES5/ES6 compatibility issues across firmware versions and enhances overall execution predictability.

<p align="center">
  <img src="ps4jb.png" alt="PSFree" width="468" height="624"/>
</p>

---

## **Legal Notice & Disclaimer:**

- This repository does not host, or distribute any exploit hosting services
- Jailbreaking, circumventing security, or deploying exploits may be illegal in some jurisdictions.  
- It is your responsibility to ensure compliance with local laws.  
- The developer assumes **no responsibility** for any potential damage, data loss, or issues that may occur on your PlayStation console as a result of using this repository.  
- Use it at your own risk and only on your own devices.

## Major Changes

- **Removed all** `.mjs` **files** — converted the codebase to plain `.js` to improve cross-platform compatibility and simplify loading requirements.
- **Refactored for more sequential** `C-like` **execution** — code reorganized to follow a linear flow for easier reasoning, deterministic timing, and simpler debugging.
- **Rewrote** `Number.isInteger()` **implementation** — The original exploit implementation relied on `Number.isInteger()`, which I guess not fully supported in the PS4’s WebKit-based JavaScript environment (situated between `ES5` and `Partial ES6` compliance). To ensure consistent behavior across these runtimes, the function was rewritten using fundamental type and arithmetic checks. This guarantees proper integer validation even in restricted or legacy WebKit engines.
- **Rewrote** `hexdump()` **implementation** — adjusted string/byte handling to comply with the PS4’s WebKit-based JavaScript environment.
- **Improved GC handling with short delay** — added a small wait (≈50 ms) to certain `gc()` paths to stabilize memory reclamation timing.
- **Added initialization checks for variable operations** — guard checks ensure variables are initialized before use to prevent undefined-state failures.
- **Reordered and cleaned global variable initializations** — made global setup deterministic and reduced race conditions at startup.
- **Added parentheses to some of the logic expressions** — explicit grouping was added to prevent operator-precedence ambiguities and reduce logic errors.
- **Removed debugging logs** — cleaned up and commented out debugging logs to reduce side effects and improve runtime consistency.
- **Embedded** `.elf/.bin` **assets as hex arrays inside JS** — binary resources converted to in-file hex arrays to avoid read/load errors in constrained environments.
- **Replaced** `XMLHttpRequest()` **with** `fetch()`**/file reads** — modernized file-loading code for better compatibility and promise-based control flow.
- **Removed all** `localStorage` **and** `sessionStorage` **usage** — Storage APIs were removed to avoid cross-origin restrictions, quota issues, and inconsistent behavior in sandboxed WebKit environments.
- **Implemented console firmware detection** — Added logic to automatically detect the running PS4 firmware version, enabling conditional execution paths and improving overall compatibility across different system revisions.
- **Merged various tweaks from Al-Azif’s source** — Incorporated selected stability, compatibility, and workflow improvements from Al-Azif’s implementation to enhance overall reliability and reduce edge-case failures.
- **Added multi-firmware support (7.00 -> 9.60) from Al-Azif’s source** — Full support implemented for firmware versions 7.00 through 9.60, including: Kernel patch + AIO fix .bin files

## Notes:
> Firmware 7.00–9.60 includes integrated PSFree kernel patch shellcodes and AIO patch sets.

> All payload binaries (`*.bin`, `*.elf`) were intentionally excluded. This repository does not include `payload.bin` file. Place your preferred Homebrew Enabler (HEN) payload in the root directory.

> Step-by-step jailbreak instructions were omitted for legal and ethical compliance.

> No modifications that alter the exploit logic in ways affecting device security outside test context.

## Local Self-Hosting

You can self-host the project using Python's built-in HTTP server.

Windows: `py -m http.server 8080`

Linux/macOS: `python3 -m http.server 8080`

On your PS4 browser, navigate to: `http://YOUR_PC_IP:8080/index.html`

## Contributing

Contributions are welcome! Feel free to open pull requests for bug fixes, UI improvements, or additional features.

## License
This project continues under the same open-source license as the original PSFree repository (**AGPL-3.0**).  
Please review the [LICENSE](LICENSE) before redistributing or modifying the code.

## Acknowledgments

Special thanks to:

* **qwertyoruiopz**, Webkit Entrypoint for 5.05
* **Specter**, Kernel Exploit for 5.05
* **Fire30**, Bad Hoist Entrypoint for 6.7x
* **Sleirsgoevy**, Kernel Exploit for 6.7x
* **ABC**, PSFree and Lapse core software
* [KAR0218](https://github.com/KAR0218) for 5.05Gold project
* [ps3120](https://github.com/ps3120) for 6.72 project
* [kmeps4](https://github.com/kmeps4) and [Al-Azif](https://github.com/Al-Azif) for PSFree projects
* **ps4dev team** for their continuous support and invaluable contributions to the PS4 research ecosystem. This project stands on the hard work of all the developers behind it — none of this would be possible without their efforts.
* everyone who tested the updates across various firmware versions and supported the project with their valuable feedback.

Extra thanks to **Sajjad** for thoroughly testing supported firmware versions and dedicating an incredible amount of time and effort to ensure stability and reliability.

## Contact

For questions or issues, please open a GitHub issue on this repository.
