# structor (v0.1)
Author: **toolchainz**

This plugin will attempt to automatically make structures.

## Description:

To make a structure, go to MLIL view, right click on a line, and click `Create Auto Structure`. Structor will prompt you to choose a variable from the line you selected, and then it will do its level best to make a function.

### Limitations

I'm only looking for the following pattern:

 * MLIL_ADD
   * MLIL_VAR_SSA
   * MLIL_CONST

Any structure access that matches this pattern should get caught.

This won't catch complicated stuff like:

* Pointer math
* Nested Structures
* Arrays

In the event it breaks on you, I probably just messed up. Issues/PRs welcome.

## Minimum Version

This plugin requires the following minimum version of Binary Ninja:

 * release - N/A
 * dev - 1.1.dev-1456

## Required Dependencies

None other than binja!

## License

This plugin is released under a [MIT](LICENSE) license.


