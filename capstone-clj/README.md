# capstone-clj

This is a Clojure wrapper library for the Capstone disassembly engine.

## Installation

Dependencies:

  - capstone native library
    - on linux: install capstone from apt or source
    - on windows: consider placing this in your $PATH

## Usage

This is a library for disassembling bytes into instructions.
It doesn't do much as a standalone executable.
See the unit tests for examples of how to invoke its routines.

## Examples

#### test
```
 $  lein test
```

#### build uberjar:
```
 $  lein uberjar
```

## License

Copyright © 2017 Willi Ballenthin

Distributed under the Eclipse Public License either version 1.0 or (at
your option) any later version.
