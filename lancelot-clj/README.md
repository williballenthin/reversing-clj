# lancelot-clj

Lancelot is a binary analysis framework.

## Installation

requirements:

  - capstone-clj (make available native library & `lein install`)
  - pe-clj (`lein install`)
   
## Building

### analyzer/server

    $ lein uberjar

### client

    $ lein cljsbuild once client-dev
    
for figwheel:

    $ lein figwheel

## Tests

    lein test

## Usage

FIXME: explanation

    $ java -jar lancelot-clj-0.1.0-standalone.jar [args]
 
## License

Copyright © 2017 William Ballenthin

Distributed under the Eclipse Public License either version 1.0 or (at
your option) any later version.
