# Design of construct-clj


The inspiration of construct-clj includes:
  - Python's construct 3: http://tomerfiliba.com/blog/Survey-of-Construct3/
  - vstruct: http://www.williballenthin.com/blog/2015/09/08/parsing-binary-data-with-vstruct/

features:
  - lazy unpacking - only unpack what is required
  - cache parsed results
  - maybe clojure map syntax is possible?
  - avoid copying data from mmap
  - be able to query the underlying offsets for some field
  - union types would be cool!
  - built-in repr?

wants:
  - want: stream unpacking - unpack from a sequence of bytes
  - want: packing

questions:
  - what about decompressed buffers?

## protocols


### unpacker

a "spec" is a specification for some data that can be deserialized/parsed/unpacked.
it sometimes called a:
  - "frame" ([ref](https://github.com/ztellman/gloss/wiki/Introduction)),
  - "codec" ([ref](https://github.com/smee/binary)), or
  - "spec" ([ref](https://github.com/clojurewerkz/buffy)).

`parse` returns a parsing context for the given structure and byte buffer.
fields are parsed lazily.

`unpack` returns a clojure data structure for the given struct and byte buffer.
all parsing is done in one go.

a key part of lazy structure parsing is knowing where to find fields.
fields are laid out consecutively, so we need to know the length of each field
 to find fields.
here's how we minimize the amount of work to do:

  1. if there is a static size provided, use that.
     ```lisp
     (make-spec ... :static-size 4)
     ```
  2. if it is a class instance, and already fully parsed, use length.
     ```lisp
     (when (fully-parsed? s)
       (parsed-length s))
     ```
  3. if there is a class method for computing length, use that.
     ```lisp
     (make-spec ... :dynamic-size (fn [byte-buffer]
                                    (with-buffer byte-buffer
                                      (unpack-uint8))))
     ```
  4. else, create instance of class, fully parse it, use length.
     ```lisp
     (let (parsed (parse some-spec byte-buffer)))
       (parsed-length parsed)
     ```

```lisp
(def ip-addr (make-spec
               (array uint8 4)
               :repr #(clojure.string/join "." %)))

(unpack ip-addr "\xC0\xA8\x02\x01")
>>> [192, 168, 0, 1]

(repr (parse ip-addr "\xC0\xA8\x02\x01"))
>>> "192.168.0.1"

(def dos-header (make-spec
                 (struct
                   ;; this needs to take ordered kwargs and maintain them

                   ;; always is a validator
                   :sig (always (ascii-char 2) "MZ")
                   :lastsize uint16
                   :nblocks uint16
                   :nreloc uint16
                   :hdrsize uint16
                   :minalloc uint16
                   :ss (bytes 2)
                   :sp (bytes 2)
                   :checksum uint16
                   :ip (bytes 2)
                   :cs (bytes 2)
                   :relocpos uint16
                   :noverlay uint16
                   :reserved1 (array uint16 4)
                   :oem_id uint16
                   :oem_info uint16
                   :e_lfanew uint32)))
```
