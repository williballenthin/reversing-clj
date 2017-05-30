(ns unicorn-clj.core
  (:import [clojure.lang ILookup]
           [clojure.string]
           [unicorn.Unicorn])
  (:gen-class))


(defn mem_map!
  ([emu addr length perms]
   (.mem_map (.uc emu) addr length perms))
  ([emu addr length]
   (mem_map! emu addr length unicorn.Unicorn/UC_PROT_EXEC)))

(defn mem_write!
  [emu addr buf]
  (.mem_write (.uc emu) addr buf))

(defn mem_read
  [emu addr addr length]
  (.mem_read (.uc emu) addr length))

(defn emu_start!
  ([emu addr until timeout count]
   (.emu_start (.uc emu) addr until timeout count))
  ([emu addr until]
   (emu_start! emu addr until 0 0)))

(defn- resolve-reg
  [emu key]
  (when (= (.arch emu) unicorn.Unicorn/UC_ARCH_X86)
    (let [regname (clojure.string/upper-case (subs (str key) 1))
          uname (str "UC_X86_REG_" regname)
          ;; well, this is a hack.
          ;; access to static fields must be compiled ahead of time.
          ;; so we generate code to fetch the requested register.
          ;; ref: https://stackoverflow.com/questions/6630432/access-java-fields-dynamically-in-clojure
          ;;
          ;; TODO: cache the generated code?
          reg (eval (read-string (str "unicorn.Unicorn/" uname)))]
      reg)))

(defn reg_write!
  [emu reg val]
  (if (keyword? reg)
    (.reg_write (.uc emu) (resolve-reg emu reg) val)
    (.reg_write (.uc emu) reg val)))

(defn reg_read
  [emu reg]
  (let [reg' (if (keyword? reg)
               (resolve-reg emu reg)
               reg)
        val (.reg_read (.uc emu) reg')]
    ;; note: return from reg_read is always 64bit
    (if (= unicorn.Unicorn/UC_MODE_32)
      (bit-and 0xFFFFFFFF val)
      val)))

(deftype Emulator [uc arch mode]
  ILookup
  (valAt [this key]
     (reg_read this (resolve-reg this key))))

(defn make-emulator
  ([arch mode]
   (Emulator. (unicorn.Unicorn. arch mode) arch mode)))

(defn -main
  "I don't do a whole lot ... yet."
  [& args]
  (println "Hello, World!")
  (let [arch unicorn.Unicorn/UC_ARCH_X86
        mode unicorn.Unicorn/UC_MODE_32
        uc (unicorn.Unicorn. arch mode)]
    (println "a" (:eax uc)))
  (println "Goodbye, World!"))

