(ns lancelot-clj.core
  (:gen-class)
  (:require [clojure.java.io :as io]
            [pantomime.mime :as panto]
            [pe.core :as pe]
            [pe.macros :as pe-macros]
            [clojure.tools.logging :as log]
            [clojure.set :as set])
  (:import (java.io RandomAccessFile))
  (:import (java.nio ByteBuffer ByteOrder))
  (:import (java.nio.channels FileChannel FileChannel$MapMode))
  (:import [capstone.Capstone])
  (:import [capstone.X86_const]))


(defn- hex
  [i]
  (format "%X" i))


(defn- conj-if [c e]
  (if (not (nil? e))
    (conj c e)
    c))


(defn- assoc-if [m k e]
  (if (not (nil? e))
    (assoc m k e)
    m))




(defn map-file
  [path]
  (let [file (RandomAccessFile. path "r")
        channel (.getChannel file)
        buffer (.map channel FileChannel$MapMode/READ_ONLY 0 (.size channel))
        _ (.load buffer)
        _ (.order buffer ByteOrder/LITTLE_ENDIAN)]
    buffer))


(defn panto-taste
  [byte-buffer]
  (pe-macros/with-position byte-buffer 0x0
    (let [;; should be able to get by with a 256 byte taste of the header.
          arr (byte-array 0x100)
          _ (.get byte-buffer arr)]
      ;; delegate to pantomime, which asks apache tika.
      ;; overkill, but easy.
      (panto/mime-type-of arr))))


(defn pe32?
  [byte-buffer]
  (= "application/x-msdownload; format=pe32" (panto-taste byte-buffer)))


(defn detect-file-type
  [byte-buffer]
  (cond
    (pe32? byte-buffer) :pe32
    :default :unknown))


(defmulti load-bytes detect-file-type)


(defn map-pe-header
  [pe]
  (let [base-addr (get-in pe [:nt-header :optional-header :ImageBase])
        header-size (get-in pe [:nt-header :optional-header :SizeOfHeaders])]
    {:start base-addr
     :end (+ base-addr header-size)
     :name "header"
     :permissions #{:read}
     ;; TODO: remove `dec` once rebuild pe.
     :data (pe/get-data pe 0 (dec header-size))}))


(defn map-pe-section
  [pe section]
  (let [start (+ (:VirtualAddress section) (get-in pe [:nt-header :optional-header :ImageBase]))]
    {:start start
     :end (+ start (:VirtualSize section))
     :name (:Name section)
     :data (pe/get-section pe (:Name section))
     ;; TODO: correctly compute permissions.
     :permissions #{:read :write :execute}
     :meta section}))


(defn map-pe
  [pe]
  (into [(map-pe-header pe)]
        (map #(map-pe-section pe %)
             (vals (:section-headers pe)))))


(defmethod load-bytes :pe32
  [byte-buffer]
  (let [pe (pe/parse-pe byte-buffer)
        cs (capstone.Capstone. capstone.Capstone/CS_ARCH_X86 capstone.Capstone/CS_MODE_32)
        _ (.setSyntax cs capstone.Capstone/CS_OPT_SYNTAX_INTEL)
        _ (.setDetail cs 1)]
    {:loader :pe32
     :byte-buffer byte-buffer
     :pe pe
     :map (map-pe pe)
     :dis cs}))


(defn get-bytes
  [workspace va length]
  (let [region (first (filter #(and (<= (:start %) va)
                                    (< va (:end %)))
                              (:map workspace)))
        rva (- va (:start region))
        arr (byte-array length)
        data (:data region)]
    (pe-macros/with-position data rva
      (.get data arr)
      arr)))


(defn disassemble
  [workspace va]
  (let [code (get-bytes workspace va 0x10)]  ;; 0x10 is an arbitrary max-insn-length constant
     (first (.disasm (:dis workspace) code va 1))))


(defn op->clj
  "
  converts a disassembled instruction into a clojure map.
  useful for debugging.
  "
  [op]
  {:address (.-address op)
   :mnem (.-mnemonic op)
   :op (.-opStr op)})


(defn load-file
  [path]
  (let [buf (map-file path)]
    (load-bytes buf)))


(defn call?
  [insn]
  (condp = (. insn id)
    capstone.X86_const/X86_INS_CALL true
    capstone.X86_const/X86_INS_LCALL true
    false))


(defn ret?
  [insn]
  (condp = (. insn id)
    capstone.X86_const/X86_INS_RET true
    capstone.X86_const/X86_INS_IRET true
    capstone.X86_const/X86_INS_IRETD true
    capstone.X86_const/X86_INS_IRETQ true
    false))


(defn jmp? [insn] (= (. insn id) capstone.X86_const/X86_INS_JMP))


(def ^:const x86-cjmp-instructions
  #{capstone.X86_const/X86_INS_JAE
    capstone.X86_const/X86_INS_JA
    capstone.X86_const/X86_INS_JBE
    capstone.X86_const/X86_INS_JB
    capstone.X86_const/X86_INS_JCXZ
    capstone.X86_const/X86_INS_JECXZ
    capstone.X86_const/X86_INS_JE
    capstone.X86_const/X86_INS_JGE
    capstone.X86_const/X86_INS_JG
    capstone.X86_const/X86_INS_JLE
    capstone.X86_const/X86_INS_JL
    capstone.X86_const/X86_INS_JNE
    capstone.X86_const/X86_INS_JNO
    capstone.X86_const/X86_INS_JNP
    capstone.X86_const/X86_INS_JNS
    capstone.X86_const/X86_INS_JO
    capstone.X86_const/X86_INS_JP
    capstone.X86_const/X86_INS_JRCXZ
    capstone.X86_const/X86_INS_JS})


(defn cjmp? [insn] (contains? x86-cjmp-instructions (. insn id)))


(defn get-op0
  "fetch the first operand to the instruction"
  [insn]
  (let [[op &rest] (.. insn operands op)]
    op))


;; capstone indexing:
;; given: [eax+10h]
;;   - segment: 0x0
;;   - base: 0x13 (eax)
;;   - index: 0x0
;;   - disp: 0x10


(defn indirect-target?
  [insn]
  (let [op (get-op0 insn)]
    (cond
      ;; jmp eax
      (= (.-type op) capstone.X86_const/X86_OP_REG) true
      ;; jmp [eax+0x10]
      ;; jmp [eax*0x8+0x10]
      (and (= (.-type op) capstone.X86_const/X86_OP_MEM)
           (or (not= (.. op value mem base) capstone.X86_const/X86_REG_INVALID)
               (not= (.. op value mem index) capstone.X86_const/X86_REG_INVALID))) true
      :default false)))


(defn get-target
  "assuming the given instruction has a first operand that is not indirect."
  [insn]
  (let [op (get-op0 insn)]
    (cond
      (= (.-type op) capstone.X86_const/X86_OP_IMM) (.. op value imm)
      ;; should we annotate this value with the `deref`?
      ;; upside: more information.
      ;; downside: inconsistent return value type.
      (= (.-type op) capstone.X86_const/X86_OP_MEM) {:deref (.. op value mem disp)}
      :default nil)))


(defn nop?
  [insn]
  (if (= (.-id insn) capstone.X86_const/X86_INS_NOP)
    true
    (if (not (= (count (.-op (.-operands insn))) 2))
      false
      (let [[op0 op1] (.-op (.-operands insn))]
        (cond
          ;; via: https://github.com/uxmal/nucleus/blob/master/disasm.cc
          (and (= (. insn id) capstone.X86_const/X86_INS_MOV)
               (= (. op0 type) capstone.X86_const/X86_OP_REG)
               (= (. op1 type) capstone.X86_const/X86_OP_REG)
               (= (.. op0 value reg) (.. op1 value reg))) true
          (and (= (. insn id) capstone.X86_const/X86_INS_XCHG)
               (= (. op0 type) capstone.X86_const/X86_OP_REG)
               (= (. op1 type) capstone.X86_const/X86_OP_REG)
               (= (.. op0 value reg) (.. op1 value reg))) true
          (and (= (. insn id) capstone.X86_const/X86_INS_LEA)
               (= (. op0 type) capstone.X86_const/X86_OP_REG)
               (= (. op1 type) capstone.X86_const/X86_OP_MEM)
               (= (.. op1 value mem segment) capstone.X86_const/X86_REG_INVALID)
               (= (.. op1 value mem base) (.. op0 value reg))
               (= (.. op1 value mem index) capstone.X86_const/X86_REG_INVALID)
               (= (.. op1 value mem disp) 0)) true
          :default false)))))



(defn analyze-instruction-flow
  [insn]
  (-> #{}
      (conj-if (when (not (or (ret? insn)
                              (jmp? insn)))
                 {:type :fall-through
                  :address (+ (. insn address) (. insn size))}))
      (conj-if (when (and (jmp? insn)
                          (not (indirect-target? insn)))
                 {:type :jmp
                  :address (get-target insn)}))
      (conj-if (when (and (cjmp? insn)
                          (not (indirect-target? insn)))
                 {:type :cjmp
                  :address (get-target insn)}))))


(defn analyze-instruction
  [workspace insn]
  (-> {:flow (analyze-instruction-flow insn)}
      (assoc-if :cref (when (and (call? insn)
                                 (not (indirect-target? insn)))
                        #{{:address (get-target insn)}}))))


(defn thunk?
  [address]
  (and (map? address)
       (contains? address :deref)))


(defn recursive-descent-disassemble
  [workspace va]
  (loop [insns {}
         q (conj clojure.lang.PersistentQueue/EMPTY va)]
    (if-let [va (peek q)]
      (let [insn (disassemble workspace va)
            ana (analyze-instruction workspace insn)
            next-addrs (map :address (:flow ana))
            new-addrs (filter #(and (not (thunk? %))
                                    (not (contains? insns %)))
                              next-addrs)]
        (recur (assoc insns va ana)
               (apply conj (pop q) new-addrs)))
      insns)))


(defn with-queue
  "
  recursively process in a breadth-first manner, given some seed elements.
  invokes the given function `f`, which should return the next keys to process and processed value.
  results are assoc'd into a map using these keys and processed values.
  skips keys that have already been encountered.

  python::

      m = {}
      while q:
        k = q.pop(0)
        next, v = f(k)
        m[k] = v
        q.append(*next)
      return m
  "
  ([f init-entries m]
   (loop [m m
          q (apply conj clojure.lang.PersistentQueue/EMPTY init-entries)]
     (if-let [i (peek q)]
       (if (contains? m i)
         (recur m (pop q))
         (let [[next r] (f i)]
           (recur (assoc m i r)
                  (apply conj (pop q) next))))
       m)))
  ([f init-entries]
   (with-queue f init-entries {})))


(defn step-queue
  "syntax sugar for `with-queue`"
  [next value]
  [next value])


(defn recursive-descent-disassemble
  [workspace va]
  (with-queue (fn [va]
                (let [insn (disassemble workspace va)
                      ana (analyze-instruction workspace insn)
                      next-addrs (filter #(not (thunk? %)) (map :address (:flow ana)))]
                  (step-queue next-addrs ana)))
              [va]))


(defn extract-cref-addresses
  [insns]
  (remove thunk? (map :address (flatten (remove nil? (map :cref insns))))))


(defn explore-functions
  [workspace vas]
  (with-queue (fn [va]
                (let [insns (recursive-descent-disassemble workspace va)
                      functions (extract-cref-addresses (vals insns))]
                  (step-queue functions insns)))
              vas))


(defn get-entrypoints
  [pe]
  (map #(+ (:function-address %)
           (get-in pe [:nt-header :optional-header :ImageBase]))
       (remove :forwarded? (pe/get-exports pe))))


(def A)

(defn analyze
  [workspace]
  (let [explored-functions (explore-functions workspace (get-entrypoints (:pe workspace)))
        function-vas (keys explored-functions)]
    (alter-var-root #'A (constantly explored-functions))
    {:functions function-vas
     :instructions (merge (vals explored-functions))
     :workspace workspace}))


(let [b (map-file kern32')
      p (pe/parse-pe b)
      w (load-file kern32')
      nop (disassemble w 0x68901000)
      call (disassemble w 0x68901032)
      mov (disassemble w 0x68901010)
      jnz (disassemble w 0x6890102b)]
  (let [ana (analyze w)]
    (count (:instructions ana))))


(defn -main
  "I don't do a whole lot ... yet."
  [& args]
  (Thread/sleep 5000)
  (let [b (map-file (first args))
        p (pe/parse-pe b)
        w (load-file (first args))
        fvas (keys (explore-functions w (get-entrypoints p)))]
    (doseq [fva (sort fvas)]
      (println (format "0x%x" fva)))))
